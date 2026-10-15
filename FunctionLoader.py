import collections
import json

import idaapi
import ida_funcs
import ida_hexrays
import ida_idp
import ida_kernwin
import ida_netnode
import ida_name
import ida_ua
import ida_xref
import idautils


TARGETS = set()
hooks = None
LOG_ENABLED = True
target_chooser = None
_targets_node = None
_inlining_targets = set()
_popup_target_ea = idaapi.BADADDR
_TARGETS_NODE_NAME = "$ FunctionLoader targets"
_TARGETS_NODE_SLOT = 0
# shortcut: cap inline attempts at 64, raise only if a target needs a larger batch.
MAX_INLINE_OPS = 64
# shortcut: cap each MBA at 25k instructions; raise if larger functions need inlining.
MAX_MBA_INSNS = 25000


def _log(message):
    if LOG_ENABLED:
        ida_kernwin.msg("[FunctionLoader] %s\n" % message)


def _open_targets_node():
    node = ida_netnode.netnode()
    if not node.create(_TARGETS_NODE_NAME):
        node = ida_netnode.netnode(_TARGETS_NODE_NAME, 0, False)
    return node


def _load_targets():
    global _targets_node
    try:
        _targets_node = _open_targets_node()
        payload = _targets_node.supval(_TARGETS_NODE_SLOT)
        if not payload:
            return set()
        offsets = json.loads(payload.decode("utf-8"))
        imagebase = idaapi.get_imagebase()
        return {imagebase + int(offset, 16) for offset in offsets}
    except Exception as e:
        _log("could not load saved targets: %s" % e)
        return set()


def _save_targets():
    global _targets_node
    try:
        if _targets_node is None:
            _targets_node = _open_targets_node()
        imagebase = idaapi.get_imagebase()
        offsets = sorted(ea - imagebase for ea in TARGETS)
        payload = json.dumps([hex(offset) for offset in offsets], separators=(",", ":")).encode("utf-8")
        if not _targets_node.supset(_TARGETS_NODE_SLOT, payload):
            raise RuntimeError("netnode write failed")
    except Exception as e:
        _log("could not save targets: %s" % e)


def _unwrap_mop_ea(mop):
    """Extract a constant function address from simple wrapped micro-operands."""
    for _ in range(16):
        if mop is None:
            return idaapi.BADADDR
        if mop.t == ida_hexrays.mop_v:
            return mop.g
        if mop.t == ida_hexrays.mop_a:
            mop = mop.a
            continue
        if mop.t != ida_hexrays.mop_d or not mop.d:
            break

        nested = mop.d
        if nested.opcode not in (
            ida_hexrays.m_mov,
            ida_hexrays.m_xds,
            ida_hexrays.m_xdu,
            ida_hexrays.m_low,
        ):
            break
        if nested.opcode in (ida_hexrays.m_mov, ida_hexrays.m_low):
            if nested.d.size != nested.l.size:
                break
        mop = nested.l
    return idaapi.BADADDR


def _xref_call_target(ea, cache):
    if ea in cache:
        return cache[ea]
    targets = set()
    if ea != idaapi.BADADDR:
        for xref in idautils.XrefsFrom(ea, 0):
            if xref.type not in (ida_xref.fl_CF, ida_xref.fl_CN):
                continue
            target = _function_start(xref.to)
            if target != idaapi.BADADDR:
                targets.add(target)
    target = next(iter(targets)) if len(targets) == 1 else idaapi.BADADDR
    cache[ea] = target
    return target


def _direct_call_target(ins, xref_cache=None):
    """Resolve direct and IDA-proven indirect call destinations."""
    if ins is None or ins.opcode not in (ida_hexrays.m_call, ida_hexrays.m_icall):
        return idaapi.BADADDR

    if ins.d.t == ida_hexrays.mop_f and ins.d.f:
        target = ins.d.f.callee
        if target != idaapi.BADADDR:
            return target

    target = _unwrap_mop_ea(ins.l)
    if target != idaapi.BADADDR:
        return target

    return _xref_call_target(ins.ea, xref_cache if xref_cache is not None else {})


def _function_chain(ea):
    """Return a function and any thunk targets, stopping safely on cycles."""
    chain = []
    seen = set()
    # shortcut: cap thunk chains at 16 entries, raise if a binary proves deeper chains.
    while ea != idaapi.BADADDR and ea not in seen and len(chain) < 16:
        func = ida_funcs.get_func(ea)
        ea = func.start_ea if func else ea
        if ea in seen:
            break
        seen.add(ea)
        chain.append(ea)
        if not func or not (func.flags & ida_funcs.FUNC_THUNK):
            break
        try:
            target = ida_funcs.calc_thunk_func_target(func)
            if isinstance(target, tuple):
                target = target[0]
        except Exception:
            break
        if target == idaapi.BADADDR:
            break
        ea = target
    return chain


def _selected_inline_target(ins, inline_targets, xref_cache):
    target = _direct_call_target(ins, xref_cache)
    if target == idaapi.BADADDR:
        return idaapi.BADADDR
    chain = _function_chain(target)
    if not chain:
        return idaapi.BADADDR
    effective_target = chain[-1]
    return effective_target if effective_target in inline_targets else idaapi.BADADDR


def _retarget_call(ins, target):
    # IDA 9.5 can return MERR_OK for m_icall inlining and then emit invalid microcode.
    callee = ida_hexrays.mop_t()
    callee.make_gvar(target)
    ins.l.assign(callee)
    ins.r.erase()
    ins.opcode = ida_hexrays.m_call
    if ins.d.t == ida_hexrays.mop_f and ins.d.f:
        ins.d.f.callee = target


class CallCollector(ida_hexrays.minsn_visitor_t):
    def __init__(self, targets, failed_sites):
        super().__init__()
        self.targets = targets
        self.failed_sites = failed_sites
        self.xref_cache = {}
        self.calls = collections.Counter()
        self.pending = []
        self.insn_count = 0

    def visit_minsn(self):
        self.insn_count += 1
        target = _selected_inline_target(self.curins, self.targets, self.xref_cache)
        key = (self.curins.ea, target)
        if target != idaapi.BADADDR and key not in self.failed_sites and self.blk:
            self.calls[key] += 1
            self.pending.append((self.blk.serial, self.curins.ea, target, key, self.curins))
        return 0


class FunctionLoaderHooks(ida_hexrays.Hexrays_Hooks):
    def begin_inlining(self, cdg, decomp_flags):
        mba = cdg.mba
        if mba is None:
            return 0

        targets = TARGETS - {mba.entry_ea} - _inlining_targets
        inline_targets = set()
        for target in targets:
            chain = _function_chain(target)
            if chain:
                inline_targets.add(chain[-1])
        inline_targets -= {mba.entry_ea} | _inlining_targets
        if not inline_targets:
            return 0

        failed_sites = set()
        range_cache = {}
        previous_success = None
        attempts = 0
        while attempts < MAX_INLINE_OPS:
            calls = CallCollector(inline_targets, failed_sites)
            mba.for_all_insns(calls)

            if previous_success:
                key, old_count = previous_success
                if calls.calls.get(key, 0) >= old_count:
                    failed_sites.add(key)
                    _log("inline at 0x%x made no progress; skipping this site" % key[0])
                previous_success = None

            if not calls.pending:
                break
            if calls.insn_count >= MAX_MBA_INSNS:
                _log("stopped inlining at %d micro-instructions" % calls.insn_count)
                break

            candidates = [candidate for candidate in calls.pending if candidate[3] not in failed_sites]
            if not candidates:
                break
            blknum, call_ea, target, key, ins = max(candidates, key=lambda item: item[0])
            attempts += 1
            saved_ins = None
            try:
                if target not in range_cache:
                    range_cache[target] = ida_hexrays.decomp_ranges_t(target)
                ranges = range_cache[target]
                saved_ins = ida_hexrays.minsn_t(ins)
                _retarget_call(ins, target)
                _inlining_targets.add(target)
                err = mba.inline_function(cdg, blknum, ranges, decomp_flags, 0)
            except Exception as e:
                if saved_ins is not None:
                    ins.swap(saved_ins)
                failed_sites.add(key)
                _log("inline 0x%x at block %d failed: %s" % (target, blknum, e))
                continue
            finally:
                _inlining_targets.discard(target)

            if err != ida_hexrays.MERR_OK:
                if saved_ins is not None:
                    ins.swap(saved_ins)
                failed_sites.add(key)
                _log("inline 0x%x at block %d skipped (error %s)" % (target, blknum, err))
                continue

            previous_success = (key, calls.calls[key])
            _log("inlined 0x%x at 0x%x" % (target, call_ea))

        if attempts == MAX_INLINE_OPS:
            _log("reached the %d-inline-attempt safety limit" % MAX_INLINE_OPS)
        return 0


MenuItem = collections.namedtuple(
    "MenuItem",
    ["action", "handler", "title", "tooltip", "shortcut", "main_menu", "popup"],
)


class MenuActionHandler(idaapi.action_handler_t):
    def __init__(self, callback, updater=None):
        super().__init__()
        self.callback = callback
        self.updater = updater

    def activate(self, ctx):
        try:
            self.callback(ctx)
        except Exception as e:
            _log("menu action failed: %s" % e)
        return 1

    def update(self, ctx):
        if self.updater:
            try:
                return self.updater(ctx)
            except Exception as e:
                _log("menu update failed: %s" % e)
        return idaapi.AST_ENABLE_ALWAYS


def _function_start(ea):
    return ida_funcs.get_func_start(ea) if ea != idaapi.BADADDR else idaapi.BADADDR


def _callee_from_ctree(expr):
    if expr is None:
        return idaapi.BADADDR
    while expr.op == ida_hexrays.cot_cast:
        expr = expr.x
    if expr.op == ida_hexrays.cot_call:
        expr = expr.x
        while expr.op == ida_hexrays.cot_cast:
            expr = expr.x
    return _function_start(expr.obj_ea) if expr.op == ida_hexrays.cot_obj else idaapi.BADADDR


def _call_target_at(ea):
    if ea == idaapi.BADADDR:
        return idaapi.BADADDR
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea) or not ida_idp.is_call_insn(insn):
        return idaapi.BADADDR
    for xref in idautils.XrefsFrom(ea, 0):
        if xref.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
            continue
        target = _function_start(xref.to)
        if target != idaapi.BADADDR:
            return target
    return idaapi.BADADDR


def _target_ea_under_cursor(device=ida_hexrays.USE_KEYBOARD, widget=None, ea_hint=idaapi.BADADDR):
    widget = widget or ida_kernwin.get_current_widget()
    if widget and ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu:
            call_sites = [ea_hint]
            try:
                if vu.get_current_item(device):
                    item = vu.item
                    if item.citype == ida_hexrays.VDI_EXPR:
                        expr = item.e
                        target = _callee_from_ctree(expr)
                        if target != idaapi.BADADDR:
                            return target
                        call_sites.insert(0, getattr(expr, "ea", idaapi.BADADDR))
                    call_sites.insert(0, item.get_ea())
            except Exception:
                pass
            for ea in dict.fromkeys(call_sites):
                target = _call_target_at(ea)
                if target != idaapi.BADADDR:
                    return target
            if vu.cfunc:
                return vu.cfunc.entry_ea
        ea = ea_hint if ea_hint != idaapi.BADADDR else ida_kernwin.get_screen_ea()
        return _function_start(ea)

    ea = ea_hint if ea_hint != idaapi.BADADDR else ida_kernwin.get_screen_ea()
    target = _call_target_at(ea)
    return target if target != idaapi.BADADDR else _function_start(ea)


def _target_ea_for_action(ctx, device):
    if device == ida_hexrays.USE_MOUSE and _popup_target_ea != idaapi.BADADDR:
        return _popup_target_ea
    return _target_ea_under_cursor(
        device,
        widget=getattr(ctx, "widget", None),
        ea_hint=getattr(ctx, "cur_ea", idaapi.BADADDR),
    )


def _target_name(ea):
    return ida_name.get_name(ea) or "sub_%X" % ea


def _enable_hooks():
    global hooks
    if hooks:
        return True
    if not ida_hexrays.init_hexrays_plugin():
        _log("Hex-Rays is unavailable")
        return False
    handler = FunctionLoaderHooks()
    if not handler.hook():
        _log("could not install Hex-Rays hook")
        return False
    hooks = handler
    _log("enabled for %d target%s" % (len(TARGETS), "" if len(TARGETS) == 1 else "s"))
    return True


def _disable_hooks():
    global hooks
    if hooks:
        hooks.unhook()
        hooks = None
        _log("disabled")


def _remove_target(ea, refresh_chooser=True):
    if ea not in TARGETS:
        return False
    TARGETS.discard(ea)
    _save_targets()
    if not TARGETS:
        _disable_hooks()
    _log("removed %s (0x%x); %d target%s remain" % (
        _target_name(ea), ea, len(TARGETS), "" if len(TARGETS) == 1 else "s"))
    _update_toggle_label()
    if refresh_chooser:
        _refresh_target_chooser()
    return True


def _toggle_target(ea):
    if ea == idaapi.BADADDR:
        _log("no function under the cursor")
        return
    if ea in TARGETS:
        _remove_target(ea)
        return
    TARGETS.add(ea)
    _save_targets()
    _enable_hooks()
    _log("added %s (0x%x); %d target%s" % (
        _target_name(ea), ea, len(TARGETS), "" if len(TARGETS) == 1 else "s"))
    _update_toggle_label()
    _refresh_target_chooser()


def _toggle_target_from_context(ctx, device):
    _toggle_target(_target_ea_for_action(ctx, device))


def _target_action_update(action, device, ctx):
    ea = _target_ea_for_action(ctx, device)
    if ea == idaapi.BADADDR:
        label = "Toggle Target Under Cursor"
    elif ea in TARGETS:
        label = "Remove %s from Targets" % _target_name(ea)
    else:
        label = "Add %s to Targets" % _target_name(ea)
    try:
        idaapi.update_action_label(action, label)
    except Exception:
        pass
    return idaapi.AST_ENABLE_ALWAYS


class TargetChooser(ida_kernwin.Choose):
    def __init__(self):
        super().__init__(
            "Function Loader Targets",
            [["Address", 16], ["Function", 40]],
            flags=ida_kernwin.Choose.CH_CAN_DEL,
        )

    def OnGetSize(self):
        return len(TARGETS)

    def OnGetLine(self, n):
        ea = sorted(TARGETS)[n]
        return ["0x%X" % ea, _target_name(ea)]

    def OnGetEA(self, n):
        return sorted(TARGETS)[n]

    def OnDeleteLine(self, n):
        ea = sorted(TARGETS)[n]
        _remove_target(ea, refresh_chooser=False)
        return [self.ALL_CHANGED] + self.adjust_last_item(n)

    def OnClose(self):
        global target_chooser
        if target_chooser is self:
            target_chooser = None


def _refresh_target_chooser():
    if target_chooser:
        try:
            target_chooser.Refresh()
        except Exception:
            pass


def show_targets(ctx=None):
    global target_chooser
    if target_chooser:
        target_chooser.Activate()
        return
    target_chooser = TargetChooser()
    target_chooser.Show()


def clear_targets():
    if not TARGETS:
        _log("there are no targets to clear")
        _disable_hooks()
        _update_toggle_label()
        return
    TARGETS.clear()
    _save_targets()
    _disable_hooks()
    _log("cleared all targets")
    _update_toggle_label()
    _refresh_target_chooser()


def toggle_functionloader():
    if hooks:
        _disable_hooks()
    else:
        _enable_hooks()
    _update_toggle_label()


def toggle_functionloader_logging():
    global LOG_ENABLED
    LOG_ENABLED = not LOG_ENABLED
    _update_logging_label()
    ida_kernwin.msg("[FunctionLoader] logging %s\n" % ("enabled" if LOG_ENABLED else "disabled"))


def _logging_action_update(action, ctx):
    _update_logging_label()
    return idaapi.AST_ENABLE_ALWAYS


class FunctionLoaderPlugin(idaapi.plugin_t, ida_kernwin.UI_Hooks):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Inline selected resolved calls before decompiler optimization."
    help = "Toggle a call target under the cursor; manage persisted targets."
    wanted_name = "Function Loader"
    wanted_hotkey = ""

    def init(self):
        TARGETS.clear()
        TARGETS.update(_load_targets())
        self.menu_items = []
        self.menu_ready = False
        self.hook()
        if TARGETS:
            _enable_hooks()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        toggle_functionloader()

    def term(self):
        global target_chooser, _targets_node
        _disable_hooks()
        self.unhook()
        if target_chooser:
            target_chooser.Close()
            target_chooser = None
        if self.menu_ready:
            self._detach_menu_actions()
            for item in self.menu_items:
                idaapi.unregister_action(item.action)
            self.menu_ready = False
        TARGETS.clear()
        _targets_node = None

    def _register_actions(self):
        self.menu_items = [
            MenuItem(
                "FunctionLoader:toggle_target",
                MenuActionHandler(
                    lambda ctx: _toggle_target_from_context(ctx, ida_hexrays.USE_KEYBOARD),
                    lambda ctx: _target_action_update("FunctionLoader:toggle_target", ida_hexrays.USE_KEYBOARD, ctx),
                ),
                "Toggle Target Under Cursor",
                "Add or remove the callee under the keyboard cursor (or the current function)",
                None,
                True,
                False,
            ),
            MenuItem(
                "FunctionLoader:toggle_target_mouse",
                MenuActionHandler(
                    lambda ctx: _toggle_target_from_context(ctx, ida_hexrays.USE_MOUSE),
                    lambda ctx: _target_action_update("FunctionLoader:toggle_target_mouse", ida_hexrays.USE_MOUSE, ctx),
                ),
                "Toggle Target Under Cursor",
                "Add or remove the callee under the mouse cursor",
                None,
                False,
                True,
            ),
            MenuItem("FunctionLoader:manage", MenuActionHandler(lambda ctx: show_targets()), "Manage Targets", "View, jump to, and remove individual targets", None, True, True),
            MenuItem("FunctionLoader:clear", MenuActionHandler(lambda ctx: clear_targets()), "Clear Targets", "Remove all inline targets", None, True, True),
            MenuItem("FunctionLoader:toggle", MenuActionHandler(lambda ctx: toggle_functionloader()), "Enable", "Temporarily enable or disable inlining", None, True, True),
            MenuItem(
                "FunctionLoader:logging",
                MenuActionHandler(
                    lambda ctx: toggle_functionloader_logging(),
                    lambda ctx: _logging_action_update("FunctionLoader:logging", ctx),
                ),
                "Disable Logging",
                "Toggle Function Loader log messages",
                None,
                True,
                True,
            ),
        ]
        for item in self.menu_items:
            action = idaapi.action_desc_t(item.action, item.title, item.handler, item.shortcut, item.tooltip, -1)
            if not idaapi.register_action(action):
                idaapi.unregister_action(item.action)
                idaapi.register_action(action)
        self._attach_menu_actions()
        self.menu_ready = True
        _update_toggle_label()
        _update_logging_label()

    def _attach_menu_actions(self):
        root = "Edit/Plugins/" + self.wanted_name + "/"
        for item in self.menu_items:
            if item.main_menu:
                idaapi.attach_action_to_menu(root + item.title, item.action, idaapi.SETMENU_APP)

    def _detach_menu_actions(self):
        root = "Edit/Plugins/" + self.wanted_name + "/"
        for item in self.menu_items:
            if item.main_menu:
                idaapi.detach_action_from_menu(root + item.title, item.action)

    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        global _popup_target_ea
        if ida_kernwin.get_widget_type(widget) in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            # The action updater runs after the mouse leaves the code view for the popup.
            _popup_target_ea = _target_ea_under_cursor(
                ida_hexrays.USE_MOUSE,
                widget=widget,
                ea_hint=getattr(ctx, "cur_ea", idaapi.BADADDR),
            )
            for item in self.menu_items:
                if item.popup:
                    idaapi.attach_action_to_popup(widget, popup_handle, item.action, "Function Loader/")

    def ready_to_run(self):
        if not self.menu_ready:
            self._register_actions()


def _update_toggle_label():
    label = "Disable" if hooks else "Enable"
    try:
        idaapi.update_action_label("FunctionLoader:toggle", label)
    except Exception:
        pass


def _update_logging_label():
    label = "Disable Logging" if LOG_ENABLED else "Enable Logging"
    try:
        idaapi.update_action_label("FunctionLoader:logging", label)
    except Exception:
        pass


def PLUGIN_ENTRY():
    return FunctionLoaderPlugin()
