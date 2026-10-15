# FunctionLoader

FunctionLoader is an IDA Pro plugin that lets an analyst choose functions whose resolved calls should be inlined during Hex-Rays microcode generation. It supports direct calls, resolved indirect calls, thunk chains, and nested inlining.

## Requirements

- IDA Pro 9.5 with the Hex-Rays Decompiler.
- IDAPython bundled with IDA; no third-party Python packages are required.

## Installation

Copy this directory (the one containing `ida-plugin.json` and `FunctionLoader.py`) to your IDA user plugins directory as `~/.idapro/plugins/functionloader/` on macOS/Linux. Restart IDA. The package includes `ida-plugin.json` for the Hex-Rays Plugin Manager format.

## Usage

1. In a Disassembly or Pseudocode view, right-click the function call or callee name.
2. Choose **Function Loader → Add <function> to Targets**. In Pseudocode, the plugin resolves the call under the cursor; elsewhere it uses the current function.
3. Use **Manage Targets** to inspect or remove individual targets.
4. Use **Disable/Enable** to pause or resume call inlining. **Disable Logging/Enable Logging** controls FunctionLoader messages.

Targets are stored in the IDB. Inlining is limited to 64 attempts and 25,000 micro-instructions per MBA. Only calls whose destination Hex-Rays resolves can be inlined.

## Credits

Author: [tien0246](https://github.com/tien0246).
