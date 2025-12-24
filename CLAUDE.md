# microBPF - Agent Context

## Project Overview

microBPF is a sandboxed, event-driven in-kernel programmability system for **constrained kernels** where full eBPF is impractical. It uses **MQuickJS** as the JavaScript execution engine and provides BPF-like capabilities with a small footprint.

**Status: NOT YET IMPLEMENTED** - Start with the `project-setup` task.

## Key Requirements

### Core Components
1. **Toolchain**: Compiles JS to MQuickJS bytecode, produces signed `.mbpf` packages
2. **Loader**: Verifies packages, creates program instances and maps, attaches to hooks
3. **Runtime**: Executes bytecode, enforces budgets, provides JS API (`mbpf`, `maps`, `ctx`)
4. **Map Subsystem**: Bounded key/value stores (array, hash, optional LRU/ring/counter)
5. **Hook Providers**: Integration points (NET_RX, NET_TX, TRACEPOINT, TIMER, SECURITY, CUSTOM)

### Safety Guarantees (MUST)
- No kernel memory corruption (no raw pointers in JS)
- Bounded CPU via step/time budgets with `JS_SetInterruptHandler`
- Bounded RAM via fixed heap size per program
- Capability-gated helpers

### Package Format (`.mbpf`)
- Little-endian binary with header + section table
- Sections: MANIFEST (CBOR/JSON), BYTECODE, MAPS, DEBUG, SIG (Ed25519)
- Manifest includes: program_name, hook_type, heap_size, budgets, capabilities, maps

### JavaScript API
- Entry: `function mbpf_prog(ctx) { return 0; }` (required)
- Optional: `mbpf_init()`, `mbpf_fini()`
- Globals: `mbpf` (helpers), `maps` (program maps), `ctx` (hook context)
- Binary data via `Uint8Array` with allocation-free helpers

### C Embedding API
```c
mbpf_runtime_t *mbpf_runtime_init(cfg);
mbpf_program_load(runtime, pkg, len, opts, &prog);
mbpf_program_attach(runtime, prog, hook);
mbpf_run(runtime, hook, ctx_blob, ctx_len, &out_rc);
mbpf_program_detach(runtime, prog, hook);
mbpf_program_unload(runtime, prog);
mbpf_runtime_shutdown(runtime);
```

## Recommended Stack

- **Language**: C (embedded-friendly, MQuickJS is C)
- **Build System**: CMake or Makefile
- **MQuickJS**: Git submodule from https://github.com/bellard/mquickjs
- **CBOR**: TinyCBOR or custom minimal parser
- **Ed25519**: TweetNaCl or libsodium (sign-only subset)
- **Toolchain**: CLI tools in C or Python

## Implementation Phases

1. **Runtime MVP**: Package parsing, single hook type, step budgeting, log helper
2. **Maps MVP**: Array + hash maps, JS map API
3. **Attach API**: Hook registry, multiple programs, per-CPU instances
4. **Signing**: Ed25519 verification and policy engine
5. **Observability**: Counters, debug symbols, event output

## Important Notes

- MQuickJS has a compacting GC - raw pointers are ephemeral
- Use `JSGCRef` for persistent references
- All helpers MUST be allocation-free on success path
- Context ABI is versioned per hook type
- Bytecode is architecture-dependent (word size, endianness)

## Files

- `task_list.json`: Complete task list (97 tasks)
- `SPEC.md`: Full technical specification
- `claude-progress.txt`: Progress log for agents
