# microBPF Architecture Overview

This document summarizes the core runtime and package components, the execution
flow, and the constraints enforced at runtime.

## Core Components (by module)

### Runtime (`src/mbpf_runtime.c`)

- Program lifecycle: load, attach, run, detach, unload, and update.
- Instance management: per-program JS heaps and `JSContext` creation.
- Map subsystem: array, hash, LRU hash, per-CPU variants, ring buffer, counter.
- JS bindings: `mbpf` helpers, `maps` object, low-level map helpers, `ctx`.
- Budget enforcement: step budget (interrupt handler), helper budget (JS wrapper),
  wall-time budget (interrupt handler).
- Safety and policy: capability gating, helper version checks, hook ABI checks,
  nested execution guard, circuit breaker, trace logging, and stats.

### Package Parsing (`src/mbpf_package.c`)

- `.mbpf` header and section table parsing with bounds and overlap checks.
- CRC32 validation for header and individual sections.
- Manifest parsing (CBOR preferred, JSON supported), with defaults for entry
  symbol, heap size, budgets, and target.
- Bytecode validation, relocation, and loading using MQuickJS helpers.
- Signature handling: locating the signature section and verifying Ed25519
  signatures over the unsigned prefix of the package.
- Package assembly helpers for tools (header/section construction + CRCs).

### JS Stdlib Wrapper (`src/mbpf_stdlib.c`)

- Provides the minimal MQuickJS stdlib symbols required for bytecode loading.
- Stubs unsupported features (timers, module loading).
- Implements `js_print` with log level parsing and rate limiting for `mbpf.log`.

### Typed Array Shim (`src/mbpf_typed_array.c`)

- Direct access to `Uint8Array` length and backing buffer pointers using
  MQuickJS internal structures.
- Used by helper/map code paths to avoid allocations and copy overhead.
- Coupled to the specific MQuickJS layout; updates require shim review.

### Ed25519 (`src/ed25519.c`)

- TweetNaCl-derived Ed25519 implementation with SHA-512.
- Used for signing in tooling and verification in `mbpf_package_verify_signature`.

## Runtime Flow (Load / Attach / Run / Unload)

```
       .mbpf bytes
            |
            v
  +--------------------+
  | mbpf_package.c     |
  | - header/sections  |
  | - CRC validation   |
  | - manifest parse   |
  | - sig verify       |
  | - bytecode load    |
  +--------------------+
            |
            v
  +--------------------+      +-----------------------+
  | mbpf_program_load  |----->| create maps storage   |
  | - validate target  |      | (array/hash/LRU/etc.) |
  | - check caps/vers  |      +-----------------------+
  | - create instances |
  | - setup JS globals |
  +--------------------+
            |
            v
  +--------------------+
  | mbpf_program_attach|
  | - bind to hook     |
  +--------------------+
            |
            v
  +--------------------+
  | mbpf_run            |
  | - build ctx object  |
  | - enforce budgets   |
  | - call entry func   |
  | - sync maps/events  |
  +--------------------+
            |
            v
  +--------------------+
  | mbpf_program_unload|
  | - call mbpf_fini   |
  | - free instances  |
  | - free maps        |
  +--------------------+
```

### Load

1. The loader parses the package header/section table and validates CRCs.
2. The manifest is parsed (CBOR/JSON) and defaults are applied if omitted.
3. Bytecode is validated and relocated, then loaded into a JS module.
4. The runtime checks target word size/endianness, API version, helper versions,
   and capability allow-lists.
5. Map storage is allocated from manifest definitions (per-CPU maps allocate
   per-instance storage).
6. Instances are created with fixed-size heaps and JS contexts.
7. `mbpf` helpers, budget tracking, and `maps` bindings are installed.
8. Optional `mbpf_init` is invoked after maps exist but before attachment.

### Attach

- Programs are bound to hook IDs. Hook type and context ABI version are checked
  during attach and at run time.

### Run

- `mbpf_run` selects the correct instances and sets per-invocation budgets.
- A `ctx` object is constructed from the hook-specific context blob (including
  read-only accessors and read helpers).
- Budget enforcement:
  - Step budget: interrupt handler aborts execution when limits are reached.
  - Helper budget: helper wrapper increments and throws on limit.
  - Wall time budget: interrupt handler aborts when elapsed time exceeds limit.
- Map and helper access is gated by declared capabilities.
- After execution, maps and event buffers are synchronized back to C storage and
  per-program stats are updated.

### Unload

- `mbpf_fini` is invoked if defined.
- JS contexts and heaps are destroyed.
- Map storage is freed or preserved during program update, depending on policy.

## Runtime Constraints and Enforcement

- **CPU budget:** Steps are limited via `JS_SetInterruptHandler`, with optional
  wall-time enforcement; overruns produce a safe default return value.
- **Helper budget:** Helper usage is counted in JS and throws on overflow.
- **Memory budget:** Each instance has a fixed heap allocated at load time; the
  manifest heap size is clamped to a runtime minimum/default.
- **Capabilities:** Helpers and map methods are only exposed when the manifest
  requests capabilities allowed by the runtime configuration.
- **Map safety:** Map definitions are validated, bounds-checked, and (for read
  paths) protected with lock-free seqlock snapshots; per-CPU maps isolate state.
- **Package integrity:** CRCs and Ed25519 signatures are validated before load.

