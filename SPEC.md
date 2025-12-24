# microBPF Technical Specification (Draft)

Status: Draft  
Audience: kernel / embedded OS developers, runtime implementers, tooling authors  
Scope: microBPF runtime + program format + host ABI, built on **MicroQuickJS (MQuickJS)** (`mquickjs/`)

---

## 1. Abstract

**microBPF** is a small, sandboxed, event-driven in-kernel (or kernel-adjacent) programmability system intended for *constrained kernels* where full eBPF is impractical due to code size, complexity, missing JIT/verifier infrastructure, or strict memory budgets.

microBPF uses **MQuickJS** as its execution engine and defines:

- A **restricted host ABI** (helpers, maps, context access).
- A **program packaging format** for distributing precompiled programs.
- A **runtime resource model** (bounded memory, bounded execution).
- A **hook model** for attaching programs to kernel events.

microBPF is not binary compatible with eBPF. It is an alternative that prioritizes small footprint, deterministic resource bounding, and ease of authoring.

---

## 2. Motivation

eBPF is highly capable but often too heavy for:

- Small RTOSes and embedded kernels with limited RAM/ROM.
- Microkernels without rich introspection facilities (BTF, kprobes, etc.).
- Safety- or certification-driven deployments where verifier/JIT complexity is unacceptable.
- Systems where “load arbitrary native bytecode into kernel” is a non-starter.

MQuickJS provides:

- Low RAM operation (≈10 KiB demonstrated) and moderate ROM footprint.
- An interpreter with bounded C-stack usage (no recursion in parser/runtime design).
- A strict JavaScript subset that avoids many footguns.
- An interrupt mechanism (`JS_SetInterruptHandler`) suitable for execution budgeting.

microBPF leverages these properties to offer “BPF-like” dynamic logic while keeping the trusted computing base (TCB) and integration surface small.

---

## 3. Goals and Non‑Goals

### 3.1 Goals

microBPF MUST:

1. Provide a safe execution environment that cannot corrupt kernel memory.
2. Bound per-invocation CPU usage via a deterministic budgeting mechanism.
3. Bound per-program RAM usage via fixed memory buffers.
4. Provide state via **maps** (persistent key/value stores) and controlled output via **events**.
5. Support multiple hook types (network, tracing, timers, custom kernel hooks).
6. Enable offline compilation into a packaged artifact suitable for OTA updates.

microBPF SHOULD:

- Support SMP systems via per-CPU program instances or a safe scheduling model.
- Provide observability (per-program stats, debug logging, failure reasons).
- Provide capability-based restriction of helper usage.

### 3.2 Non‑Goals

microBPF does NOT aim to:

- Implement eBPF bytecode, eBPF verifier semantics, BTF, CO‑RE, or the Linux eBPF API.
- Match eBPF performance characteristics (no JIT requirement).
- Allow arbitrary kernel memory reads/writes.
- Provide a general-purpose JS runtime (no filesystem, sockets, threads, etc.).

---

## 4. Terminology

- **Program**: A microBPF application compiled to MQuickJS bytecode and packaged with metadata.
- **Instance**: A runtime execution context for a program (typically per CPU).
- **Hook**: A kernel event where a program can run (e.g., net RX, tracepoint).
- **Context**: Hook-specific input provided to the program.
- **Helper**: A host-provided function callable from the program (e.g., map lookup).
- **Map**: A host-managed data structure shared across invocations and/or instances.
- **Budget**: Limits for execution steps, helper calls, and memory usage.

Normative keywords (MUST/SHOULD/MAY) are used as in RFC 2119.

---

## 5. System Model and Constraints

microBPF targets kernels with one or more of:

- RAM in the 10s–100s of KiB range.
- ROM/flash budgets that disfavor large subsystems.
- No user/kernel separation (common in RTOS), increasing safety requirements.
- Limited or no MMU (cannot rely on page protections).

Therefore microBPF assumes:

- **No dynamic memory allocation from the host C library** at runtime for untrusted code paths.
- Predictable worst-case behavior is preferred over peak throughput.
- The runtime may execute in constrained contexts (softirq/bottom-half) and MUST support a “deferred execution” mode if hard IRQ execution is unsafe.

---

## 6. High-Level Architecture

### 6.1 Components

1. **Toolchain (host/CI)**:
   - Compiles JavaScript (MQuickJS subset) to MQuickJS bytecode.
   - Produces a signed **`.mbpf`** package with metadata and sections.
2. **Loader (kernel / privileged OS component)**:
   - Verifies the package (format + signature + policy).
   - Creates program instances and maps.
   - Attaches programs to hooks.
3. **Runtime (embedded)**:
   - Uses MQuickJS to execute program bytecode.
   - Enforces budgets and helper capabilities.
   - Provides the microBPF JS standard library surface (`mbpf`, `maps`, `ctx`).
   - SHOULD use MQuickJS’ ROM-resident stdlib mechanism (build-time generated tables) to keep initialization fast and RAM usage low.
4. **Hook Providers (kernel integration points)**:
   - Call into microBPF at well-defined points and supply a typed context.
5. **Map Subsystem**:
   - Host-managed storage with bounded memory.
   - Optional per-CPU semantics and atomic operations.

### 6.2 Execution Flow (per event)

1. Hook provider constructs a **context view** (not raw pointers).
2. Runtime enters the program instance and calls the entry function.
3. Program reads context, updates maps, emits events, returns an action.
4. Runtime enforces budgets; on violation, aborts and returns a safe default.

---

## 7. JavaScript Profile (MQuickJS-Based)

### 7.1 Language

Programs are written in JavaScript compatible with the **MQuickJS “stricter mode”** subset (approximately ES5 + select extensions).

microBPF MUST assume:

- Programs may be untrusted.
- Source compilation may be excluded from the kernel build (preferred).

### 7.2 Standard Library Surface

microBPF MUST provide a minimal global surface, and MUST NOT expose general-purpose I/O.

Required globals:

- `mbpf`: host API namespace (helpers, logging, stats, event output).
- `maps`: map handles defined in the program package (optional name-based access).

Optional (configurable) globals:

- `console.log` mapped to `mbpf.log()` in debug builds only.

Disallowed / removed globals (RECOMMENDED):

- Dynamic code generation (`Function` constructor).
- Non-deterministic APIs unless explicitly enabled by policy (e.g., random).

### 7.3 Program Entry Points

Programs MUST define exactly one required entry function:

```js
function mbpf_prog(ctx) { /* ... */ }
```

Programs MAY define:

- `function mbpf_init() {}` called at load time (after maps are created).
- `function mbpf_fini() {}` called at unload time (best-effort).

The loader/runtime MUST treat missing optional entry points as no-ops.

### 7.4 Return Value Semantics

The entry function MUST return a 32-bit signed integer. Meaning depends on hook type:

- **Trace/Tick hooks**: `0` indicates success; other values indicate “soft failure” and are counted.
- **Net hooks**: return an action enum (e.g., `MBPF_NET_PASS`, `MBPF_NET_DROP`, `MBPF_NET_REDIRECT` if supported).
- **Security hooks**: return allow/deny codes.

If the program throws an exception or violates a budget, the runtime MUST return a **policy-defined default** (typically “allow/ignore” for observability hooks, “pass” for forwarding hooks unless configured otherwise).

### 7.5 Binary Data Representation

microBPF frequently needs to move bounded byte sequences across the host/program boundary (packet bytes, map keys/values, event payloads).

The canonical binary blob type in programs is:

- `Uint8Array` (and, by extension, its backing `ArrayBuffer`).

The runtime MUST support the following operations on binary blobs passed from JS:

1. Validate that a value is a `Uint8Array` (or reject with `TypeError`).
2. Obtain a `(pointer, length)` view of the bytes **for the duration of a single helper call**.
3. Copy bytes **into** a provided `Uint8Array` (for `lookup(..., out)` and `readBytes(...)`) with strict bounds checks.

#### 7.5.1 Typed Array Access Safety Invariants (normative)

MQuickJS uses a compacting GC; object addresses may change on allocation. Therefore, when a helper/context method obtains a raw pointer to a `Uint8Array` backing store:

- The pointer MUST be treated as **ephemeral** and MUST NOT be cached outside the helper/method invocation.
- The helper/method MUST NOT perform any operation that can trigger a JS heap allocation **after** obtaining the pointer and **before** it has finished copying from/to it.
- microBPF helpers/context methods SHOULD be designed to be allocation-free on their success path (see §7.5.3).

These invariants are required even if an implementation chooses to access typed arrays via private MQuickJS internals.

#### 7.5.2 Required Typed Array Access Shim

To avoid direct use of private engine structures, a microBPF implementation MUST provide a stable “typed array access shim” with, at minimum:

- `is_u8array(val) -> bool`
- `u8array_len(val) -> size_t`
- `u8array_data(val) -> uint8_t*` (valid only until the next JS allocation)

The shim MAY be implemented:

- As a small extension to the MQuickJS public API (preferred), or
- Inside the microBPF integration layer with strict pinning to a specific MQuickJS engine revision.

#### 7.5.3 Helper Allocation Contract (normative, core profile)

In the core profile, all microBPF-provided C functions callable from programs (helpers and `ctx.*` methods) MUST NOT allocate JS objects/strings/arrays on the success path. They MUST:

- Take inputs as numbers/booleans and preallocated buffers (`Uint8Array`).
- Return numbers/booleans (or `undefined`) and write outputs into caller-provided buffers.

Rationale: this keeps helper latency bounded and makes typed-array backing pointers safe to use within a helper call (no GC-triggering allocations).

Implementation note: MQuickJS supports typed arrays, but its public API (`mquickjs.h`) is intentionally small. Implementations that reach into `mquickjs_priv.h` MUST ensure they meet the invariants above and MUST treat the engine as version-pinned.

---

## 8. Safety and Resource Bounding

microBPF safety is achieved by a combination of:

1. **Language-level safety** (no raw pointers in JS).
2. **Host ABI design** (no unchecked memory access helpers).
3. **Runtime budgets** (time/step and memory).
4. **Package trust** (signing + policy).

### 8.1 Memory Bounding

Each program instance MUST execute within a fixed-size memory buffer passed to `JS_NewContext()`.

- Let `heap_size` be configured per program (or per hook class).
- The runtime MUST fail program load if `heap_size` is below the platform minimum for the chosen stdlib surface.
- On out-of-memory during execution, the runtime MUST abort the invocation and return the safe default action.

Persistent program state SHOULD be stored in maps, not JS heap, to:

- Avoid GC pauses affecting hook latency.
- Enable per-program memory accounting.

### 8.2 Execution Bounding (Step/Time Budget)

microBPF MUST enforce an execution budget per invocation. It SHOULD use MQuickJS’ interrupt mechanism:

- Register an interrupt handler via `JS_SetInterruptHandler(ctx, handler)`.
- Maintain a per-invocation counter in `ctx` opaque state (`JS_SetContextOpaque`).
- Abort (throw) when the budget is exceeded.

The budget model MUST support at least:

- `max_steps`: an abstract “VM step” limit (implementation-defined granularity).
- `max_helpers`: maximum helper calls per invocation (total and/or per helper).

Optionally:

- `max_wall_time_us`: enforced only when a reliable monotonic clock exists and timing overhead is acceptable.

Portability note: `max_steps` is intentionally an abstract unit. Programs MUST NOT rely on a stable “steps per second” mapping across devices or runtime versions. Platforms SHOULD publish recommended budget ranges per hook type and provide a calibration methodology (e.g., run a reference program under load and tune `max_steps` to meet latency targets).

### 8.3 Helper Capabilities and Policy

Programs MUST declare required capabilities in metadata (see §11). The loader MUST enforce policy:

- Disallow loading if required capabilities are not granted.
- Disallow calling helpers not declared/granted (defense-in-depth).

### 8.4 Failure Isolation

The runtime MUST ensure that a failing program cannot:

- Crash the kernel (no unchecked pointers).
- Permanently starve the system (budgeted execution).
- Corrupt shared state beyond allowed map operations.

The runtime SHOULD provide:

- Per-program failure counters (OOM, budget exceeded, exception).
- Optional “circuit breaker” that temporarily disables a program after repeated failures.

---

## 9. Hook Model

microBPF defines hook *classes* and a small set of canonical context types. Platforms MAY implement only a subset.

### 9.1 Hook Types (canonical)

Each hook has:

- A numeric **hook type ID**.
- A context schema (fields + optional buffer access methods).
- A return-code interpretation.

Recommended initial hook types:

1. `MBPF_HOOK_TRACEPOINT`: lightweight tracing event.
2. `MBPF_HOOK_TIMER`: periodic execution (housekeeping, metrics aggregation).
3. `MBPF_HOOK_NET_RX`: packet receive path decision hook.
4. `MBPF_HOOK_NET_TX`: packet transmit path hook.
5. `MBPF_HOOK_SECURITY`: authorization/policy hook.
6. `MBPF_HOOK_CUSTOM`: platform-defined, versioned schema.

### 9.2 Context Exposure Principles

Contexts MUST be exposed without raw pointers. Two patterns are supported:

1. **Scalar fields**: numbers, booleans, small strings.
2. **Bounded reads/writes via helpers**:
   - `ctx.readU8(off)`, `ctx.readU16LE(off)`, `ctx.readU32LE(off)`, etc.
   - `ctx.slice(off, len)` returning a copied `Uint8Array`/`ArrayBuffer` (optional).

Rationale: exposing a zero-copy typed array view into kernel memory introduces lifetime hazards (program could retain the view). Copying or helper-based reads avoid dangling references.

### 9.3 Example: `MBPF_HOOK_NET_RX` Context

Required context fields:

- `ifindex: number`
- `pkt_len: number`
- `data_len: number` (bytes accessible via `read*`)
- `l2_proto: number` (if known)

Required context methods:

- `readU8(off) -> number`
- `readU16LE(off) -> number`
- `readU32LE(off) -> number`
- `readBytes(off, len, out /* Uint8Array */) -> number`
  - MUST copy at most `len` bytes into `out` and MUST NOT write past `out.length`.
  - MUST return the number of bytes copied on success.
  - MUST throw on type/bounds errors.

Return codes:

- `MBPF_NET_PASS = 0`
- `MBPF_NET_DROP = 1`
- `MBPF_NET_ABORT = 2` (platform-defined)

Recommended C ABI (NET_RX v1):

```c
typedef int (*mbpf_read_bytes_fn)(const void *ctx_blob,
                                 uint32_t off, uint32_t len, uint8_t *dst);

typedef struct mbpf_ctx_net_rx_v1 {
  uint32_t abi_version;   /* = 1 */
  uint32_t ifindex;
  uint32_t pkt_len;       /* original packet length */
  uint32_t data_len;      /* bytes readable via data/read_fn */
  uint16_t l2_proto;
  uint16_t flags;
  const uint8_t *data;    /* optional contiguous view */
  mbpf_read_bytes_fn read_fn; /* optional scatter-gather reader */
} mbpf_ctx_net_rx_v1_t;
```

Rules:

- If `data != NULL`, `ctx.read*` MUST read from `[data, data + data_len)`.
- Else if `read_fn != NULL`, `ctx.readBytes` MUST use it and `ctx.readU*` MAY be implemented via small stack buffers.
- If neither is present, all buffer reads MUST fail.

Recommended flag bits:

- `MBPF_CTX_F_TRUNCATED = 1u << 0` (context bytes were truncated for deferred execution)

### 9.4 Context ABI and JS Object Construction

`mbpf_run(..., ctx_blob, ctx_len, ...)` does **not** accept a serialized payload (CBOR/JSON/etc.). Instead:

- `ctx_blob` MUST point to a **hook-specific in-memory context structure** defined by the platform.
- The context structure MUST be versioned. The first field of the structure MUST be `u32 abi_version`. The version MUST be compared against the program’s manifest requirements before execution.
- The runtime MUST validate that `ctx_len` is sufficient for the claimed context ABI version.

The runtime MUST present the context to JavaScript as a host object `ctx` passed as the sole argument to `mbpf_prog(ctx)`:

- Scalar fields (e.g., `ifindex`, `pkt_len`) are exposed as read-only properties.
- Buffer access is exposed via allocation-free methods (`readU8`, `readU16LE`, `readU32LE`, `readBytes`) that perform bounds checks and copy data out.

To avoid per-invocation allocation and to control latency, the runtime SHOULD:

- Create the `ctx` host object once per `mbpf_instance_t`, and
- Update its associated opaque pointer (and/or vtable) to refer to the current `ctx_blob` at each invocation.

Platforms SHOULD implement buffer reads via a single hook-provided primitive:

- `read_bytes(ctx_blob, off, len, dst) -> int` (returns bytes copied or negative error)

`ctx.read*` methods then wrap this primitive and translate errors into JavaScript exceptions.

### 9.5 Deferred Execution Mode (Hard IRQ Safe)

Some platforms cannot safely execute an interpreter in a hard IRQ context. microBPF therefore defines a **deferred execution** mode.

#### 9.5.1 Hook Classes: Decision vs. Observer

- **Decision hooks** (e.g., `MBPF_HOOK_NET_RX`, `MBPF_HOOK_SECURITY`) MUST return a result that affects the current kernel action. These hooks MUST run inline in a safe context. If the platform cannot provide a safe inline context, the hook type MUST NOT be supported.
- **Observer hooks** (e.g., `MBPF_HOOK_TRACEPOINT`, `MBPF_HOOK_TIMER`) do not affect the immediate kernel action. These hooks MAY be executed in deferred mode.

#### 9.5.2 Queueing and Backpressure

In deferred mode, the hook provider MUST enqueue an invocation record into a bounded queue drained by a worker context. The queue MUST have a fixed maximum depth; when full:

- The invocation MUST be dropped.
- A per-program/per-hook drop counter MUST be incremented.

#### 9.5.3 Context Snapshot Requirements

Because the original context may not remain valid until the worker runs, deferred mode MUST snapshot all program-visible context:

- Scalar fields MUST be copied into the queued record.
- Any bytes accessible via `ctx.read*` MUST be copied into a bounded buffer (configurable maximum). The queued context MUST set `data_len` to the number of bytes copied. If truncation occurs, the context `flags` SHOULD include a `TRUNCATED` bit.

Programs MUST treat `data_len` as authoritative for bounds; `pkt_len` MAY exceed `data_len`.

---

## 10. Maps

Maps are persistent, bounded kernel data structures. They provide the “state” feature analogous to eBPF maps.

### 10.1 Map Types

Required map types (minimum viable set):

1. **Array map**: fixed-size indexed storage.
2. **Hash map**: key/value store with bounded entries.

Optional map types:

- **LRU hash**
- **Per-CPU variants** of array/hash
- **Ring buffer** (event output / logging)
- **Counter** (optimized atomic increments)

### 10.2 Map Definition (metadata)

Each map definition MUST include:

- `name`: unique within the program package (ASCII).
- `type`: enum.
- `key_size`: bytes (0 for array maps).
- `value_size`: bytes.
- `max_entries`: integer.
- `flags`: bitfield (e.g., `PERCPU`, `NO_PREALLOC`).

### 10.3 JS Map API

Maps SHOULD be exposed as JS objects under `maps.<name>`.

To minimize allocations, the API MUST support “out buffer” operations:

- `maps.name.lookup(key, outValue) -> boolean`
  - For hash maps, `key` MUST be a `Uint8Array` of length `key_size`.
  - For array maps, `key` MUST be a number in `[0, max_entries)`.
  - `outValue` MUST be a `Uint8Array` of length `value_size`.
- `maps.name.update(key, value, flags /* optional */) -> void`
  - For hash maps, `value` MUST be a `Uint8Array` of length `value_size`.
  - For array maps, `value` MUST be a `Uint8Array` of length `value_size`.
- `maps.name.delete(key) -> boolean` (hash only)

Convenience allocation-returning variants MAY be provided in debug or non-constrained profiles:

- `maps.name.get(key) -> Uint8Array | null`

### 10.4 Concurrency Semantics

The platform MUST define map concurrency guarantees. Recommended:

- Hash/array lookup is lock-free for readers where possible.
- Update/delete are serialized per map or per bucket (implementation choice).
- Per-CPU maps avoid global contention.

Maps MUST remain valid across program updates unless explicitly destroyed by policy. This enables “hot swap” updates.

### 10.5 64-bit Values and Counters (portable core)

MQuickJS does not provide `BigInt`, and JavaScript numbers cannot precisely represent all 64-bit integers. To avoid per-platform divergence, microBPF defines a canonical 64-bit unsigned integer representation for program-visible APIs.

#### 10.5.1 Canonical `u64` Representation in Programs

All 64-bit unsigned integers exposed to programs MUST use the following representation:

- `u64`: a JavaScript array of length 2: `[lo, hi]`
  - `lo` is the least-significant 32 bits (0…2³²-1).
  - `hi` is the most-significant 32 bits (0…2³²-1).

Programs SHOULD preallocate and reuse `u64` arrays to avoid per-invocation allocations.

#### 10.5.2 Canonical Encoding in Byte Buffers

When a `u64` value is stored into or loaded from a `Uint8Array` buffer by a standard microBPF helper, the byte order MUST be little-endian (least significant byte first), independent of CPU endianness.

#### 10.5.3 Required Helper Support

Runtimes MUST provide helper functions to move `u64` values between byte buffers and the canonical `u64` array:

- `mbpf.u64LoadLE(bytes /* Uint8Array */, off /* number */, out /* u64 */) -> void`
- `mbpf.u64StoreLE(bytes /* Uint8Array */, off /* number */, val /* u64 */) -> void`

These helpers MUST be allocation-free on the success path (§7.5.3) and MUST throw on type/bounds errors.

#### 10.5.4 Counters (recommended)

For high-frequency counters, platforms SHOULD provide a dedicated **counter map** type with atomic host-side 64-bit arithmetic (e.g., `maps.counter.add(key, delta32)`), so programs rarely need to manipulate full 64-bit values in JS.

### 10.6 Map Iteration (optional extension)

The core microBPF map API intentionally omits iteration to reduce the risk of unbounded work in hot paths. Platforms that need in-program iteration (debugging, telemetry aggregation) MAY expose a bounded iteration primitive.

If supported for hash maps, the JS API SHOULD be:

- `maps.name.nextKey(prevKey, outNextKey) -> boolean`
  - `prevKey` MUST be `null` (to request the first key) or a `Uint8Array(key_size)`.
  - `outNextKey` MUST be a `Uint8Array(key_size)` to receive the next key.
  - Returns `true` and writes `outNextKey` if a next key exists; returns `false` on end of iteration.

Rules:

- Iteration is best-effort under concurrent updates; keys MAY be skipped or repeated.
- Each `nextKey` call MUST count toward `max_helpers`.
- Loading programs that use iteration SHOULD require an explicit capability (e.g., `CAP_MAP_ITERATE`).

---

## 11. Host Helper API (`mbpf`)

The helper surface is intentionally small and capability-gated.

### 11.1 Required helpers

All platforms MUST implement:

- `mbpf.apiVersion` (number)
  - Encoded as `major << 16 | minor` for the microBPF helper API.
- `mbpf.log(level, msg)` (may be a no-op in production profiles).
- `mbpf.u64LoadLE(bytes, off, out)` and `mbpf.u64StoreLE(bytes, off, val)` (see §10.5.3).

Runtimes MAY also implement (capability-gated by policy):

- `mbpf.nowNs(out /* u64 */) -> void`
  - Writes the current monotonic time in nanoseconds into `out` as a `u64` (§10.5.1).
- `mbpf.stats()` or `mbpf.stat(name)` (debug/telemetry; shape is platform-defined).

### 11.2 Event Output (optional)

If supported, implement:

- `mbpf.emit(eventId, bytes /* Uint8Array */) -> void`
  - Backed by a ring buffer or platform event pipe.

### 11.3 Map access helpers (optional alternative)

If `maps.*` object exposure is too heavy, a lower-level API MAY be used:

- `mbpf.mapLookup(mapId, keyBytes, outValueBytes) -> boolean`
- `mbpf.mapUpdate(mapId, keyBytes, valueBytes, flags) -> void`
- `mbpf.mapDelete(mapId, keyBytes) -> boolean`

### 11.4 Capability Model

Helpers MUST be categorized into capabilities, e.g.:

- `CAP_LOG`
- `CAP_MAP_READ`
- `CAP_MAP_WRITE`
- `CAP_MAP_ITERATE`
- `CAP_EMIT`
- `CAP_TIME`
- `CAP_STATS`

Packages MUST declare requested capabilities; the loader MUST enforce a per-platform allow-list.

### 11.5 Helper ABI Versioning

microBPF helper behavior is part of the program/runtime ABI and MUST be versioned.

- Each runtime MUST expose `mbpf.apiVersion` (major/minor).
- Each program package MUST declare a required helper API version in its manifest (see §12.3).
- The loader MUST reject a program if:
  - The runtime helper API major version differs, or
  - The runtime helper API minor version is less than the program’s required minor version.

Version encoding is `u32 major<<16 | minor`.

If a platform needs to evolve a specific helper (e.g., `mbpf.emit`) with incompatible semantics without changing unrelated helpers, it MAY also version helpers individually via a manifest `helper_versions` map (see §12.3). Loaders MUST enforce per-helper versions when present.

---

## 12. Program Package Format (`.mbpf`)

microBPF programs are distributed as a single binary package to simplify loading and signing.

### 12.1 Design Requirements

The format MUST:

- Be parseable with a single pass and bounded memory.
- Support adding new sections without breaking older loaders.
- Bind metadata, bytecode, and map definitions under a signature.

### 12.2 Container Layout

All integer fields are little-endian.

#### 12.2.1 File Header

```
struct mbpf_file_header {
  u32 magic;              // "MBPF" = 0x4D425046
  u16 format_version;     // starts at 1
  u16 header_size;        // bytes, including section table
  u32 flags;              // e.g., SIGNED, DEBUG, RESERVED
  u32 section_count;
  u32 file_crc32;         // optional, 0 if unused
};
```

#### 12.2.2 Section Table

```
enum mbpf_section_type {
  MBPF_SEC_MANIFEST = 1,  // metadata (CBOR preferred; JSON allowed)
  MBPF_SEC_BYTECODE = 2,  // MQuickJS bytecode blob (relocated-to-zero form)
  MBPF_SEC_MAPS     = 3,  // map definitions (may be inside manifest instead)
  MBPF_SEC_DEBUG    = 4,  // optional debug info / symbols
  MBPF_SEC_SIG      = 5,  // signature over the package (excluding this section)
};

struct mbpf_section_desc {
  u32 type;
  u32 offset;
  u32 length;
  u32 crc32;              // optional per-section integrity
};
```

### 12.3 Manifest (metadata)

The manifest MUST include:

- `program_name` (string)
- `program_version` (string or semver)
- `hook_type` (enum)
- `hook_ctx_abi_version` (u32; required context ABI version for `hook_type`)
- `entry_symbol` (string; default `"mbpf_prog"`)
- `mquickjs_bytecode_version` (u32; must match `JS_BYTECODE_VERSION` of target runtime)
- `target`:
  - `word_size` (32/64)
  - `endianness` (`"little"`/`"big"`)
- `mbpf_api_version` (u32; encoded `major<<16|minor`; loader enforces compatibility per §11.5)
- `heap_size` (bytes)
- `budgets`:
  - `max_steps`
  - `max_helpers`
  - optional `max_wall_time_us`
- `capabilities` (array of strings/enums)
- optional `helper_versions` (map: helper name → required version; version encoding is `major<<16|minor`)
- `maps` (array of map definitions; or in `MBPF_SEC_MAPS`)

### 12.4 Bytecode Section

`MBPF_SEC_BYTECODE` contains the exact bytecode output of the toolchain in “relocated-to-zero” form (deterministic output). At load time, the loader/runtime MUST:

1. Copy the section into a writable buffer whose lifetime is ≥ the JSContext lifetime.
2. Call `JS_RelocateBytecode(ctx, buf, len)` on that copy.
3. Call `JS_LoadBytecode(ctx, buf)` to obtain the `main_func`.
4. Install/initialize the `mbpf`/`maps` objects in the global scope as needed by the program.
5. Call `JS_Run(ctx, main_func)` to initialize globals.

Implementation note: `JS_LoadBytecode()` requires that no atoms were previously defined in RAM. Loaders SHOULD avoid creating new global strings/properties before step (3).

The loader MUST reject packages where:

- The bytecode is not recognized as MQuickJS bytecode (`JS_IsBytecode(buf, len)` fails).
- The bytecode version does not match the runtime.
- Relocation fails.

Rationale: MQuickJS bytecode is intentionally not forward/backward compatible and is not self-verifying; the package format ensures explicit versioning and allows policy enforcement.

### 12.5 Signing

If `MBPF_SEC_SIG` is present, the loader MUST verify the signature before loading.

Recommended signature scheme:

- Ed25519 over the concatenation of all bytes from file start up to (but excluding) the signature section.
- Public keys provisioned by the platform (ROM or secure storage).

The platform MAY support unsigned packages only in development mode.

---

## 13. Loader and Runtime C API (Embedding Interface)

This section specifies the minimal host-facing interface for embedding microBPF.

### 13.1 Objects

- `mbpf_runtime_t`: global runtime state (maps registry, hook registry, policy).
- `mbpf_program_t`: loaded program metadata and bytecode storage.
- `mbpf_instance_t`: per-CPU or per-thread execution context (wraps `JSContext` + budgets).

### 13.2 API Sketch

```c
mbpf_runtime_t *mbpf_runtime_init(const mbpf_runtime_config_t *cfg);
void mbpf_runtime_shutdown(mbpf_runtime_t *);

int mbpf_program_load(mbpf_runtime_t *, const void *pkg, size_t pkg_len,
                      const mbpf_load_opts_t *opts, mbpf_program_t **out_prog);
int mbpf_program_unload(mbpf_runtime_t *, mbpf_program_t *);

int mbpf_program_attach(mbpf_runtime_t *, mbpf_program_t *, mbpf_hook_id_t hook);
int mbpf_program_detach(mbpf_runtime_t *, mbpf_program_t *, mbpf_hook_id_t hook);

int mbpf_run(mbpf_runtime_t *, mbpf_hook_id_t hook,
             const void *ctx_blob, size_t ctx_len,
             int32_t *out_rc);
```

Notes:

- `mbpf_run` MAY select a per-CPU instance based on current CPU.
- `ctx_blob` is a hook-specific in-memory context structure (not a serialization); runtime wraps it in a JS `ctx` object per §9.4.

### 13.3 Instance and Concurrency Model

MQuickJS contexts are not intended to be concurrently re-entered. Therefore:

- A given `mbpf_instance_t` MUST NOT be executed by more than one CPU/thread at a time.
- The runtime MUST either:
  - Provide **per-CPU instances** (recommended), or
  - Serialize execution with a lock (may be acceptable on single-core systems).

Nested execution (a hook firing while already executing microBPF on the same instance) MUST be prevented. The runtime MUST detect this and fail the nested invocation with a safe default.

The runtime MUST implement nested-execution detection. A recommended approach is a per-`mbpf_instance_t` `in_use` flag:

- Atomically set `in_use` on entry; if it was already set, treat as a nested invocation.
- Clear `in_use` on exit (including error paths).
- Count nested invocations and return the safe default without executing the program.

### 13.4 Interrupt Handler Budgeting

The runtime SHOULD implement budgeting via:

- `JS_SetContextOpaque(ctx, instance)` to access counters.
- `JS_SetInterruptHandler(ctx, mbpf_interrupt_handler)` and decrement steps.

On budget exhaustion, the handler MUST request interruption (non-zero return), and the runtime MUST treat it as invocation failure and return the safe default.

### 13.5 MQuickJS GC Reference Handling (implementation requirement)

MQuickJS uses a compacting GC and may move objects on allocation. As a result:

- Host code MUST NOT retain raw `JSValue` variables across calls that can allocate.
- Persistent references (entry function, `maps` object, preallocated buffers) MUST be held via `JSGCRef` (`JS_AddGCRef`/`JS_PushGCRef`) so that values remain valid when objects move.

This requirement is essential for a correct microBPF embedding.

In addition, when extracting raw pointers from JS values (e.g., `Uint8Array` backing stores):

- The pointer MUST be considered valid only until the next potential JS allocation.
- microBPF helpers/context methods MUST follow the allocation-free success-path contract in §7.5.3, or otherwise ensure no allocations occur while using extracted pointers.

---

## 14. Observability and Debugging

The runtime SHOULD expose:

- Per-program counters: invocations, successes, exceptions, OOM, budget exceeded.
- Optional trace logs with rate limiting.
- Optional “debug build” mode that keeps line information in bytecode (`--no-column` disabled) and enables `console.log`.

The package MAY include `MBPF_SEC_DEBUG` with:

- Symbol names (entry function, map names, hook names).
- Source hash for provenance.

---

## 15. Portability and Compatibility

### 15.1 Target Coupling

MQuickJS bytecode is:

- Architecture-dependent (word size, endianness).
- Version-dependent (`JS_BYTECODE_VERSION`).

Therefore microBPF packages MUST be built per target class (e.g., `armv7m-le-32`, `riscv32-le-32`) and per runtime bytecode version.

### 15.2 Stable Policy Surface

While bytecode is not stable, microBPF SHOULD keep:

- The `.mbpf` container format backwards compatible across format versions.
- The helper API and manifest keys stable and versioned.

---

## 16. Security Considerations

Threats addressed:

- Infinite loops / CPU starvation → step/time budgets.
- Memory exhaustion → fixed heap buffer + failure handling.
- Kernel memory corruption → no raw pointers; bounded helper reads/writes only.
- Unauthorized side effects → capability-gated helper surface.
- Supply-chain attacks → package signing + version pinning.

Residual risks:

- Bugs in the MQuickJS engine or microBPF integration code are in TCB.
- Side-channel leakage is not explicitly mitigated (platform-dependent).

Recommended hardening:

- Keep stdlib surface minimal.
- Prefer interpreter-only build where possible (omit parser/`JS_Eval` in production if the platform can).
- Fuzz the `.mbpf` parser and helper boundary.
- Rate-limit logs/events from programs.

---

## 17. Tooling (Reference Workflow)

### 17.1 Prerequisites

Before building microBPF programs, MQuickJS MUST be cloned and built:

```bash
git clone https://github.com/bellard/mquickjs
cd mquickjs
make
```

This provides the `mqjs` compiler tool required for JavaScript-to-bytecode compilation.

### 17.2 Compilation

Recommended toolchain steps (host side):

1. Compile JS to bytecode:
   - `mqjs --no-column -o prog.qjbc prog.js`
   - Use `-m32` when producing 32-bit bytecode from a 64-bit host.
2. Build manifest + map defs, then assemble `.mbpf`.
3. Sign the package.

### 17.3 Verification

The loader SHOULD verify:

- Container header, section bounds, CRCs (if present).
- Manifest schema and limits (heap size, map sizes, budgets).
- Signature (if required by policy).
- Helper ABI compatibility (`mbpf_api_version` / `helper_versions`) and granted capabilities.
- Hook/context ABI compatibility (`hook_type` + `hook_ctx_abi_version`).
- Bytecode version/target compatibility.

---

## 18. Example Program (Net RX Filter)

```js
function mbpf_prog(ctx) {
  // Drop packets whose first byte is 0xFF (toy example).
  if (ctx.pkt_len < 1)
    return 0; // PASS
  var b0 = ctx.readU8(0);
  if (b0 === 0xFF)
    return 1; // DROP
  return 0; // PASS
}
```

---

## 19. Phased Implementation Plan (suggested)

1. **Runtime MVP**: package parsing, single hook type, step budgeting, log helper.
2. **Maps MVP**: array + hash maps, JS map API.
3. **Attach API**: hook registry, multiple programs, per-CPU instances.
4. **Signing**: Ed25519 verification and policy engine.
5. **Observability**: counters, debug symbols, event output.
