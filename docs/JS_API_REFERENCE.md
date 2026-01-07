# microBPF JavaScript API Reference

This document provides a comprehensive reference for writing microBPF programs in JavaScript. It covers all global objects, helpers, maps, and context APIs available to program authors.

## Table of Contents

- [Overview](#overview)
- [Program Entry Points](#program-entry-points)
- [Global Objects](#global-objects)
  - [mbpf Object](#mbpf-object)
  - [maps Object](#maps-object)
  - [ctx Object](#ctx-object)
- [mbpf Helper API](#mbpf-helper-api)
  - [mbpf.apiVersion](#mbpfapiversion)
  - [mbpf.log](#mbpflog)
  - [mbpf.u64LoadLE](#mbpfu64loadle)
  - [mbpf.u64StoreLE](#mbpfu64storele)
  - [mbpf.nowNs](#mbpfnowns)
  - [mbpf.emit](#mbpfemit)
  - [mbpf.stats](#mbpfstats)
  - [mbpf.mapLookup](#mbpfmaplookup)
  - [mbpf.mapUpdate](#mbpfmapupdate)
  - [mbpf.mapDelete](#mbpfmapdelete)
- [Maps API](#maps-api)
  - [Array Maps](#array-maps)
  - [Hash Maps](#hash-maps)
  - [LRU Hash Maps](#lru-hash-maps)
  - [Per-CPU Maps](#per-cpu-maps)
  - [Ring Buffer Maps](#ring-buffer-maps)
  - [Counter Maps](#counter-maps)
- [Context API](#context-api)
  - [Common Context Methods](#common-context-methods)
  - [NET_RX Context](#net_rx-context)
  - [NET_TX Context](#net_tx-context)
  - [TRACEPOINT Context](#tracepoint-context)
  - [TIMER Context](#timer-context)
  - [SECURITY Context](#security-context)
  - [CUSTOM Context](#custom-context)
- [Return Codes](#return-codes)
- [Capabilities](#capabilities)
- [64-bit Value Representation](#64-bit-value-representation)
- [Code Examples](#code-examples)

---

## Overview

microBPF programs are written in JavaScript and execute in a sandboxed environment. Programs have access to three global objects:

- **`mbpf`**: Host API namespace containing helper functions
- **`maps`**: Map objects defined in the program manifest
- **`ctx`**: Hook-specific context passed to the entry function

### Language Profile

Programs run on MQuickJS, a compact JavaScript engine supporting approximately ES5 plus select extensions. Key restrictions:

- No `Function` constructor (dynamic code generation disabled)
- No `eval` (unless explicitly enabled)
- No filesystem or network APIs
- Optional `console.log` (debug mode only, maps to `mbpf.log`)
- Binary buffers must be `Uint8Array` (other TypedArrays are not supported)

### Memory and Execution Bounds

Programs execute within strict resource limits defined in the manifest:

- **`heap_size`**: Maximum JavaScript heap memory (minimum 8192 bytes)
- **`max_steps`**: Maximum VM execution steps per invocation
- **`max_helpers`**: Maximum helper calls per invocation
- **`max_wall_time_us`**: Optional wall-clock timeout

---

## Program Entry Points

### mbpf_prog (required)

The main entry point called on each hook invocation.

```javascript
function mbpf_prog(ctx) {
    // Process context and return result
    return 0;
}
```

**Parameters:**
- `ctx`: Hook-specific context object

**Returns:** 32-bit signed integer. Interpretation depends on hook type.

### mbpf_init (optional)

Called once after program load, before the first `mbpf_prog` invocation.

```javascript
function mbpf_init() {
    // Initialize program state
    // Maps are available here
}
```

### mbpf_fini (optional)

Called at program unload (best-effort).

```javascript
function mbpf_fini() {
    // Cleanup (optional)
}
```

---

## Global Objects

### mbpf Object

The `mbpf` object provides helper functions and runtime information.

| Property/Method | Capability | Description |
|-----------------|------------|-------------|
| `apiVersion` | - | API version number |
| `log(level, msg)` | `CAP_LOG` | Log a message |
| `u64LoadLE(bytes, off, out)` | - | Load 64-bit value from buffer |
| `u64StoreLE(bytes, off, val)` | - | Store 64-bit value to buffer |
| `nowNs(out)` | `CAP_TIME` | Get monotonic time in nanoseconds |
| `emit(eventId, bytes)` | `CAP_EMIT` | Emit event to host |
| `stats(out)` | `CAP_STATS` | Get program statistics |
| `mapLookup(mapId, key, out)` | `CAP_MAP_READ` | Low-level map lookup |
| `mapUpdate(mapId, key, val, flags)` | `CAP_MAP_WRITE` | Low-level map update |
| `mapDelete(mapId, key)` | `CAP_MAP_WRITE` | Low-level map delete |

### maps Object

The `maps` object provides named access to maps defined in the program manifest.

```javascript
// Access maps by name
maps.myarray.lookup(index, outBuffer);
maps.myhash.update(keyBuffer, valueBuffer);
```

See [Maps API](#maps-api) for detailed documentation of each map type.

### ctx Object

The `ctx` object provides hook-specific context data. It is passed as the sole argument to `mbpf_prog()`.

See [Context API](#context-api) for detailed documentation per hook type.

---

## mbpf Helper API

### mbpf.apiVersion

The runtime's helper API version encoded as `(major << 16) | minor`.

```javascript
var version = mbpf.apiVersion;  // e.g., 0x00010000 for version 1.0
var major = (version >> 16) & 0xFFFF;
var minor = version & 0xFFFF;
```

**Type:** `number` (read-only property)

### mbpf.log

Log a message. Capability: `CAP_LOG`.

```javascript
mbpf.log(level, message);
```

**Parameters:**
- `level` (number): Log level (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR)
- `message` (string): Message to log

**Returns:** `undefined`

**Notes:**
- In production mode, log messages are rate-limited (100 per second)
- In debug mode, all messages are logged
- `level` is clamped to 0-3; non-numeric levels default to 1
- `message` must be a string; other types throw `TypeError`

**Example:**
```javascript
mbpf.log(1, "Packet received");
mbpf.log(3, "Error: invalid checksum");
```

### mbpf.u64LoadLE

Load a 64-bit unsigned integer from a byte buffer in little-endian format.

```javascript
mbpf.u64LoadLE(bytes, offset, out);
```

**Parameters:**
- `bytes` (Uint8Array): Source buffer (must be at least `offset + 8` bytes)
- `offset` (number): Byte offset to read from
- `out` (Array): Output array of length 2: `[lo, hi]`

**Returns:** `undefined`

**Throws:**
- `TypeError` if arguments have wrong types
- `RangeError` if offset is out of bounds

**Example:**
```javascript
var data = new Uint8Array(8);
var u64 = [0, 0];
mbpf.u64LoadLE(data, 0, u64);
// u64[0] = low 32 bits, u64[1] = high 32 bits
```

### mbpf.u64StoreLE

Store a 64-bit unsigned integer to a byte buffer in little-endian format.

```javascript
mbpf.u64StoreLE(bytes, offset, value);
```

**Parameters:**
- `bytes` (Uint8Array): Destination buffer (must be at least `offset + 8` bytes)
- `offset` (number): Byte offset to write to
- `value` (Array): Input array of length 2: `[lo, hi]`

**Returns:** `undefined`

**Throws:**
- `TypeError` if arguments have wrong types
- `RangeError` if offset is out of bounds

**Example:**
```javascript
var data = new Uint8Array(8);
var u64 = [0x12345678, 0x9ABCDEF0];
mbpf.u64StoreLE(data, 0, u64);
// data now contains the 64-bit value in LE format
```

### mbpf.nowNs

Get the current monotonic time in nanoseconds. Capability: `CAP_TIME`.

```javascript
mbpf.nowNs(out);
```

**Parameters:**
- `out` (Array): Output array of length 2: `[lo, hi]`

**Returns:** `undefined`

**Throws:**
- `TypeError` if `out` is not an array of length >= 2

**Example:**
```javascript
var startTime = [0, 0];
var endTime = [0, 0];
mbpf.nowNs(startTime);
// ... do work ...
mbpf.nowNs(endTime);
```

### mbpf.emit

Emit an event to the host. Capability: `CAP_EMIT`.

```javascript
var success = mbpf.emit(eventId, bytes);
```

**Parameters:**
- `eventId` (number): Application-defined event identifier
- `bytes` (Uint8Array): Event payload data

**Returns:** `boolean`
- `true`: Event was successfully queued
- `false`: Event was too large or could not fit in the buffer

**Notes:**
- `eventId` is stored as an unsigned 32-bit value
- Maximum event size is 256 bytes by default (from `MBPF_EMIT_MAX_EVENT_SIZE`)
- Events are stored in a per-program ring buffer and can be read by the host
- When the buffer is full, oldest events are dropped to make room

**Example:**
```javascript
var payload = new Uint8Array([1, 2, 3, 4]);
if (!mbpf.emit(42, payload)) {
    mbpf.log(2, "Event dropped");
}
```

### mbpf.stats

Get current program statistics. Capability: `CAP_STATS`.

```javascript
mbpf.stats(out);
```

**Parameters:**
- `out` (Object): Output object with preallocated `[lo, hi]` arrays

**Returns:** `undefined`

**Throws:** `TypeError` if output fields are missing or wrong type

**Required output fields:**
| Field | Type | Description |
|-------|------|-------------|
| `invocations` | `[lo, hi]` | Total invocation count |
| `successes` | `[lo, hi]` | Successful invocations |
| `exceptions` | `[lo, hi]` | Exceptions thrown |
| `oom_errors` | `[lo, hi]` | Out-of-memory errors |
| `budget_exceeded` | `[lo, hi]` | Budget exceeded events |
| `nested_dropped` | `[lo, hi]` | Nested invocations dropped |
| `deferred_dropped` | `[lo, hi]` | Deferred invocations dropped |

**Example:**
```javascript
var stats = {
    invocations: [0, 0],
    successes: [0, 0],
    exceptions: [0, 0],
    oom_errors: [0, 0],
    budget_exceeded: [0, 0],
    nested_dropped: [0, 0],
    deferred_dropped: [0, 0]
};
mbpf.stats(stats);
mbpf.log(1, "Invocations: " + stats.invocations[0]);
```

### mbpf.mapLookup

Low-level map lookup by numeric ID. Capability: `CAP_MAP_READ`.

```javascript
var found = mbpf.mapLookup(mapId, key, outValue);
```

**Parameters:**
- `mapId` (number): Map index (0-based, in manifest order)
- `key` (number|Uint8Array): Key (number for array maps, Uint8Array for hash maps)
- `outValue` (Uint8Array): Buffer to receive value

**Returns:** `boolean` - `true` if found, `false` otherwise

**Notes:**
- Supported map types: array, hash, LRU hash, per-CPU array, per-CPU hash
- Ring buffer and counter maps do not support low-level lookup/update/delete helpers

### mbpf.mapUpdate

Low-level map update by numeric ID. Capability: `CAP_MAP_WRITE`.

```javascript
var success = mbpf.mapUpdate(mapId, key, value, flags);
```

**Parameters:**
- `mapId` (number): Map index (0-based)
- `key` (number|Uint8Array): Key
- `value` (Uint8Array): Value to store
- `flags` (number): Update flags (0=create or update, 1=create only, 2=update only)

**Returns:** `boolean` - `true` on success

**Notes:**
- `flags` default to `0` when omitted
- Supported map types: array, hash, LRU hash, per-CPU array, per-CPU hash

### mbpf.mapDelete

Low-level map delete by numeric ID. Capability: `CAP_MAP_WRITE`.

```javascript
var found = mbpf.mapDelete(mapId, key);
```

**Parameters:**
- `mapId` (number): Map index (0-based)
- `key` (number|Uint8Array): Key to delete (number for array maps, Uint8Array for hash/LRU maps)

**Returns:** `boolean` - `true` if key was found and deleted

**Notes:**
- Supported map types: array, hash, LRU hash, per-CPU array, per-CPU hash

---

## Maps API

Maps are persistent key/value stores that survive across invocations. They are defined in the program manifest and accessed via the `maps` global object.

### Array Maps

Fixed-size indexed arrays where keys are numeric indices.

**Manifest definition:**
```json
{
    "name": "myarray",
    "type": "array",
    "key_size": 0,
    "value_size": 4,
    "max_entries": 100
}
```

**Methods:**

#### lookup(index, outBuffer)

Look up a value by index. Capability: `CAP_MAP_READ`.

```javascript
var found = maps.myarray.lookup(index, outBuffer);
```

- `index` (number): Array index (0 to max_entries-1)
- `outBuffer` (Uint8Array): Buffer to receive value (must be >= value_size)
- Returns: `boolean` - `true` if entry exists

#### update(index, valueBuffer)

Update a value at index. Capability: `CAP_MAP_WRITE`.

```javascript
var success = maps.myarray.update(index, valueBuffer);
```

- `index` (number): Array index
- `valueBuffer` (Uint8Array): Value to store (must be >= value_size)
- Returns: `boolean` - `true` on success

**Example:**
```javascript
var value = new Uint8Array(4);
if (maps.counters.lookup(0, value)) {
    value[0]++;
    maps.counters.update(0, value);
}
```

### Hash Maps

Key/value stores with arbitrary byte keys. Uses FNV-1a hashing with linear probing.

**Manifest definition:**
```json
{
    "name": "myhash",
    "type": "hash",
    "key_size": 8,
    "value_size": 16,
    "max_entries": 100
}
```

**Methods:**

#### lookup(keyBuffer, outBuffer)

Look up a value by key. Capability: `CAP_MAP_READ`.

```javascript
var found = maps.myhash.lookup(keyBuffer, outBuffer);
```

- `keyBuffer` (Uint8Array): Key (must be >= key_size)
- `outBuffer` (Uint8Array): Buffer to receive value
- Returns: `boolean` - `true` if key found

#### update(keyBuffer, valueBuffer)

Insert or update a key/value pair. Capability: `CAP_MAP_WRITE`.

```javascript
var success = maps.myhash.update(keyBuffer, valueBuffer);
```

- `keyBuffer` (Uint8Array): Key
- `valueBuffer` (Uint8Array): Value
- Returns: `boolean` - `true` on success, `false` if table full

#### delete(keyBuffer)

Delete an entry by key. Capability: `CAP_MAP_WRITE`.

```javascript
var found = maps.myhash.delete(keyBuffer);
```

- `keyBuffer` (Uint8Array): Key to delete
- Returns: `boolean` - `true` if key was found and deleted

#### nextKey(prevKey, outKey)

Iterate over keys. Capability: `CAP_MAP_ITERATE`.

```javascript
var hasNext = maps.myhash.nextKey(prevKey, outKey);
```

- `prevKey` (null|Uint8Array): Previous key, or `null` for first key
- `outKey` (Uint8Array): Buffer to receive next key
- Returns: `boolean` - `true` if next key exists

**Notes:**
- Iteration is best-effort under concurrent updates
- Each `nextKey` call counts toward `max_helpers` budget

**Example:**
```javascript
var key = new Uint8Array(8);
var value = new Uint8Array(16);
var prev = null;

while (maps.myhash.nextKey(prev, key)) {
    maps.myhash.lookup(key, value);
    // Process key/value
    prev = key.slice();  // Copy for next iteration
}
```

### LRU Hash Maps

Hash maps with automatic least-recently-used eviction when at capacity.

**Manifest definition:**
```json
{
    "name": "mylru",
    "type": "lru_hash",
    "key_size": 8,
    "value_size": 16,
    "max_entries": 100
}
```

**Methods:**

Same as hash maps: `lookup`, `update`, `delete`, `nextKey`.

**Behavior differences:**
- `lookup()` moves the entry to the front of the LRU list (most recently used)
- `update()` moves the entry to the front
- When at capacity, `update()` with a new key evicts the least recently used entry
- `update()` returns `false` only if eviction fails (no slots available)

**Example:**
```javascript
// Cache with automatic eviction
var key = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
var value = new Uint8Array(16);

// Store value (may evict old entries if at capacity)
maps.cache.update(key, value);

// Lookup refreshes entry's LRU position
if (maps.cache.lookup(key, value)) {
    // Entry is now most recently used
}
```

### Per-CPU Maps

Maps with independent storage per CPU instance. Avoids contention in multi-CPU configurations.

**Types:** `percpu_array`, `percpu_hash`

**Manifest definition:**
```json
{
    "name": "cpu_counters",
    "type": "percpu_array",
    "key_size": 0,
    "value_size": 8,
    "max_entries": 16
}
```

**Methods:**

Same as the base type (array or hash), plus:

#### cpuId()

Get the current CPU/instance ID.

```javascript
var cpu = maps.cpu_counters.cpuId();
```

- Returns: `number` - Current instance index (0-based)

**Notes:**
- Per-CPU array maps provide `lookup()` and `update()` only
- Per-CPU hash maps provide `lookup()`, `update()`, `delete()`, and `nextKey()`
- Helper budget tracking applies, but capability checks are not enforced for per-CPU maps in the current runtime

**Example:**
```javascript
var value = new Uint8Array(8);
var cpu = maps.cpu_counters.cpuId();

if (maps.cpu_counters.lookup(0, value)) {
    // Increment local counter
    value[0]++;
    maps.cpu_counters.update(0, value);
}
```

### Ring Buffer Maps

Circular buffers for event output. Supports multiple producers, single consumer.

**Manifest definition:**
```json
{
    "name": "events",
    "type": "ring",
    "key_size": 0,
    "value_size": 256,
    "max_entries": 4096
}
```

The `value_size` specifies maximum event size. The buffer size in bytes is `max_entries * value_size` (with a minimum of 64 bytes).

**Methods:**

#### submit(eventData)

Submit an event to the ring buffer. Capability: `CAP_MAP_WRITE`.

```javascript
var success = maps.events.submit(eventData);
```

- `eventData` (Uint8Array): Event payload
- Returns: `boolean` - `true` on success, `false` if event too large

When the buffer is full, oldest events are automatically dropped.

#### count()

Get number of events in the buffer. Capability: `CAP_MAP_READ`.

```javascript
var n = maps.events.count();
```

- Returns: `number` - Event count

#### dropped()

Get number of dropped events. Capability: `CAP_MAP_READ`.

```javascript
var n = maps.events.dropped();
```

- Returns: `number` - Dropped event count

#### peek(outBuffer)

Read the oldest event without removing it. Capability: `CAP_MAP_READ`.

```javascript
var len = maps.events.peek(outBuffer);
```

- `outBuffer` (Uint8Array): Buffer to receive event data
- Returns: `number` - Actual event length (0 if empty). Copies up to `outBuffer.length` bytes.

#### consume()

Remove the oldest event. Capability: `CAP_MAP_WRITE`.

```javascript
var success = maps.events.consume();
```

- Returns: `boolean` - `true` if an event was removed

**Example:**
```javascript
var event = new Uint8Array(64);
event[0] = ctx.ifindex;
event[1] = ctx.pkt_len & 0xFF;
event[2] = (ctx.pkt_len >> 8) & 0xFF;
maps.events.submit(event.subarray(0, 3));
```

### Counter Maps

Optimized 64-bit counters with atomic operations.

**Manifest definition:**
```json
{
    "name": "stats",
    "type": "counter",
    "key_size": 0,
    "value_size": 8,
    "max_entries": 4
}
```

**Methods:**

#### add(index, delta)

Atomically add a value to a counter. Capability: `CAP_MAP_WRITE`.

```javascript
var success = maps.stats.add(index, delta);
```

- `index` (number): Counter index (0 to max_entries-1)
- `delta` (number): Value to add (can be negative)
- Returns: `boolean` - `true` on success

#### get(index)

Get the current counter value. Capability: `CAP_MAP_READ`.

```javascript
var value = maps.stats.get(index);
```

- `index` (number): Counter index
- Returns: `number` - Counter value (JavaScript number, may lose precision for large values)

#### set(index, value)

Set a counter to a specific value. Capability: `CAP_MAP_WRITE`.

```javascript
var success = maps.stats.set(index, value);
```

- `index` (number): Counter index
- `value` (number): New value
- Returns: `boolean` - `true` on success

**Example:**
```javascript
// Increment packet counter
maps.stats.add(0, 1);

// Increment byte counter by packet length
maps.stats.add(1, ctx.pkt_len);
```

---

## Context API

The context object (`ctx`) provides hook-specific input data. It is passed to `mbpf_prog()` and contains read-only properties and data access methods.

### Common Context Methods

All contexts with data buffers provide these methods:

#### readU8(offset)

Read an unsigned 8-bit value.

```javascript
var byte = ctx.readU8(offset);
```

- `offset` (number): Byte offset
- Returns: `number` - Unsigned byte value (0-255)
- Throws: `TypeError` if `offset` is not a number
- Throws: `RangeError` if offset is out of bounds

#### readU16LE(offset)

Read an unsigned 16-bit little-endian value.

```javascript
var value = ctx.readU16LE(offset);
```

- `offset` (number): Byte offset
- Returns: `number` - Unsigned 16-bit value
- Throws: `TypeError` if `offset` is not a number
- Throws: `RangeError` if offset+2 exceeds data length

#### readU32LE(offset)

Read an unsigned 32-bit little-endian value.

```javascript
var value = ctx.readU32LE(offset);
```

- `offset` (number): Byte offset
- Returns: `number` - Unsigned 32-bit value
- Throws: `TypeError` if `offset` is not a number
- Throws: `RangeError` if offset+4 exceeds data length

#### readBytes(offset, length, outBuffer)

Copy bytes to a buffer.

```javascript
var copied = ctx.readBytes(offset, length, outBuffer);
```

- `offset` (number): Byte offset
- `length` (number): Number of bytes to copy
- `outBuffer` (Uint8Array): Destination buffer
- Returns: `number` - Bytes actually copied (min of `length`, remaining data, and `outBuffer.length`)
- Throws: `TypeError` if arguments have wrong types
- Throws: `RangeError` if `offset` is out of bounds or data is unavailable

### NET_RX Context

Network packet receive context. Hook type: `MBPF_HOOK_NET_RX`.

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `ifindex` | number | Interface index |
| `pkt_len` | number | Original packet length |
| `data_len` | number | Bytes available for reading |
| `l2_proto` | number | Layer 2 protocol (e.g., 0x0800 for IPv4) |
| `flags` | number | Context flags (see below) |

**Flags:**
- `MBPF_CTX_F_TRUNCATED` (1): Data was truncated

**Methods:** `readU8`, `readU16LE`, `readU32LE`, `readBytes`

**Notes:**
- If `read_fn` is used, `data_len` reflects the bytes actually read

**Return codes:**
- `0` (`MBPF_NET_PASS`): Allow packet
- `1` (`MBPF_NET_DROP`): Drop packet
- `2` (`MBPF_NET_ABORT`): Abort (program error)

**Example:**
```javascript
function mbpf_prog(ctx) {
    // Drop packets with first byte 0xFF
    if (ctx.pkt_len >= 1) {
        var firstByte = ctx.readU8(0);
        if (firstByte === 0xFF) {
            return 1;  // DROP
        }
    }
    return 0;  // PASS
}
```

### NET_TX Context

Network packet transmit context. Hook type: `MBPF_HOOK_NET_TX`.

**Properties:** Same as NET_RX.

**Methods:** Same as NET_RX.

**Return codes:** Same as NET_RX.

### TRACEPOINT Context

Tracepoint event context. Hook type: `MBPF_HOOK_TRACEPOINT`.

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `tracepoint_id` | number | Tracepoint identifier |
| `timestamp` | number | Event timestamp (nanoseconds) |
| `cpu` | number | CPU where event occurred |
| `pid` | number | Process ID (0 if not applicable) |
| `data_len` | number | Optional data length |
| `flags` | number | Context flags |

**Methods:** `readU8`, `readU16LE`, `readU32LE`, `readBytes` (if data present)

**Notes:**
- `timestamp` is provided as a JavaScript number and may lose precision for large values

**Return codes:**
- `0`: Success
- Non-zero: Soft failure (counted in stats)

**Example:**
```javascript
function mbpf_prog(ctx) {
    mbpf.log(1, "Tracepoint " + ctx.tracepoint_id + " on CPU " + ctx.cpu);
    return 0;
}
```

### TIMER Context

Periodic timer context. Hook type: `MBPF_HOOK_TIMER`.

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `timer_id` | number | Timer identifier |
| `period_us` | number | Timer period in microseconds |
| `invocation_count` | number | Times timer has fired |
| `timestamp` | number | Current timestamp (nanoseconds) |
| `flags` | number | Context flags |

**Methods:** None (no data buffer).

**Notes:**
- `timestamp` and `invocation_count` are provided as JavaScript numbers and may lose precision for large values

**Return codes:**
- `0`: Success
- Non-zero: Soft failure

**Example:**
```javascript
function mbpf_prog(ctx) {
    // Aggregate stats every timer tick
    var pktCount = maps.stats.get(0);
    mbpf.log(1, "Packets: " + pktCount);
    return 0;
}
```

### SECURITY Context

Security/authorization context. Hook type: `MBPF_HOOK_SECURITY`.

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `subject_id` | number | Subject identifier (e.g., process, user) |
| `object_id` | number | Object identifier (e.g., resource) |
| `action` | number | Requested action/operation |
| `data_len` | number | Optional data length |
| `flags` | number | Context flags |

**Methods:** `readU8`, `readU16LE`, `readU32LE`, `readBytes` (if data present)

**Return codes:**
- `0` (`MBPF_SEC_ALLOW`): Allow operation
- `1` (`MBPF_SEC_DENY`): Deny operation
- `2` (`MBPF_SEC_ABORT`): Abort (fall through to default)

**Example:**
```javascript
function mbpf_prog(ctx) {
    // Block action 5 for subject 100
    if (ctx.subject_id === 100 && ctx.action === 5) {
        return 1;  // DENY
    }
    return 0;  // ALLOW
}
```

### CUSTOM Context

Platform-defined custom hook context. Hook type: `MBPF_HOOK_CUSTOM`.

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `custom_hook_id` | number | Platform-defined hook ID |
| `schema_version` | number | Schema version for this hook |
| `field_count` | number | Number of custom fields |
| `data_len` | number | Custom data length |
| `flags` | number | Context flags |

**Methods:**
- `readU8`, `readU16LE`, `readU32LE`, `readBytes`

**Custom field accessors:**
Custom hooks can provide a schema (`fields`) with typed field accessors. Field names become read-only properties:

| Field Type | JS Value |
|-----------|----------|
| `U8`/`I8` | number |
| `U16`/`I16` | number |
| `U32`/`I32` | number |
| `U64` | `[lo, hi]` |
| `I64` | `[lo, hi]` (signed high word) |
| `BYTES` | `Uint8Array` slice |

Field accessors are generated only when a schema is provided; otherwise only the base properties and read methods are available.

**Return codes:** Platform-defined.

---

## Return Codes

### Network Hooks (NET_RX, NET_TX)

| Constant | Value | Description |
|----------|-------|-------------|
| `MBPF_NET_PASS` | 0 | Allow packet |
| `MBPF_NET_DROP` | 1 | Drop packet |
| `MBPF_NET_ABORT` | 2 | Abort (error condition) |

### Security Hooks

| Constant | Value | Description |
|----------|-------|-------------|
| `MBPF_SEC_ALLOW` | 0 | Allow operation |
| `MBPF_SEC_DENY` | 1 | Deny operation |
| `MBPF_SEC_ABORT` | 2 | Abort (fall through) |

### Observer Hooks (TRACEPOINT, TIMER)

- `0`: Success
- Non-zero: Soft failure (counted in stats, does not affect system)

### Exception Handling

If a program throws an exception or exceeds its budget, the runtime returns a safe default:

- NET_RX, NET_TX: `MBPF_NET_PASS` (allow packet)
- SECURITY: `MBPF_SEC_DENY` (deny operation for safety)
- TRACEPOINT, TIMER: `0` (success)

---

## Capabilities

Programs must declare required capabilities in their manifest. The runtime enforces these at load time and helper call time.

| Capability | Description | Gated APIs |
|------------|-------------|------------|
| `CAP_LOG` | Logging | `mbpf.log()` |
| `CAP_MAP_READ` | Map reads | `maps.*.lookup()`, `mbpf.mapLookup()` |
| `CAP_MAP_WRITE` | Map writes | `maps.*.update()`, `maps.*.delete()`, `mbpf.mapUpdate()`, `mbpf.mapDelete()` |
| `CAP_MAP_ITERATE` | Map iteration | `maps.*.nextKey()` |
| `CAP_EMIT` | Event emission | `mbpf.emit()` |
| `CAP_TIME` | Time access | `mbpf.nowNs()` |
| `CAP_STATS` | Statistics | `mbpf.stats()` |

Calling a capability-gated helper without the required capability throws an error.

---

## 64-bit Value Representation

MQuickJS does not support `BigInt`. 64-bit unsigned integers are represented as `[lo, hi]` arrays where:

- `lo`: Low 32 bits (0 to 2³²-1)
- `hi`: High 32 bits (0 to 2³²-1)

The full 64-bit value is: `hi * 2³² + lo`

**Example:**
```javascript
// Represent 0x123456789ABCDEF0
var u64 = [0x9ABCDEF0, 0x12345678];

// Load from buffer
var bytes = new Uint8Array(8);
var result = [0, 0];
mbpf.u64LoadLE(bytes, 0, result);

// Store to buffer
mbpf.u64StoreLE(bytes, 0, result);
```

---

## Code Examples

### Simple Program (examples/simple_prog.js)

```javascript
function mbpf_prog(ctx) {
    return 0;
}
```

### NET_RX Filter (examples/net_rx_filter.js)

```javascript
function mbpf_prog(ctx) {
    if (ctx.pkt_len < 1) {
        return 0; // PASS
    }

    var b0 = ctx.readU8(0);
    if (b0 === 0xFF) {
        return 1; // DROP
    }

    return 0; // PASS
}
```
