# microBPF

microBPF is a sandboxed, event-driven programmability system for constrained kernels
(RTOS, microkernels, embedded). Programs are written in JavaScript, compiled to
MQuickJS bytecode, and packaged into signed `.mbpf` bundles that the runtime loads,
attaches to hooks, and executes with strict CPU/memory budgets.

## Overview

- **Runtime**: loads packages, enforces budgets, exposes `mbpf`, `maps`, and `ctx` APIs.
- **Toolchain**: compile JS to bytecode, generate manifests, assemble `.mbpf`, sign.
- **Hooks**: NET_RX, NET_TX, TRACEPOINT, TIMER, SECURITY, CUSTOM.
- **Safety**: capability-gated helpers, bounded execution, fixed heap per program.

## Prerequisites

- POSIX shell environment
- `gcc`, `make`, `ar`
- MQuickJS source in `deps/mquickjs` (bundled in this repo)

## Build

Build MQuickJS and the microBPF library, tests, and tools:

```bash
make
```

Build just the tool binaries (manifest generator, assembler, signer):

```bash
make tools
```

Clean build artifacts:

```bash
make clean
```

## Tests

Quick smoke check:

```bash
./init.sh --quick
```

Full initialization and test run:

```bash
./init.sh
```

Run the Makefile test target (builds and executes the core test suite):

```bash
make test
```

## Toolchain Quickstart

Compile JS to bytecode, generate a manifest, assemble a package, and sign it:

```bash
make tools
mkdir -p build

# 1) Compile JS -> bytecode
./tools/mbpf-compile examples/net_rx_filter.js -o build/net_rx_filter.qjbc

# 2) Generate manifest (CBOR)
./tools/mbpf-manifest \
  -n net_rx_filter \
  -v 1.0.0 \
  --hook net_rx \
  --caps CAP_LOG,CAP_MAP_READ \
  -o build/net_rx_filter.cbor

# 3) Assemble .mbpf
./tools/mbpf-assemble \
  -m build/net_rx_filter.cbor \
  -b build/net_rx_filter.qjbc \
  --crc \
  -o build/net_rx_filter.mbpf

# 4) Sign .mbpf (optional, but recommended)
./build/mbpf_sign keygen -o build/mbpf.key
./build/mbpf_sign pubkey -k build/mbpf.key -o build/mbpf.pub
./build/mbpf_sign sign -k build/mbpf.key -i build/net_rx_filter.mbpf -o build/net_rx_filter.signed.mbpf
./build/mbpf_sign verify -k build/mbpf.pub -i build/net_rx_filter.signed.mbpf
```

## Documentation

- `SPEC.md`
- `docs/C_API_REFERENCE.md`
- `docs/JS_API_REFERENCE.md`
- `docs/PACKAGE_FORMAT.md`
- `docs/ARCHITECTURE.md`
- `docs/TOOLCHAIN.md`
