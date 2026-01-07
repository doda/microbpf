# microBPF Toolchain Guide

This document describes the CLI workflow for compiling JavaScript to MQuickJS
bytecode, generating manifests, assembling `.mbpf` packages, and signing them.

## Prerequisites

- Build MQuickJS (for `mqjs`) and the tool binaries:

```bash
make mquickjs
make tools
```

- Ensure a build output directory exists:

```bash
mkdir -p build
```

## Tool Overview

### `mbpf-compile`

Compile JavaScript to MQuickJS bytecode (`.qjbc`).

```bash
./tools/mbpf-compile [options] input.js -o output.qjbc
```

Options:
- `-o FILE` Output bytecode file (required)
- `-m32` Generate 32-bit bytecode (for 32-bit targets)
- `-h`, `--help` Show help

Notes:
- Requires `deps/mquickjs/mqjs` (built via `make mquickjs`).
- `--no-column` is passed to `mqjs` to reduce debug size.

### `mbpf-manifest`

Generate a manifest section in CBOR (default) or JSON.

```bash
./tools/mbpf-manifest [options] -o output.manifest
```

Required options:
- `-n NAME` Program name
- `-v VERSION` Program version (e.g., "1.0.0")
- `--hook TYPE` Hook type: `tracepoint`, `timer`, `net_rx`, `net_tx`, `security`, `custom`
- `-o FILE` Output manifest file

Optional options:
- `--entry SYMBOL` Entry function name (default: `mbpf_prog`)
- `--heap SIZE` Heap size in bytes (default: 8192)
- `--max-steps N` Max execution steps (default: 10000)
- `--max-helpers N` Max helper calls (default: 100)
- `--max-time-us N` Max wall time in microseconds (default: 0 = disabled)
- `--caps CAP,...` Comma-separated capabilities
- `--word-size N` Target word size: 32 or 64 (default: host)
- `--endianness E` Target endianness: `little` or `big` (default: little)
- `--json` Output JSON instead of CBOR
- `-h`, `--help` Show help

Capabilities:
`CAP_LOG`, `CAP_MAP_READ`, `CAP_MAP_WRITE`, `CAP_MAP_ITERATE`, `CAP_EMIT`,
`CAP_TIME`, `CAP_STATS`

### `mbpf-assemble`

Assemble a `.mbpf` package from a manifest and bytecode.

```bash
./tools/mbpf-assemble [options] -o output.mbpf
```

Required options:
- `-m FILE` Manifest file (CBOR or JSON)
- `-b FILE` Bytecode file (`.qjbc` from `mbpf-compile`)
- `-o FILE` Output `.mbpf` package

Optional options:
- `-d FILE` Debug info file (included as a DEBUG section)
- `--crc` Compute file and section CRCs
- `--debug` Set the DEBUG flag in the header
- `-h`, `--help` Show help

### `mbpf_sign`

Sign or verify `.mbpf` packages with Ed25519.

```bash
./build/mbpf_sign keygen -o keypair.key
./build/mbpf_sign pubkey -k keypair.key -o pub.key
./build/mbpf_sign sign -k keypair.key -i pkg.mbpf -o pkg_signed.mbpf
./build/mbpf_sign verify -k pub.key -i pkg_signed.mbpf
```

Commands:
- `keygen` Generate a new Ed25519 keypair
- `pubkey` Extract public key from a keypair
- `sign` Sign a `.mbpf` package (rejects already signed packages)
- `verify` Verify the signature on a `.mbpf` package

Options:
- `-k FILE` Key file (keypair for `sign`, public or keypair for `verify`)
- `-i FILE` Input `.mbpf` package
- `-o FILE` Output file
- `-h`, `--help` Show help

## End-to-End Pipeline Example (NET_RX)

This example uses `examples/net_rx_filter.js` and produces a signed package.

```bash
make mquickjs tools
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

# 3) Assemble the package
./tools/mbpf-assemble \
  -m build/net_rx_filter.cbor \
  -b build/net_rx_filter.qjbc \
  --crc \
  -o build/net_rx_filter.mbpf

# 4) Sign and verify
./build/mbpf_sign keygen -o build/mbpf.key
./build/mbpf_sign pubkey -k build/mbpf.key -o build/mbpf.pub
./build/mbpf_sign sign -k build/mbpf.key -i build/net_rx_filter.mbpf -o build/net_rx_filter.signed.mbpf
./build/mbpf_sign verify -k build/mbpf.pub -i build/net_rx_filter.signed.mbpf
```

Artifacts:
- `build/net_rx_filter.qjbc` bytecode
- `build/net_rx_filter.cbor` manifest section
- `build/net_rx_filter.mbpf` unsigned package
- `build/net_rx_filter.signed.mbpf` signed package
- `build/mbpf.key`, `build/mbpf.pub` signing keys

## Minimal Example (simple_prog)

```bash
./tools/mbpf-compile examples/simple_prog.js -o build/simple_prog.qjbc
./tools/mbpf-manifest -n simple_prog -v 1.0.0 --hook tracepoint -o build/simple_prog.cbor
./tools/mbpf-assemble -m build/simple_prog.cbor -b build/simple_prog.qjbc -o build/simple_prog.mbpf
```

## Troubleshooting

- `mqjs compiler not found`:
  Run `make mquickjs` and re-run `./tools/mbpf-compile`.
- `manifest generator not found` or `assembler not found`:
  Run `make tools` to build `build/mbpf_manifest_gen` and `build/mbpf_assemble`.
- `Unknown option` errors:
  Check the CLI flags above; the wrapper scripts only accept listed options.
- `package is already signed` from `mbpf_sign sign`:
  Sign the original unsigned package, not a previously signed artifact.
- `package is not signed` during verification:
  Ensure you are verifying a signed `.mbpf` and not the unsigned output.
- Signature verification failures:
  Confirm the public key matches the keypair used to sign.
- Target mismatch at load time:
  Match `--word-size` and `--endianness` to the target platform.
- Budget or heap rejections:
  Adjust `--heap`, `--max-steps`, `--max-helpers`, or `--max-time-us` values
  to fit the target policy and program needs.
