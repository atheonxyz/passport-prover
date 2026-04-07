# Passport Prover - Parsers

Parser implementations for ePassport data extraction and Zero-Knowledge proof generation. These parsers read raw ePassport binary files (DG1, SOD) and produce ZK proofs that verify passport authenticity without revealing sensitive personal data.

## Prerequisites

### External Repositories

Two external repos are required. Clone them as siblings to this repo:

```bash
# From the parent directory of passport-prover:
git clone https://github.com/atheonxyz/verity
git clone -b v1 https://github.com/worldfnd/provekit
```

Expected directory layout:

```
workspace/
├── passport-prover/     <- this repo
├── verity/              <- Verity SDK (proving engine)
└── provekit/            <- ProveKit ZK backend (Rust)
```

Alternatively, set environment variables to point to custom locations:

```bash
export VERITY_DIR=/path/to/verity
export PROVEKIT_ROOT=/path/to/provekit
```

### Prover Key Files

Pre-compiled prover key files (`.pkp`) are required for proof generation:

- `t_add_dsc_1300-prover.pkp`
- `t_add_id_data_1300-prover.pkp`
- `t_add_integrity_commit-prover.pkp`
- `t_attest-prover.pkp`

Place these in the `pkp/` directory at the repo root.

### CSCA Registry

A CSCA public key registry (`csca_registry/csca_public_key.json`) is included for automatic country-based CSCA key lookup.

---

## Implementations

| | Rust | Kotlin | Swift |
|---|---|---|---|
| **Purpose** | End-to-end ZK proof generation (native) | End-to-end ZK proof generation (JVM/Android) | End-to-end ZK proof generation (iOS/macOS) |
| **Language** | Rust (nightly-2026-03-04) | Kotlin 1.9.24 / JVM 21 | Swift 5.9+ |
| **Key Libraries** | Noir, ProveKit, bn254 | BouncyCastle, Verity SDK (JNI) | Verity SDK, BigInt, CommonCrypto |
| **ASN.1/CMS Parsing** | Custom Rust | BouncyCastle | Custom DER parser |
| **Poseidon2** | bn254_blackbox_solver | Pure Kotlin (BigInteger) | Pure Swift (BigUInt, ported from Kotlin) |
| **Output** | `.np` proof files + Merkle leaf | `.np` proof files + Merkle leaf | `.np` proof files + Merkle leaf |

---

## Rust Parser

The Rust parser is the primary proof generation pipeline. It uses ProveKit crates directly.

### Dependencies

Requires `provekit` cloned at `../../provekit` relative to `parsers/rust/`, or override paths in `Cargo.toml`.

### Build & Run

```bash
cd parsers/rust
cargo build --release

./target/release/passport-prover \
  --dg1 <PATH>       \
  --sod <PATH>       \
  --pkp_dir <PATH>   \
  [--r_dg1 <HEX>]   \
  [--min_age <U8>]   \
  [--max_age <U8>]   \
  [--output <PATH>]
```

### Example

```bash
./target/release/passport-prover \
  --dg1 ./data/dg1.bin \
  --sod ./data/sod.bin \
  --pkp_dir ../../pkp/ \
  --output ./proofs/
```

---

## Kotlin Parser

The Kotlin parser uses the Verity SDK with JNI bindings to ProveKit.

### Dependencies

Requires `verity` cloned at `../../verity` relative to `parsers/kotlin/`, or set `VERITY_DIR`.

### Building the JNI Library

Build ProveKit FFI first, then the JNI bridge:

```bash
cd $PROVEKIT_ROOT && cargo build --release -p provekit-ffi
cd parsers/kotlin && bash scripts/build-macos-jni.sh
```

Requires JDK with JNI headers (e.g. `openjdk@17` via Homebrew or `JAVA_HOME` set).

### Build & Run

```bash
cd parsers/kotlin
./gradlew build
./gradlew fatJar

# Run via Gradle
./gradlew run --args="--dg1 <path> --sod <path> --pkp_dir <path> --csca_registry <path>"

# Run via fat JAR
java -Djava.library.path=./native \
  -jar build/libs/passport-prover-0.1.0-all.jar \
  --dg1 <path> --sod <path> --pkp_dir <path> --csca_registry <path>
```

### Example

```bash
java -Djava.library.path=./native \
  -jar build/libs/passport-prover-0.1.0-all.jar \
  --dg1 ~/Downloads/dg1_full_data.bin \
  --sod ~/Downloads/sod_full_data.bin \
  --pkp_dir ../../pkp \
  --csca_registry ../../csca_registry/csca_public_key.json \
  --output ../../proofs
```

---

## Swift Parser

The Swift parser uses the Verity SDK via SPM with ProveKit as the proving backend.

### How the Native Backend Works

The Verity SDK's proving engine is written in **Rust**. To use it from Swift, that Rust code must be compiled into a native library and packaged as an **xcframework** — this is the format SPM requires to link native binary libraries. The xcframework bundles the compiled static library (`.a`) together with C headers and a module map so Swift can call the Rust functions through a C dispatch layer.

The architecture looks like this:

```
Swift code -> Verity SDK (Swift) -> VerityDispatch (C) -> VerityFFI (xcframework) -> ProveKit (Rust)
```

### SDK Modes

The Verity SDK supports three modes, controlled by the `VERITY_SWIFT_SDK_MODE` environment variable:

| Mode | What it does | Proving? | Use case |
|------|-------------|----------|----------|
| `source-only` | Compiles a stub C backend. No real proving engine linked. | No | Development, testing parsing/commitments on any Mac |
| `release` | Downloads a pre-built xcframework from GitHub. Contains iOS slices only. | iOS only | iOS app builds |
| `native` | Uses a locally-built xcframework with macOS slices. | Yes (macOS + iOS) | Full end-to-end proving on Mac CLI |

### Dependencies

- **Verity SDK**: Pulled automatically via SPM from `https://github.com/atheonxyz/verity`
- **BigInt**: Pulled automatically via SPM from `https://github.com/attaswift/BigInt`

For native mode, the Verity SDK must be a **local path dependency** (not GitHub) because the SDK's `Package.swift` uses `#filePath` to locate the xcframework relative to itself. When fetched from GitHub, it can't find a locally-built xcframework. Setting `VERITY_DIR` switches to the local repo automatically.

### Quick Start (source-only, no proving)

```bash
cd parsers/swift
VERITY_SWIFT_SDK_MODE=source-only swift build
VERITY_SWIFT_SDK_MODE=source-only swift run passport-prover \
  --dg1 <path> --sod <path> --pkp_dir ../../pkp \
  --csca_registry ../../csca_registry/csca_public_key.json
```

This runs parsing, validation, and Poseidon2 commitment computation but skips proof generation.

### Full Proving on macOS

**Step 1: Build ProveKit FFI**

```bash
cd $PROVEKIT_ROOT && cargo build --release -p provekit-ffi
```

**Step 2: Build the macOS xcframework**

```bash
cd parsers/swift && bash scripts/build-macos.sh
```

This script:
1. Compiles the C dispatch layer (`verity_dispatch.c`, `pk_backend.c`)
2. Combines it with `libprovekit_ffi.a` (the Rust proving engine) into `libverity.a`
3. Packages it as `Verity.xcframework` using `xcodebuild -create-xcframework`
4. Places it at `$VERITY_DIR/output/Verity.xcframework` where the SDK expects it

**Step 3: Build and run with native backend**

```bash
VERITY_SWIFT_SDK_MODE=native VERITY_DIR=/path/to/verity swift build
VERITY_SWIFT_SDK_MODE=native VERITY_DIR=/path/to/verity swift run passport-prover \
  --dg1 <path> --sod <path> --pkp_dir ../../pkp \
  --csca_registry ../../csca_registry/csca_public_key.json \
  --output ../../proofs
```

### Example (full proving)

```bash
VERITY_SWIFT_SDK_MODE=native VERITY_DIR=/path/to/verity swift run passport-prover \
  --dg1 ~/Downloads/dg1_full_data.bin \
  --sod ~/Downloads/sod_full_data.bin \
  --pkp_dir ../../pkp \
  --csca_registry ../../csca_registry/csca_public_key.json \
  --output ../../proofs
```

Expected output:

```
Parsing SOD (2683 bytes)...
Loading CSCA registry: ../../csca_registry/csca_public_key.json
Looking up CSCA for country: USA
  Matched CSCA key: serial=4E32D006
Validating passport data chain...
Extracting circuit inputs...
Country: USA
Commitments computed in 0.98s
[1/4] t_add_dsc_1300        done in 1.82s (load 0.48s)  comm_out=0x075058127f421dd4
[2/4] t_add_id_data_1300    done in 0.94s (load 0.15s)  comm_out=0x13df2cd4cf19ee5e
[3/4] t_add_integrity_commit done in 0.55s (load 0.10s)  leaf=0x0314456fbc0a4c24
[4/4] t_attest               done in 0.24s (load 0.04s)  nullifier=

Pipeline complete in 5.40s
  leaf:              0x0314456fbc0a4c2448713ed1e29f21a93e60118938e6f1dc832d5a43b5def36e
  scoped_nullifier:  0x164cbaa7ed97fc4ab3a364d50f84e88b790528bebcc5220b20b9c6a3cf3d72a7
  Wrote ../../proofs/t_add_dsc_1300.np (719479 bytes)
  Wrote ../../proofs/t_add_id_data_1300.np (674414 bytes)
  Wrote ../../proofs/t_add_integrity_commit.np (653351 bytes)
  Wrote ../../proofs/t_attest.np (592368 bytes)
Proofs written to: ../../proofs
```

### CLI Arguments

```
Usage: passport-prover [OPTIONS]

Required:
  --dg1 <path>            Path to DG1 binary file
  --sod <path>            Path to SOD binary file
  --pkp_dir <path>        Directory containing .pkp prover files

CSCA key (one required):
  --csca <path>           Path to CSCA public key (DER-encoded)
  --csca_registry <path>  Path to CSCA registry JSON (auto-selects by country)

Optional:
  --r_dg1 <hex>           Random blinding factor for DG1 commitment
  --min_age <int>         Minimum age requirement (default: 18)
  --max_age <int>         Maximum age requirement (default: 0 = no upper bound)
  --output <dir>          Directory to write .np proof files
  -h, --help              Show this help message
```

---

## Output

All parsers produce the same output when `--output` is specified:

| File | Stage | Description |
|---|---|---|
| `t_add_dsc_1300.np` | DSC Verification | Verifies CSCA signature over the Document Signing Certificate |
| `t_add_id_data_1300.np` | ID Data Verification | Verifies DSC signature over passport signed attributes |
| `t_add_integrity_commit.np` | Integrity Commitment | Verifies DG1 hash chain and computes Merkle leaf |
| `t_attest.np` | Attestation | Proves age requirement and computes scoped nullifier |

The Merkle leaf and scoped nullifier are printed to stdout.

---

## Architecture

```
ePassport Binary Files (DG1, SOD)
        |
        v
   +---------+
   |  Parser  |  Parse ASN.1 / CMS / X.509 structures
   +----+----+
        |
        v
   +----------+
   | Validate  |  Verify CSCA -> DSC -> SOD signature chain
   +----+-----+
        |
        v
   +---------------+
   | Input Builder  |  Generate JSON witness maps per circuit stage
   +------+--------+
        |
        v
   +----------+
   | Pipeline  |  Run 4-stage ZK proof generation
   +----+-----+
        |
        v
   Proof Files (.np) + Merkle Leaf + Scoped Nullifier
```
