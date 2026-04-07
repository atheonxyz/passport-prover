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
├── passport-prover/     ← this repo
├── verity/              ← Verity SDK (proving engine)
└── provekit/            ← ProveKit ZK backend (Rust)
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
| **Language** | Rust (nightly-2026-03-04) | Kotlin 1.9.24 / JVM 21 | Swift 5.9 |
| **Key Libraries** | Noir, ProveKit, bn254 | BouncyCastle, Verity SDK (JNI) | Verity SDK, BigInt, CommonCrypto |
| **ASN.1/CMS Parsing** | Custom Rust | BouncyCastle | Custom DER parser |
| **Poseidon2** | bn254_blackbox_solver | Pure Kotlin (BigInteger) | Pure Swift (BigUInt) |
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

The Swift parser uses the Verity SDK via SPM. Proving requires the ProveKit native backend.

### Dependencies

- **Verity SDK**: Pulled automatically via SPM from `https://github.com/atheonxyz/verity`
- **BigInt**: Pulled automatically via SPM from `https://github.com/attaswift/BigInt`

### Build

```bash
cd parsers/swift

# Source-only mode (parsing + commitments, no proving — works on any Mac)
VERITY_SWIFT_SDK_MODE=source-only swift build

# iOS (release mode downloads pre-built xcframework — full proving on device/simulator)
VERITY_SWIFT_SDK_MODE=release swift build
```

### Building the macOS Native Library (for CLI proving)

The Verity release xcframework only includes iOS slices. To prove on macOS:

```bash
# Build ProveKit FFI first
cd $PROVEKIT_ROOT && cargo build --release -p provekit-ffi

# Build macOS static library
cd parsers/swift && bash scripts/build-macos.sh

# Build with native backend
VERITY_SWIFT_SDK_MODE=native swift build
```

### CLI Usage

```bash
swift run passport-prover \
  --dg1 <path>            \
  --sod <path>            \
  --pkp_dir <path>        \
  --csca_registry <path>  \
  [--r_dg1 <hex>]         \
  [--min_age <int>]       \
  [--max_age <int>]       \
  [--output <dir>]
```

### Example

```bash
VERITY_SWIFT_SDK_MODE=source-only swift run passport-prover \
  --dg1 ~/Downloads/dg1_full_data.bin \
  --sod ~/Downloads/sod_full_data.bin \
  --pkp_dir ../../pkp \
  --csca_registry ../../csca_registry/csca_public_key.json \
  --output ../../proofs
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
        │
        ▼
   ┌─────────┐
   │  Parser  │  Parse ASN.1 / CMS / X.509 structures
   └────┬────┘
        │
        ▼
   ┌──────────┐
   │ Validate  │  Verify CSCA → DSC → SOD signature chain
   └────┬─────┘
        │
        ▼
   ┌───────────────┐
   │ Input Builder  │  Generate JSON witness maps per circuit stage
   └──────┬────────┘
        │
        ▼
   ┌──────────┐
   │ Pipeline  │  Run 4-stage ZK proof generation
   └────┬─────┘
        │
        ▼
   Proof Files (.np) + Merkle Leaf + Scoped Nullifier
```
