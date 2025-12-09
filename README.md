# Itsuku PoW

A memory-hard Proof-of-Work (PoW) scheme implementation in Rust, based on the **Itsuku** algorithm. Itsuku is an improvement over the MTP-Argon2 scheme, designed to be resistant to ASIC/FPGA implementations by requiring significant memory bandwidth.

This implementation leverages Rust's **SIMD** capabilities (via `portable_simd`) and multi-threading to maximize solver performance on CPUs.

## 📄 Reference

This project implements the scheme described in:

> **Itsuku: a Memory-Hardened Proof-of-Work Scheme**  
> _Fabien Coelho, Arnaud Larroche, and Baptiste Colin (MINES ParisTech, PSL Research University, 2017)_

Source: [https://eprint.iacr.org/2017/1168.pdf]

Key improvements over MTP-Argon2 implemented here include:

- Challenge-dependent memory generation.
- Hardened compression function using SIMD operations.
- Merkle Tree-based solution verification.

## 🚀 Features

- **Memory-Hard:** Enforces large memory usage (configurable, defaults to \~2GB via chunk settings) to deter specialized hardware.
- **SIMD Optimized:** Uses `std::simd` for fast 64-byte element processing.
- **Multi-threaded:** Parallelizes both the memory generation phase and the nonce search loop.
- **Progress-Free:** The algorithm allows parallel segment generation, making it more "progress-free" for miners.
- **Complete CLI:** Includes tools for both solving (`search`) and verifying (`verify`) proofs.

## 🛠 Prerequisites

This project uses the experimental `portable_simd` feature. You **must** use a **Nightly** version of the Rust compiler.

```bash
rustup install nightly
rustup default nightly
```

## 📦 Installation & Building

Clone the repository and build using Cargo:

```bash
git clone https://github.com/Le-Maz/itsuku-rs.git
cd itsuku-rs
cargo build --release
```

The binary will be located at `./target/release/itsuku`.

## 💻 Usage

The application provides two main subcommands: `search` and `verify`.

### 1\. Search

The `search` command generates the memory array, builds the Merkle tree, and iterates over nonces to find a solution that satisfies the difficulty. The resulting proof is self-contained, embedding both the configuration and the challenge ID.

```bash
# Basic usage with default parameters
./target/release/itsuku search

# Custom parameters (e.g., lower difficulty for testing)
./target/release/itsuku search \
  --difficulty-bits 16 \
  --chunk-count 16 \
  --chunk-size 1024
```

**Output:**
The command outputs status logs to `stderr` and the final JSON Proof to `stdout`.

### 2\. Verification

The `verify` command accepts a JSON proof from `stdin`. Because the `Proof` structure includes the configuration parameters and the challenge ID, **no flags are required** for verification.

```bash
# 1. Search for a proof and save it
./target/release/itsuku search --difficulty-bits 16 > proof.json

# 2. Verify
# The verifier reads the config and challenge directly from the proof file
cat proof.json | ./target/release/itsuku verify
```

## ⚙️ Configuration Parameters

| Parameter            | Default | Description                                                          |
| :------------------- | :------ | :------------------------------------------------------------------- |
| `--chunk-count`      | 1024    | Number of memory chunks. Affects total memory size ($T$).            |
| `--chunk-size`       | 32768   | Size of each chunk in elements.                                      |
| `--difficulty-bits`  | 24      | Number of leading zero bits required in the final hash ($d$).        |
| `--antecedent-count` | 4       | Number of previous elements required to compute a new element ($n$). |
| `--search-length`    | 9       | Length of the hash chain search ($L$).                               |
| `--challenge-id`     | Random  | Base64 encoded challenge (Seed).                                     |

**Memory Calculation:**
Total Memory = `chunk_count` \* `chunk_size` \* 64 bytes.
_Default:_ 1024 \* 32768 \* 64 = 2 GiB.

## ⚠️ Disclaimer

This is a research-grade implementation. While it implements the cryptographic primitives described in the Itsuku paper, it has not undergone a formal security audit. Use with caution in production environments.

## License

Copyright 2025 Lech Mazur

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
