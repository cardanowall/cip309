# Label 309 Python reference examples

Self-contained Python reference implementations of the Label 309 **wire**
primitives. Each module is the smallest faithful illustration of one operation a
producer or verifier performs when building and checking a Proof-of-Existence
record.

These examples are a **byte-parity twin** of the
[TypeScript examples](../typescript): fed the same deterministic inputs, the two
implementations produce **byte-identical** output for every pure-function
operation (canonical CBOR, COSE_Sign1, Merkle roots, sealed-PoE wrap, ...). The
canonical conformance vectors that pin this parity live in
[`../../conformance`](../../conformance).

## Self-contained

Nothing here imports a published CardanoWall SDK. The implementations build only
on widely-used, audited public libraries:

- [`cryptography`](https://pypi.org/project/cryptography/) — X25519, Ed25519
  key handling, HKDF, ChaCha20-Poly1305.
- [`PyNaCl`](https://pypi.org/project/PyNaCl/) — strict RFC 8032 Ed25519
  verify, XChaCha20-Poly1305 AEAD.
- [`cbor2`](https://pypi.org/project/cbor2/) — canonical CBOR (RFC 8949 §4.2.1).
- [`argon2-cffi`](https://pypi.org/project/argon2-cffi/) — Argon2id (sealed-PoE
  passphrase path).
- [`kyber-py`](https://pypi.org/project/kyber-py/) — ML-KEM-768, over which the
  X-Wing hybrid KEM combiner is rebuilt explicitly.
- [`httpx`](https://pypi.org/project/httpx/) — outbound HTTP for the standalone
  verifier only (every other module is pure and offline).

## What each file shows

Modules live under [`label309_examples/`](./label309_examples):

| Module                     | Primitive                                                      |
| -------------------------- | -------------------------------------------------------------- |
| `hash_dual.py`             | SHA-256 + BLAKE2b-256 content hashing.                         |
| `cbor_canonical.py`        | Canonical CBOR encode/decode; float rejection.                 |
| `cose_sign1.py`            | COSE_Sign1 encode/decode + RFC 9052 Sig_structure.             |
| `ed25519.py`               | Strict (RFC 8032 §5.1.7) Ed25519 sign / verify / keygen.       |
| `x25519.py`                | X25519 keygen + ECDH.                                          |
| `mlkem768x25519.py`        | X-Wing hybrid KEM (ML-KEM-768 + X25519).                       |
| `hkdf.py`                  | HKDF-SHA-256.                                                  |
| `seed_derive.py`           | Seed → Ed25519 / X25519 / X-Wing keypairs (stops at the seed). |
| `merkle_sha2_256.py`       | RFC 6962 Merkle tree, roots + inclusion proofs.                |
| `merkle_leaves_list.py`    | Canonical-CBOR Merkle leaves-list codec.                       |
| `cid_validator.py`         | IPFS CID (v0/v1) structural validator.                         |
| `off_host_sign.py`         | Off-host (KMS / HSM / air-gapped) record signing helper.       |
| `label309_validator.py`    | Pure-function structural validator over record CBOR bytes.     |
| `ecies_sealed_poe.py`      | Multi-recipient sealed-PoE wrap / unwrap (x25519 + X-Wing).    |
| `passphrase_kdf_unwrap.py` | Passphrase (Argon2id) sealed-PoE wrap / unwrap.                |
| `passphrase.py`            | Passphrase normalization (NFKC + whitespace) for the KDF.      |
| `cbor_walker.py`           | Position-aware walker: extract label-309 bytes from a tx.      |
| `standalone_verifier.py`   | Service-independent verifier: fetch tx → validate → verify.    |

Two runnable entry points:

- [`end_to_end.py`](./end_to_end.py) — a full publish/verify walkthrough: build
  a record → canonical-CBOR encode → attach a COSE_Sign1 → decode → validate →
  verify the signature → recompute content hashes → sealed-PoE wrap then unwrap.
  It asserts byte-parity against a pinned vector along the way.
- `label309_examples/standalone_verifier.py` exposes `verify_tx(...)`, which
  resolves a Cardano transaction through a caller-supplied gateway (Koios /
  Blockfrost), extracts the label-309 record, runs the structural validator,
  checks confirmation depth, and verifies record-level signatures, sealed-PoE
  decryption, and Merkle commitments. No issuer server is contacted.

## How to run

With [uv](https://docs.astral.sh/uv/):

```bash
uv sync                      # create the venv and install dependencies
uv run python end_to_end.py  # run the end-to-end demo
```

Or, with any environment where the package is installed / on the path:

```bash
python -m label309_examples.merkle_sha2_256   # module self-test
python -m label309_examples.cid_validator     # module self-test
```

Quality gates (linter + type checker):

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy label309_examples end_to_end.py
```

## Out of scope

These examples cover the **wire standard only**. The identity key-envelope —
building or unlocking the envelope, diceware passphrases, the passphrase/PIN
vault, and envelope discovery — is **out of scope** and does not appear here.
Key derivation is demonstrated only down to the seed (`seed_derive.py`); how a
seed is stored and protected is an implementation concern outside this standard.
The sealed-PoE passphrase path (an Argon2id-derived content-encryption key)
**is** in scope and is included; the separate envelope-discovery KDF is not.

## License

Apache-2.0 (see [`../../LICENSE`](../../LICENSE)).
