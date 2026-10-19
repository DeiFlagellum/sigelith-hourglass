# Sigelith Hourglass

A public clock of sequential work for the [Sigelith](https://sigelith.org) timestamp log.
Hourglass computes a **proof of sequential work** (Cohen–Pietrzak 2018) on SHA-256, in
segments, on one CPU core. Every segment absorbs a fresh Bitcoin block and the latest Sigelith
checkpoint into its seed and chains to the previous segment's root; its record is stamped in the
public log, where independent cosigners confirm it.

What it proves: **between two events at least a given amount of time elapsed** — a lower bound,
under an explicit, published assumption about hardware speed: k, "no one computes this more than
k times faster than the measured prover". It is not a VDF: a VDF from hash functions alone does
not exist in the random-oracle model, and the price of a hash-only construction is that the
checks guarantee only a share of the work (`claim_permille`, SPEC.md §6).

**Status: phase 0, a 30-day measurement** on the Sigelith production server, from 2026-10-19
(genesis stamped as log entry #453) to 2026-11-18, with test identifiers `p0`. k = 20 is an
assumption until the measurement ends; nothing derived from phase 0 appears on Sigelith
certificates. After phase 0: analysis, a public note, then parameters and a genesis for `v1`.

## What it does not do

- no public randomness and no encryption to the future;
- one operator runs it: the clock can be stopped, but not silently forged — records are stamped
  in a public log confirmed by independent cosigners, and two different roots for one segment are
  visible to anyone;
- only lower bounds, and modest ones while k is conservative: with k = 20 and c ≈ 0.76, a week of
  segments proves about 6 hours.

## Check it yourself

    python -I reference/hourglass_ref.py verify <directory with genesis.json and segments/>

Python standard library only. It recomputes the genesis root, every seed, every proof and every
rule of SPEC.md, and prints the minimum elapsed time under the published k.

## Contents

| path | |
| --- | --- |
| `SPEC.md` | formats and algorithms (phase 0 draft) |
| `reference/` | reference implementation and verifier, Python standard library only; `gen_vectors.py` writes the test vectors |
| `vectors/vectors.json` | test vectors for any implementation |
| `prover/` | production prover in Rust with no dependencies: own SHA-256 (portable and SHA-NI), resumable run loop with durable state, proofs from subtrees; `prover/cavp/` — NIST CAVP vectors |
| `deploy/` | systemd units, input sync and installer used on the Sigelith server |
| `tests/` | reference, prover against the vectors and the reference, NIST CAVP, a differential SHA-256 test against `hashlib`, kill and resume of the run loop, the sync |

## Build and test

    cargo build --release --manifest-path prover/Cargo.toml
    cargo test --release --manifest-path prover/Cargo.toml
    python -I -m unittest discover -s tests -v
    prover/target/release/hourglass selftest
    prover/target/release/hourglass cavp prover/cavp
    prover/target/release/hourglass bench --n 22
    HOURGLASS_DIFF_COUNT=10000000 python -I -m unittest discover -s tests -k differential

Comments in the code are partly in Polish; identifiers such as D7 or D16 refer to the
operator's design decisions, which SPEC.md summarizes where they matter for the formats.

## Related

- [sigelith-cosigner](https://github.com/DeiFlagellum/sigelith-cosigner) — independent witnesses of the log
- Sigelith specification: <https://sigelith.org/spec/>
- Cohen, Pietrzak, *Simple Proofs of Sequential Work*, EUROCRYPT 2018

License: Apache-2.0 (LICENSE, NOTICE). How to cite: CITATION.cff.
