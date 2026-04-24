# MVP

## Goal

Produce the first defensible answer to this question:

"Can we materially improve the current no-softfork QSB frontier without changing Bitcoin consensus?"

The repo does not need a wallet, a broadcaster, or a polished user flow. It needs a serious model, a comparable baseline, and at least one candidate construction worth deeper implementation.

## Baseline assumptions

The public QSB baseline currently states:

- legacy script only
- `201` non-push opcodes
- `10,000` byte script limit
- hash-to-signature puzzle based on `OP_RIPEMD160`
- HORS-like digest layer
- estimated total honest cost around `$75-$150`
- non-standard transaction, miner-direct submission required

Those numbers come from the public upstream README and paper and should be treated as the initial baseline until we import and calibrate the generator.

## MVP deliverables

1. Baseline model

- Encode the current public QSB point as a machine-readable baseline.
- Separate consensus limits from policy limits.
- Track script bytes, non-push opcodes, digest bits, and honest work separately.

2. Frontier model

- Implement a search tool for candidate constructions.
- Support at least:
  - HORS-like baseline
  - grouped-choice limited-use codebook candidate
- Expose a stable reporting format for side-by-side comparisons.

3. First research memo

- State where modern hash research helps.
- State where modern hash research does not help because Bitcoin Script cannot use those primitives on chain.
- Identify the first backend that is actually worth implementing.

## Metrics

The repo will compare candidates using:

- raw choice entropy bits
- adjusted digest / security bits once calibrated against the baseline generator
- effective security under Grover-style search assumptions
- honest work target
- bytes per effective digest bit
- non-push opcodes per effective digest bit
- bits per revealed opening
- tuning slack against the fixed hash-to-signature puzzle target

## What counts as an interesting result

At least one of:

- A candidate beats the public baseline on one core metric without losing badly on the others.
- A negative result shows that a whole family of modern-looking candidates is structurally worse under Bitcoin Script.
- A compiler result shows the public baseline is already close to optimal under the current limits.

## Current thesis

The most likely first interesting result is negative for naive tree-based designs:

- Direct FORS / SLH-DSA-style authentication paths probably lose under Bitcoin’s byte and opcode limits.
- The more promising path is a limited-use codebook construction that increases digest bits per checked opening without adding Merkle path overhead.
