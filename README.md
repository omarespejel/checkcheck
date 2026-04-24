# checkcheck

`checkcheck` is a research repo for the next frontier after Quantum Safe Bitcoin (QSB).

The question is not:

"Can one no-softfork quantum-safe-ish Bitcoin spend be made to work?"

That question is already being worked by StarkWare / Avihu.

The question here is:

"Under current Bitcoin consensus limits, can a limited-use hash-based construction beat the current QSB frontier on cost, size, or security?"

## Why a new repo

- The work is a different research artifact than the upstream QSB implementation.
- We need explicit baseline-vs-candidate benchmarking.
- We do not want the optimizer/compiler architecture to inherit every assumption from the upstream pipeline.
- The upstream repo mixes MIT code with GPL-covered GPU components from CudaBrainSecp, so clean isolation is useful.

## Research target

Build a frontier compiler and optimizer for no-softfork post-quantum-style Bitcoin spends.

Inputs:

- Bitcoin legacy script limits
- hash primitives that Bitcoin Script actually exposes
- candidate digest constructions
- honest-work target
- script size and opcode budgets

Outputs:

- compiled candidate configurations
- estimated digest bits
- estimated honest work
- estimated byte cost
- estimated opcode cost
- direct comparison to the public QSB baseline

## MVP

The MVP is successful if it finds a consensus-compatible candidate that improves at least one of:

- `>= 30%` lower honest work at similar security
- `>= 30%` smaller script at similar security
- `>= 10` more effective security bits at similar cost

If the optimizer fails to find such a candidate after a serious search, that is still a useful result. It would suggest the current QSB design is already near the efficient frontier under today’s Bitcoin constraints.

## First interesting result

The first calibrated result is stronger than the initial sketch:

- The imported upstream QSB baseline already uses `9953-9967` bytes out of the `10,000` byte script budget.
- `9300` of those bytes are just hardcoded commitments and dummy signatures.
- An optimistic grouped-choice family cannot catch up under the same script and op limits.
- The best grouped-choice point found by the current model reaches only `67.74` raw digest bits at `9983` bytes and `197` ops, still far below the public QSB points at `80.35` and `84.51` signed digest bits.

That shifts the thesis:

- plain grouped-choice is not the next frontier
- naive tree-based designs are still blocked by Script expressivity
- HORS-like subset encoding looks closer to the no-softfork frontier than the initial intuition suggested

Details are in [`docs/results/2026-04-24-frontier-1.md`](./docs/results/2026-04-24-frontier-1.md).

## Is this post-quantum safe?

Not in the strongest marketing sense. The right claim is narrower:

- The target is to make spending security depend on hash-based assumptions rather than on the hardness of secp256k1 discrete logs.
- That makes the construction resistant to Shor-style attacks on ECDSA.
- It is still limited by the hash functions Bitcoin exposes today and by Grover-style quadratic speedups against hash search.
- It also depends on limited-use / one-shot assumptions and on awkward legacy Script behavior.

So the honest framing is:

"Shor-safe spending under current Bitcoin rules, with residual limits from Bitcoin’s existing hash surface and policy constraints."

## Repo layout

```text
checkcheck/
  README.md
  docs/
    background-hash-functions.md
    mvp.md
    results/
      2026-04-24-frontier-0.md
      2026-04-24-frontier-1.md
  specs/
    compiler.md
  third_party/
    README.md
  tools/
    frontier_model.py
```

## References

- Avihu Mordechai Levy, StarkWare: [Quantum-Safe Bitcoin Transactions Without Softforks](https://starkware.co/blog/quantum-safe-bitcoin-transactions-without-softforks/)
- Upstream implementation: [avihu28/Quantum-Safe-Bitcoin-Transactions](https://github.com/avihu28/Quantum-Safe-Bitcoin-Transactions)
- Robin Linus: [Binohash](https://robinlinus.com/binohash.pdf)
- NIST: [FIPS 205, Stateless Hash-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/205/final)
- NIST: [SP 800-230 IPD, Additional SLH-DSA Parameter Sets for Limited Signature Use Cases](https://csrc.nist.gov/pubs/sp/800/230/ipd)
