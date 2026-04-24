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

## Current result

The current decision gate is in [`docs/results/2026-04-24-frontier-20.md`](./docs/results/2026-04-24-frontier-20.md).

In short:

- `frontier-16` showed that the best numeric partial-polyglot family is **asymmetric**, not symmetric
- the first Config-A-beating model point drops from `192` trusted polyglot elements to `143`
- the first baseline-collision model crossing drops from `224` to `200`
- `frontier-17` adds a stack-feasibility gate and returns **NO-GO** for further economics tuning
- `frontier-18` adds a conservative stack-correct polyglot round skeleton and shows that version is too expensive
- `frontier-19` finds a cheaper `OP_ROLL + OP_DUP` selection gadget that avoids `OP_PICK + OP_ROLL`
- the old `143` trusted-element result survives under emitted stack-correct accounting
- the first stack-correct baseline-collision crossing appears at `198` trusted elements, with the stronger practical point at `224`
- `frontier-20` validates pinning + round 1 + round 2 as one symbolic script and shows those three points still fit the byte/opcode envelope
- `frontier-20` also makes the honest limitation explicit: the construction leaves stack residue, so it is a non-standard / miner-direct path, not a cleanstack standard-relay claim

That shifts the repo:

from

"keep tuning the asymmetric polyglot curve"

to

"run the full script through an external Bitcoin Script interpreter with explicit consensus-vs-standardness flags."

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
      2026-04-24-frontier-2.md
      2026-04-24-frontier-3.md
      2026-04-24-frontier-4.md
      2026-04-24-frontier-5.md
      2026-04-24-frontier-6.md
      2026-04-24-frontier-7.md
      2026-04-24-frontier-8.md
      2026-04-24-frontier-9.md
      2026-04-24-frontier-10.md
      2026-04-24-frontier-11.md
      2026-04-24-frontier-12.md
      2026-04-24-frontier-13.md
      2026-04-24-frontier-14.md
      2026-04-24-frontier-15.md
      2026-04-24-frontier-16.md
      2026-04-24-frontier-17.md
      2026-04-24-frontier-18.md
      2026-04-24-frontier-19.md
      2026-04-24-frontier-20.md
  specs/
    compiler.md
  third_party/
    README.md
  tools/
    stack_correct_polyglot_frontier.py
    qsb_stack_sanity.py
    polyglot_setup_frontier.py
    polyglot_frontier.py
    der_triple_anchor_frontier.py
    der_double_anchor_frontier.py
    der_conflict_lift_frontier.py
    fad_conflict_collapse_frontier.py
    fad_cascade_frontier.py
    fad_mechanism_frontier.py
    der_higher_order_frontier.py
    der_overlap_threshold_frontier.py
    der_surface_frontier.py
    fad_overlap_search.py
    frontier_model.py
```

## References

- Avihu Mordechai Levy, StarkWare: [Quantum-Safe Bitcoin Transactions Without Softforks](https://starkware.co/blog/quantum-safe-bitcoin-transactions-without-softforks/)
- Upstream implementation: [avihu28/Quantum-Safe-Bitcoin-Transactions](https://github.com/avihu28/Quantum-Safe-Bitcoin-Transactions)
- Robin Linus: [Binohash](https://robinlinus.com/binohash.pdf)
- NIST: [FIPS 205, Stateless Hash-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/205/final)
- NIST: [SP 800-230 IPD, Additional SLH-DSA Parameter Sets for Limited Signature Use Cases](https://csrc.nist.gov/pubs/sp/800/230/ipd)
