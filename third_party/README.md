# Third-party code

This directory is reserved for pinned baselines and imported references.

Planned imports:

- `qsb-avihu/`
  - upstream baseline implementation from `avihu28/Quantum-Safe-Bitcoin-Transactions`
  - imported only as a baseline and reference point
  - kept isolated to preserve architecture and licensing boundaries
  - pinned snapshot currently corresponds to commit `861960e4f67d19ddeadb68cc9359a3257f461dde`

Notes:

- The public QSB repo currently states that it mixes MIT-licensed code with GPL-covered GPU components derived from CudaBrainSecp.
- Keep imported baselines isolated from original code in this repo until the intended reuse boundary is explicit.
