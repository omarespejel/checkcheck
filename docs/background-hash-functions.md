# Modern hash functions and why they matter here

This repo is not trying to argue that Bitcoin can suddenly use modern hash functions on chain.

It cannot.

Bitcoin Script today gives us only the existing Bitcoin hash surface:

- `SHA256`
- `HASH256`
- `RIPEMD160`
- `HASH160`

That constraint is the most important fact for this project.

## SHA-3 / SHAKE

NIST standardized SHA-3 and SHAKE in [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final). SHAKE-style XOFs matter because they make domain separation and flexible output sizing much cleaner than old fixed-length hash interfaces.

Takeaway for this repo:

- good off-chain design reference
- not directly available in Bitcoin Script

## SLH-DSA and limited-use variants

NIST standardized SLH-DSA in [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final). Then, on April 13, 2026, NIST published draft [SP 800-230](https://csrc.nist.gov/pubs/sp/800/230/ipd), which adds limited-signature parameter sets with smaller signatures and faster verification under a strict signature cap.

This is the most relevant recent standards signal for the repo.

Takeaway for this repo:

- the "limited-use is acceptable when carefully bounded" idea is directly relevant to Bitcoin UTXOs
- the exact SLH-DSA / FORS tree machinery is probably not the right on-chain realization for Bitcoin legacy Script

## KangarooTwelve

[KangarooTwelve](https://keccak.team/kangarootwelve.html) is a fast tree hash built on Keccak-p. It is useful as a reminder that modern hash design is comfortable with tree modes, XOF interfaces, and parallelism.

Takeaway for this repo:

- useful conceptual reference for off-chain search and transcript handling
- not directly available in Bitcoin Script

## BLAKE3

[BLAKE3](https://github.com/BLAKE3-team/BLAKE3) is fast, parallel, and tree-based. It is a strong off-chain engineering primitive for modeling, transcript hashing, or search infrastructure.

Takeaway for this repo:

- good off-chain systems primitive
- not a viable no-softfork on-chain primitive for Bitcoin

## Ascon hash / XOF

NIST finalized [SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/ipd) in 2025 for Ascon-based lightweight cryptography, including Ascon-Hash256 and Ascon-XOF variants.

Takeaway for this repo:

- another sign that modern hash research emphasizes flexible permutation-based designs
- still not directly usable inside Bitcoin Script

## Bottom line

Modern hash research matters here in two ways:

1. It reinforces that limited-use hash-based designs are acceptable engineering tradeoffs in the right setting.
2. It points us toward better off-chain digest construction and compiler design.

It does not let us avoid the core Bitcoin constraint:

"The on-chain verifier can only use the hash opcodes Bitcoin already has."

