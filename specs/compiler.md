# Compiler Spec

## Purpose

The compiler turns a candidate digest construction into a Bitcoin-specific resource estimate.

It does not need to emit a spendable transaction in v0. It needs to answer whether a construction is plausible under the current consensus envelope.

## Inputs

- `limits`
  - `max_non_push_opcodes`
  - `max_script_bytes`
  - `hash_surface`
- `construction`
  - `family`
  - `rounds`
  - `selection_parameters`
  - `commitment_shape`
  - `opening_shape`
- `cost_model`
  - bytes per commitment
  - bytes per opening
  - non-push opcodes per verification step
  - search target in bits

## Outputs

- fits or does not fit
- estimated script bytes
- estimated non-push opcodes
- raw choice entropy bits
- adjusted digest / security bits after calibration
- honest-work estimate
- notes about tuning slack and suspected hidden costs

## Required backends for v0

### 1. HORS-like baseline

Purpose:

- represent the public QSB baseline faithfully enough for comparison

Characteristics:

- combinatorial subset-based digest
- flat opening verification
- tuned to match the `~2^46` puzzle target

### 2. Grouped-choice codebook

Purpose:

- test whether limited-use codebooks can increase digest efficiency without tree overhead

Characteristics:

- each group contributes one local choice
- total digest bits is the sum of per-group choice entropy
- verification remains flat and local

## Explicit non-goals for v0

- no wallet integration
- no on-chain broadcaster
- no miner policy integration
- no GPU implementation
- no end-to-end transaction assembly
