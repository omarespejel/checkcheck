#!/usr/bin/env python3
"""
Probe short non-minimal DER surfaces as selectable QSB token families.

This tool focuses on the next question after frontier-4:

1. If minimal 9-byte DER is structurally overlap-free, do slightly longer but
   still DER-valid signature-shaped blobs open a useful new surface?
2. If so, how much byte budget do those longer blobs cost under the current
   QSB-like static script budget?
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations, permutations
from math import floor, lgamma, log
from pathlib import Path
import random
import sys


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_PIPELINE = ROOT / "third_party" / "qsb-avihu" / "pipeline"

if str(UPSTREAM_PIPELINE) not in sys.path:
    sys.path.insert(0, str(UPSTREAM_PIPELINE))

from bitcoin_tx import push_data  # type: ignore
from secp256k1 import P, encode_der_sig  # type: ignore


BASELINE_N = 150
BASELINE_PAYLOAD_LEN = 9
COMMITMENT_PUSH_BYTES = 21
BASELINE_PER_CHOICE_STATIC_BYTES = COMMITMENT_PUSH_BYTES + 1 + BASELINE_PAYLOAD_LEN
STATIC_CHOICE_BUDGET = BASELINE_N * BASELINE_PER_CHOICE_STATIC_BYTES * 2


@dataclass(frozen=True)
class FamilyScore:
    unique_ordered_outcomes: int
    max_results_per_unordered_subset: int


@dataclass(frozen=True)
class RandomProbeResult:
    payload_len: int
    trials: int
    best_score: FamilyScore
    best_family: tuple[str, ...]
    best_script_order: tuple[str, ...]


@dataclass(frozen=True)
class MotifPoolResult:
    name: str
    pool_size: int
    best_score: FamilyScore
    best_family: tuple[str, ...]
    best_script_order: tuple[str, ...]


@dataclass(frozen=True)
class RepricingRow:
    payload_len: int
    per_choice_static_bytes: int
    max_n_under_budget: int
    signed_bits_8_8: float
    signed_gap_vs_baseline_8_8: float


def log2_binom(n: int, k: int) -> float:
    return (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)) / log(2)


def signed_bits_8_8(n: int) -> float:
    return 2 * log2_binom(n, 8)


def is_valid_x(x: int) -> bool:
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    return pow(y, 2, P) == y_sq


def find_and_delete_pattern(script: bytes, pattern: bytes) -> bytes:
    result = bytearray()
    plen = len(pattern)
    i = 0
    while i <= len(script) - plen:
        if script[i : i + plen] == pattern:
            i += plen
        else:
            result.append(script[i])
            i += 1
    result.extend(script[i:])
    return bytes(result)


def analyze_family(tokens_in_script_order: tuple[bytes, ...], selection_size: int = 2) -> FamilyScore:
    patterns = tuple(push_data(token) for token in tokens_in_script_order)
    script = b"".join(patterns)
    outcomes = set()
    subset_to_outcomes: dict[frozenset[int], set[bytes]] = {}
    for selection in permutations(range(len(patterns)), selection_size):
        cur = script
        for idx in selection:
            cur = find_and_delete_pattern(cur, patterns[idx])
        outcomes.add(cur)
        subset_to_outcomes.setdefault(frozenset(selection), set()).add(cur)
    return FamilyScore(
        unique_ordered_outcomes=len(outcomes),
        max_results_per_unordered_subset=max(len(v) for v in subset_to_outcomes.values()),
    )


def exact_r_pools() -> tuple[tuple[int, ...], tuple[int, ...]]:
    r_len1 = tuple(x for x in range(1, 128) if is_valid_x(x))
    r_len2 = tuple(x for x in range(128, 32768) if is_valid_x(x))
    return r_len1, r_len2


def sample_r_of_exact_len(target_len: int, rng: random.Random, r_len1: tuple[int, ...], r_len2: tuple[int, ...]) -> int:
    if target_len == 1:
        return rng.choice(r_len1)
    if target_len == 2:
        return rng.choice(r_len2)
    if target_len == 3:
        while True:
            candidate = rng.randint(32768, 8_388_607)
            if is_valid_x(candidate):
                return candidate
    if target_len == 4:
        while True:
            candidate = rng.randint(8_388_608, 2_147_483_647)
            if is_valid_x(candidate):
                return candidate
    raise ValueError(f"unsupported exact r length: {target_len}")


def sample_s_of_exact_len(target_len: int, rng: random.Random) -> int:
    if target_len == 1:
        return rng.randint(1, 127)
    if target_len == 2:
        return rng.randint(128, 32767)
    if target_len == 3:
        return rng.randint(32768, 8_388_607)
    if target_len == 4:
        return rng.randint(8_388_608, 2_147_483_647)
    raise ValueError(f"unsupported exact s length: {target_len}")


def exact_len_cases(payload_len: int) -> tuple[tuple[int, int], ...]:
    cases = []
    for r_len in range(1, 5):
        for s_len in range(1, 5):
            if 7 + r_len + s_len == payload_len:
                cases.append((r_len, s_len))
    return tuple(cases)


def sample_exact_payload_sig(
    payload_len: int,
    rng: random.Random,
    r_len1: tuple[int, ...],
    r_len2: tuple[int, ...],
) -> bytes:
    r_len, s_len = rng.choice(exact_len_cases(payload_len))
    r = sample_r_of_exact_len(r_len, rng, r_len1, r_len2)
    s = sample_s_of_exact_len(s_len, rng)
    sig = encode_der_sig(r, s, sighash=0x03)
    if len(sig) != payload_len:
        raise AssertionError(f"expected payload length {payload_len}, got {len(sig)}")
    return sig


def random_exact_len_probe(
    payload_len: int,
    trials: int,
    seed: int,
    r_len1: tuple[int, ...],
    r_len2: tuple[int, ...],
) -> RandomProbeResult:
    rng = random.Random(seed + payload_len)
    best_score: FamilyScore | None = None
    best_family: tuple[bytes, ...] | None = None
    best_order: tuple[bytes, ...] | None = None
    for _ in range(trials):
        family = set()
        while len(family) < 4:
            family.add(sample_exact_payload_sig(payload_len, rng, r_len1, r_len2))
        order = list(family)
        rng.shuffle(order)
        score = analyze_family(tuple(order))
        if best_score is not None and (
            score.unique_ordered_outcomes,
            score.max_results_per_unordered_subset,
        ) <= (
            best_score.unique_ordered_outcomes,
            best_score.max_results_per_unordered_subset,
        ):
            continue
        best_score = score
        best_family = tuple(sorted(family))
        best_order = tuple(order)
    if best_score is None or best_family is None or best_order is None:
        raise RuntimeError(f"no random result for payload_len={payload_len}")
    return RandomProbeResult(
        payload_len=payload_len,
        trials=trials,
        best_score=best_score,
        best_family=tuple(token.hex() for token in best_family),
        best_script_order=tuple(token.hex() for token in best_order),
    )


def motif_pool_probe(name: str, pool: tuple[bytes, ...]) -> MotifPoolResult:
    best_score: FamilyScore | None = None
    best_family: tuple[bytes, ...] | None = None
    best_order: tuple[bytes, ...] | None = None
    for family in combinations(pool, 4):
        for order in permutations(family):
            score = analyze_family(tuple(order))
            if best_score is not None and (
                score.unique_ordered_outcomes,
                score.max_results_per_unordered_subset,
            ) <= (
                best_score.unique_ordered_outcomes,
                best_score.max_results_per_unordered_subset,
            ):
                continue
            best_score = score
            best_family = tuple(sorted(family))
            best_order = tuple(order)
    if best_score is None or best_family is None or best_order is None:
        raise RuntimeError(f"no motif result for {name}")
    return MotifPoolResult(
        name=name,
        pool_size=len(pool),
        best_score=best_score,
        best_family=tuple(token.hex() for token in best_family),
        best_script_order=tuple(token.hex() for token in best_order),
    )


def repricing_rows() -> tuple[RepricingRow, ...]:
    baseline_bits = signed_bits_8_8(BASELINE_N)
    rows = []
    for payload_len in [9, 10, 11, 12, 13]:
        per_choice_static_bytes = COMMITMENT_PUSH_BYTES + 1 + payload_len
        max_n = floor(STATIC_CHOICE_BUDGET / (2 * per_choice_static_bytes))
        bits = signed_bits_8_8(max_n)
        rows.append(
            RepricingRow(
                payload_len=payload_len,
                per_choice_static_bytes=per_choice_static_bytes,
                max_n_under_budget=max_n,
                signed_bits_8_8=bits,
                signed_gap_vs_baseline_8_8=baseline_bits - bits,
            )
        )
    return tuple(rows)


def build_len11_motif_pool() -> tuple[bytes, ...]:
    return tuple(
        encode_der_sig(1, s_value, sighash=0x03)
        for s_value in [
            0x0B3008,
            0x0B3009,
            0x0B300A,
            0x0B300B,
            0x30080B,
            0x30090B,
            0x080B30,
            0x090B30,
        ]
    )


def build_len12_motif_pool() -> tuple[bytes, ...]:
    return tuple(
        encode_der_sig(1, s_value, sighash=0x03)
        for s_value in [
            0x0C300902,
            0x0C300903,
            0x3009020C,
            0x3009030C,
            0x020C3009,
            0x030C3009,
            0x09020C30,
            0x09030C30,
        ]
    )


def main() -> None:
    r_len1, r_len2 = exact_r_pools()
    print("# exact-der-r-pools")
    print(f"recoverable_r_len1: {len(r_len1)}")
    print(f"recoverable_r_len2: {len(r_len2)}")

    for probe in [
        random_exact_len_probe(payload_len=10, trials=10_000, seed=20_260_424, r_len1=r_len1, r_len2=r_len2),
        random_exact_len_probe(payload_len=11, trials=10_000, seed=20_260_424, r_len1=r_len1, r_len2=r_len2),
        random_exact_len_probe(payload_len=12, trials=10_000, seed=20_260_424, r_len1=r_len1, r_len2=r_len2),
    ]:
        print()
        print(f"# exact_payload_len_{probe.payload_len}_random")
        print(f"trials: {probe.trials}")
        print(f"best_unique_ordered_outcomes: {probe.best_score.unique_ordered_outcomes}")
        print("unordered_subset_baseline: 6")
        print(f"best_max_results_per_unordered_subset: {probe.best_score.max_results_per_unordered_subset}")
        print(f"best_family: {list(probe.best_family)}")
        print(f"best_script_order: {list(probe.best_script_order)}")

    for probe in [
        motif_pool_probe("len11_motif_pool", build_len11_motif_pool()),
        motif_pool_probe("len12_motif_pool", build_len12_motif_pool()),
    ]:
        print()
        print(f"# {probe.name}")
        print(f"pool_size: {probe.pool_size}")
        print(f"best_unique_ordered_outcomes: {probe.best_score.unique_ordered_outcomes}")
        print("unordered_subset_baseline: 6")
        print(f"best_max_results_per_unordered_subset: {probe.best_score.max_results_per_unordered_subset}")
        print(f"best_family: {list(probe.best_family)}")
        print(f"best_script_order: {list(probe.best_script_order)}")

    print()
    print("# repricing")
    baseline_bits = signed_bits_8_8(BASELINE_N)
    print(f"baseline_n: {BASELINE_N}")
    print(f"baseline_signed_bits_8_8: {baseline_bits:.2f}")
    print(f"static_choice_budget: {STATIC_CHOICE_BUDGET}")
    for row in repricing_rows():
        print(
            "row:",
            f"payload_len={row.payload_len}",
            f"per_choice_static_bytes={row.per_choice_static_bytes}",
            f"max_n_under_budget={row.max_n_under_budget}",
            f"signed_bits_8_8={row.signed_bits_8_8:.2f}",
            f"signed_gap_vs_baseline_8_8={row.signed_gap_vs_baseline_8_8:.2f}",
        )


if __name__ == "__main__":
    main()
