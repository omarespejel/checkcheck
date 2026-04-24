#!/usr/bin/env python3
"""
Probe the first longer DER surfaces where explicit pushed-token overlaps exist.

This follows frontier-6. The question is no longer whether short DER below
length 13 is exhausted. The question is whether the first overlap-bearing exact
DER surfaces actually create new FindAndDelete states, or merely allow overlaps
that remain subset-like in practice.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations, permutations
from math import comb
from pathlib import Path
import random
import sys


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
UPSTREAM_PIPELINE = ROOT / "third_party" / "qsb-avihu" / "pipeline"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
if str(UPSTREAM_PIPELINE) not in sys.path:
    sys.path.insert(0, str(UPSTREAM_PIPELINE))

from der_surface_frontier import analyze_family  # type: ignore
from secp256k1 import P, encode_der_sig  # type: ignore


@dataclass(frozen=True)
class RandomProbe:
    payload_len: int
    family_size: int
    selection_size: int
    trials: int
    best_unique_ordered_outcomes: int
    best_max_results_per_unordered_subset: int
    best_family: tuple[str, ...]
    best_script_order: tuple[str, ...]


@dataclass(frozen=True)
class ExplicitPoolProbe:
    name: str
    pool_size: int
    family_size: int
    selection_size: int
    max_pairwise_overlap: int
    overlap_a: str | None
    overlap_b: str | None
    best_unique_ordered_outcomes: int
    best_max_results_per_unordered_subset: int
    best_family: tuple[str, ...]
    best_script_order: tuple[str, ...]


def is_valid_x(x: int) -> bool:
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    return pow(y, 2, P) == y_sq


def random_exact_len_int(nbytes: int, rng: random.Random, is_r: bool) -> int:
    lower = 1 if nbytes == 1 else 1 << (8 * (nbytes - 1))
    upper = (1 << (8 * nbytes - 1)) - 1
    while True:
        candidate = rng.randint(lower, upper)
        if not is_r or is_valid_x(candidate):
            return candidate


def exact_len_cases(payload_len: int) -> tuple[tuple[int, int], ...]:
    cases = []
    for r_len in range(1, 9):
        for s_len in range(1, 9):
            if 7 + r_len + s_len == payload_len:
                cases.append((r_len, s_len))
    return tuple(cases)


def sample_exact_payload_sig(payload_len: int, rng: random.Random) -> bytes:
    r_len, s_len = rng.choice(exact_len_cases(payload_len))
    r = random_exact_len_int(r_len, rng, is_r=True)
    s = random_exact_len_int(s_len, rng, is_r=False)
    sig = encode_der_sig(r, s, sighash=0x03)
    if len(sig) != payload_len:
        raise AssertionError(f"expected payload length {payload_len}, got {len(sig)}")
    return sig


def random_probe(
    payload_len: int,
    family_size: int,
    selection_size: int,
    trials: int,
    seed: int,
) -> RandomProbe:
    rng = random.Random(seed + payload_len * 100 + family_size * 10 + selection_size)
    best_score: tuple[int, int] | None = None
    best_family: tuple[bytes, ...] | None = None
    best_order: tuple[bytes, ...] | None = None
    for _ in range(trials):
        family = set()
        while len(family) < family_size:
            family.add(sample_exact_payload_sig(payload_len, rng))
        order = list(family)
        rng.shuffle(order)
        score = analyze_family(tuple(order), selection_size=selection_size)
        score_tuple = (
            score.unique_ordered_outcomes,
            score.max_results_per_unordered_subset,
        )
        if best_score is not None and score_tuple <= best_score:
            continue
        best_score = score_tuple
        best_family = tuple(sorted(family))
        best_order = tuple(order)
    if best_score is None or best_family is None or best_order is None:
        raise RuntimeError("random probe found no result")
    return RandomProbe(
        payload_len=payload_len,
        family_size=family_size,
        selection_size=selection_size,
        trials=trials,
        best_unique_ordered_outcomes=best_score[0],
        best_max_results_per_unordered_subset=best_score[1],
        best_family=tuple(token.hex() for token in best_family),
        best_script_order=tuple(token.hex() for token in best_order),
    )


def pushed_overlap_stats(tokens: tuple[bytes, ...]) -> tuple[int, str | None, str | None]:
    pushed = tuple(bytes([len(token)]) + token for token in tokens)
    max_overlap = 0
    overlap_a = None
    overlap_b = None
    for i, token_a in enumerate(pushed):
        for j, token_b in enumerate(pushed):
            if i == j:
                continue
            for overlap_len in range(1, min(len(token_a), len(token_b))):
                if token_a[-overlap_len:] != token_b[:overlap_len]:
                    continue
                if overlap_len > max_overlap:
                    max_overlap = overlap_len
                    overlap_a = token_a.hex()
                    overlap_b = token_b.hex()
    return max_overlap, overlap_a, overlap_b


def explicit_pool_probe(
    name: str,
    pool: tuple[bytes, ...],
    family_size: int,
    selection_size: int,
) -> ExplicitPoolProbe:
    max_overlap, overlap_a, overlap_b = pushed_overlap_stats(pool)
    best_score: tuple[int, int] | None = None
    best_family: tuple[bytes, ...] | None = None
    best_order: tuple[bytes, ...] | None = None
    for family in combinations(pool, family_size):
        for order in permutations(family):
            score = analyze_family(tuple(order), selection_size=selection_size)
            score_tuple = (
                score.unique_ordered_outcomes,
                score.max_results_per_unordered_subset,
            )
            if best_score is not None and score_tuple <= best_score:
                continue
            best_score = score_tuple
            best_family = tuple(sorted(family))
            best_order = tuple(order)
    if best_score is None or best_family is None or best_order is None:
        raise RuntimeError(f"explicit pool probe found no result for {name}")
    return ExplicitPoolProbe(
        name=name,
        pool_size=len(pool),
        family_size=family_size,
        selection_size=selection_size,
        max_pairwise_overlap=max_overlap,
        overlap_a=overlap_a,
        overlap_b=overlap_b,
        best_unique_ordered_outcomes=best_score[0],
        best_max_results_per_unordered_subset=best_score[1],
        best_family=tuple(token.hex() for token in best_family),
        best_script_order=tuple(token.hex() for token in best_order),
    )


def build_exact13_overlap_pool() -> tuple[bytes, ...]:
    # These exact-13 signatures explicitly embed the full pushed-token prefix
    # 0d300a0201 inside the 5-byte s field, which creates real pushed-token
    # overlaps between distinct family members.
    return tuple(
        encode_der_sig(r, s, sighash=0x03)
        for r, s in zip(
            range(1, 7),
            [
                0x0D300A0201,
                0x0D300A0202,
                0x0D300A0203,
                0x0D300A0204,
                0x0D300A0205,
                0x0D300A0206,
            ],
        )
    )


def print_random_probe(probe: RandomProbe) -> None:
    print(
        f"# exact_payload_len_{probe.payload_len}_m{probe.family_size}_t{probe.selection_size}_random"
    )
    print(f"trials: {probe.trials}")
    print(f"unordered_subset_baseline: {comb(probe.family_size, probe.selection_size)}")
    print(f"best_unique_ordered_outcomes: {probe.best_unique_ordered_outcomes}")
    print(
        "best_max_results_per_unordered_subset:"
        f" {probe.best_max_results_per_unordered_subset}"
    )
    print(f"best_family: {list(probe.best_family)}")
    print(f"best_script_order: {list(probe.best_script_order)}")


def print_pool_probe(probe: ExplicitPoolProbe) -> None:
    print(f"# {probe.name}")
    print(f"pool_size: {probe.pool_size}")
    print(f"family_size: {probe.family_size}")
    print(f"selection_size: {probe.selection_size}")
    print(f"unordered_subset_baseline: {comb(probe.family_size, probe.selection_size)}")
    print(f"max_pairwise_overlap: {probe.max_pairwise_overlap}")
    if probe.overlap_a is not None and probe.overlap_b is not None:
        print(f"overlap_a: {probe.overlap_a}")
        print(f"overlap_b: {probe.overlap_b}")
    print(f"best_unique_ordered_outcomes: {probe.best_unique_ordered_outcomes}")
    print(
        "best_max_results_per_unordered_subset:"
        f" {probe.best_max_results_per_unordered_subset}"
    )
    print(f"best_family: {list(probe.best_family)}")
    print(f"best_script_order: {list(probe.best_script_order)}")


def main() -> None:
    random_probes = [
        random_probe(payload_len=13, family_size=4, selection_size=2, trials=5_000, seed=20_260_424),
        random_probe(payload_len=14, family_size=4, selection_size=2, trials=5_000, seed=20_260_424),
        random_probe(payload_len=15, family_size=4, selection_size=2, trials=4_000, seed=20_260_424),
        random_probe(payload_len=16, family_size=4, selection_size=2, trials=3_000, seed=20_260_424),
        random_probe(payload_len=17, family_size=4, selection_size=2, trials=2_500, seed=20_260_424),
        random_probe(payload_len=18, family_size=4, selection_size=2, trials=2_000, seed=20_260_424),
        random_probe(payload_len=13, family_size=5, selection_size=3, trials=3_000, seed=20_260_424),
        random_probe(payload_len=13, family_size=6, selection_size=3, trials=2_000, seed=20_260_424),
    ]
    for probe in random_probes:
        print()
        print_random_probe(probe)

    for probe in [
        explicit_pool_probe(
            name="exact13_overlap_pool_m4_t2",
            pool=build_exact13_overlap_pool(),
            family_size=4,
            selection_size=2,
        ),
        explicit_pool_probe(
            name="exact13_overlap_pool_m5_t3",
            pool=build_exact13_overlap_pool(),
            family_size=5,
            selection_size=3,
        ),
    ]:
        print()
        print_pool_probe(probe)


if __name__ == "__main__":
    main()
