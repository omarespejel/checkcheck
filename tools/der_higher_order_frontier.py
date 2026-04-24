#!/usr/bin/env python3
"""
Probe higher-order overlap behavior on short DER-valid signature surfaces.

This follows frontier-5. The question is no longer whether short non-minimal
DER wakes up under ordered 2-of-4 deletion. The question is whether it only
becomes expressive once we raise family size and deletion order.
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

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from der_surface_frontier import (  # type: ignore
    analyze_family,
    build_len11_motif_pool,
    build_len12_motif_pool,
    exact_r_pools,
    sample_exact_payload_sig,
)


@dataclass(frozen=True)
class HigherOrderRandomProbe:
    payload_len: int
    family_size: int
    selection_size: int
    trials: int
    best_unique_ordered_outcomes: int
    best_max_results_per_unordered_subset: int
    best_family: tuple[str, ...]
    best_script_order: tuple[str, ...]


@dataclass(frozen=True)
class HigherOrderPoolProbe:
    name: str
    pool_size: int
    family_size: int
    selection_size: int
    best_unique_ordered_outcomes: int
    best_max_results_per_unordered_subset: int
    best_family: tuple[str, ...]
    best_script_order: tuple[str, ...]


def random_higher_order_probe(
    payload_len: int,
    family_size: int,
    selection_size: int,
    trials: int,
    seed: int,
    r_len1: tuple[int, ...],
    r_len2: tuple[int, ...],
) -> HigherOrderRandomProbe:
    rng = random.Random(seed + payload_len * 100 + family_size * 10 + selection_size)
    best_score: tuple[int, int] | None = None
    best_family: tuple[bytes, ...] | None = None
    best_order: tuple[bytes, ...] | None = None
    for _ in range(trials):
        family = set()
        while len(family) < family_size:
            family.add(sample_exact_payload_sig(payload_len, rng, r_len1, r_len2))
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
        raise RuntimeError("higher-order random probe found no result")
    return HigherOrderRandomProbe(
        payload_len=payload_len,
        family_size=family_size,
        selection_size=selection_size,
        trials=trials,
        best_unique_ordered_outcomes=best_score[0],
        best_max_results_per_unordered_subset=best_score[1],
        best_family=tuple(token.hex() for token in best_family),
        best_script_order=tuple(token.hex() for token in best_order),
    )


def pool_higher_order_probe(
    name: str,
    pool: tuple[bytes, ...],
    family_size: int,
    selection_size: int,
) -> HigherOrderPoolProbe:
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
        raise RuntimeError(f"higher-order pool probe found no result for {name}")
    return HigherOrderPoolProbe(
        name=name,
        pool_size=len(pool),
        family_size=family_size,
        selection_size=selection_size,
        best_unique_ordered_outcomes=best_score[0],
        best_max_results_per_unordered_subset=best_score[1],
        best_family=tuple(token.hex() for token in best_family),
        best_script_order=tuple(token.hex() for token in best_order),
    )


def print_random_probe(probe: HigherOrderRandomProbe) -> None:
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


def print_pool_probe(probe: HigherOrderPoolProbe) -> None:
    print(f"# {probe.name}")
    print(f"pool_size: {probe.pool_size}")
    print(f"family_size: {probe.family_size}")
    print(f"selection_size: {probe.selection_size}")
    print(f"unordered_subset_baseline: {comb(probe.family_size, probe.selection_size)}")
    print(f"best_unique_ordered_outcomes: {probe.best_unique_ordered_outcomes}")
    print(
        "best_max_results_per_unordered_subset:"
        f" {probe.best_max_results_per_unordered_subset}"
    )
    print(f"best_family: {list(probe.best_family)}")
    print(f"best_script_order: {list(probe.best_script_order)}")


def main() -> None:
    r_len1, r_len2 = exact_r_pools()
    print("# higher-order-der-r-pools")
    print(f"recoverable_r_len1: {len(r_len1)}")
    print(f"recoverable_r_len2: {len(r_len2)}")

    random_probes = [
        random_higher_order_probe(
            payload_len=11,
            family_size=5,
            selection_size=3,
            trials=3_000,
            seed=20_260_424,
            r_len1=r_len1,
            r_len2=r_len2,
        ),
        random_higher_order_probe(
            payload_len=12,
            family_size=5,
            selection_size=3,
            trials=3_000,
            seed=20_260_424,
            r_len1=r_len1,
            r_len2=r_len2,
        ),
        random_higher_order_probe(
            payload_len=11,
            family_size=6,
            selection_size=3,
            trials=2_000,
            seed=20_260_424,
            r_len1=r_len1,
            r_len2=r_len2,
        ),
        random_higher_order_probe(
            payload_len=12,
            family_size=6,
            selection_size=3,
            trials=2_000,
            seed=20_260_424,
            r_len1=r_len1,
            r_len2=r_len2,
        ),
    ]
    for probe in random_probes:
        print()
        print_random_probe(probe)

    pool_probes = [
        pool_higher_order_probe(
            name="len11_motif_pool_m5_t3",
            pool=build_len11_motif_pool(),
            family_size=5,
            selection_size=3,
        ),
        pool_higher_order_probe(
            name="len12_motif_pool_m5_t3",
            pool=build_len12_motif_pool(),
            family_size=5,
            selection_size=3,
        ),
    ]
    for probe in pool_probes:
        print()
        print_pool_probe(probe)


if __name__ == "__main__":
    main()
