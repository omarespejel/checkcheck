#!/usr/bin/env python3
"""
Probe the conflict-free collapse conjecture under wider FindAndDelete search.

This follows frontier-9. Conflict looked like the better invariant than
cascade, but that still left the stronger question open:

Can a conflict-free family ever beat the plain subset baseline in the searched
regimes, or does every expressive family need real destructive conflict?
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations, permutations, product
from math import comb
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from der_overlap_threshold_frontier import build_exact13_overlap_pool  # type: ignore
from der_surface_frontier import FamilyScore, analyze_family  # type: ignore
from fad_mechanism_frontier import conflict_witness_for_order  # type: ignore


@dataclass(frozen=True)
class ExhaustiveConflictBoundaryResult:
    name: str
    payload_count: int
    family_size: int
    selection_size: int
    unordered_subset_baseline: int
    total_orders: int
    expressive_orders: int
    expressive_without_conflict: int
    representative_conflict_free_expressive_order: tuple[str, ...] | None


@dataclass(frozen=True)
class ExplicitPoolBaselineResult:
    name: str
    pool_size: int
    family_size: int
    selection_size: int
    unordered_subset_baseline: int
    total_orders: int
    expressive_orders: int
    best_score: FamilyScore
    best_family: tuple[str, ...]
    best_order: tuple[str, ...]


def score_tuple(score: FamilyScore) -> tuple[int, int]:
    return (score.unique_ordered_outcomes, score.max_results_per_unordered_subset)


def payload_pool(alphabet: tuple[int, ...], lengths: tuple[int, ...]) -> tuple[bytes, ...]:
    payloads: list[bytes] = []
    for length in lengths:
        payloads.extend(bytes(tup) for tup in product(alphabet, repeat=length))
    return tuple(payloads)


def is_expressive(
    score: FamilyScore,
    unordered_subset_baseline: int,
) -> bool:
    return (
        score.unique_ordered_outcomes > unordered_subset_baseline
        or score.max_results_per_unordered_subset > 1
    )


def exhaustive_conflict_boundary_case(
    name: str,
    alphabet: tuple[int, ...],
    lengths: tuple[int, ...],
    family_size: int = 4,
    selection_size: int = 2,
) -> ExhaustiveConflictBoundaryResult:
    payloads = payload_pool(alphabet, lengths)
    baseline = comb(family_size, selection_size)
    total_orders = 0
    expressive_orders = 0
    expressive_without_conflict = 0
    representative_conflict_free_expressive_order = None

    for order in permutations(payloads, family_size):
        total_orders += 1
        score = analyze_family(order, selection_size=selection_size)
        if not is_expressive(score, baseline):
            continue
        expressive_orders += 1
        if conflict_witness_for_order(order, selection_size=selection_size) is not None:
            continue
        expressive_without_conflict += 1
        if representative_conflict_free_expressive_order is None:
            representative_conflict_free_expressive_order = tuple(
                token.hex() for token in order
            )

    return ExhaustiveConflictBoundaryResult(
        name=name,
        payload_count=len(payloads),
        family_size=family_size,
        selection_size=selection_size,
        unordered_subset_baseline=baseline,
        total_orders=total_orders,
        expressive_orders=expressive_orders,
        expressive_without_conflict=expressive_without_conflict,
        representative_conflict_free_expressive_order=(
            representative_conflict_free_expressive_order
        ),
    )


def explicit_pool_baseline_case(
    name: str,
    pool: tuple[bytes, ...],
    family_size: int,
    selection_size: int,
) -> ExplicitPoolBaselineResult:
    baseline = comb(family_size, selection_size)
    total_orders = 0
    expressive_orders = 0
    best_score: FamilyScore | None = None
    best_family: tuple[str, ...] | None = None
    best_order: tuple[str, ...] | None = None

    for family in combinations(pool, family_size):
        for order in permutations(family):
            total_orders += 1
            score = analyze_family(order, selection_size=selection_size)
            if is_expressive(score, baseline):
                expressive_orders += 1
            if best_score is not None and score_tuple(score) <= score_tuple(best_score):
                continue
            best_score = score
            best_family = tuple(token.hex() for token in family)
            best_order = tuple(token.hex() for token in order)

    if best_score is None or best_family is None or best_order is None:
        raise RuntimeError(f"no best score found for {name}")

    return ExplicitPoolBaselineResult(
        name=name,
        pool_size=len(pool),
        family_size=family_size,
        selection_size=selection_size,
        unordered_subset_baseline=baseline,
        total_orders=total_orders,
        expressive_orders=expressive_orders,
        best_score=best_score,
        best_family=best_family,
        best_order=best_order,
    )


def print_exhaustive(result: ExhaustiveConflictBoundaryResult) -> None:
    print(f"# {result.name}")
    print(f"payload_count: {result.payload_count}")
    print(f"family_size: {result.family_size}")
    print(f"selection_size: {result.selection_size}")
    print(f"unordered_subset_baseline: {result.unordered_subset_baseline}")
    print(f"total_orders: {result.total_orders}")
    print(f"expressive_orders: {result.expressive_orders}")
    print(f"expressive_without_conflict: {result.expressive_without_conflict}")
    if result.representative_conflict_free_expressive_order is not None:
        print(
            "representative_conflict_free_expressive_order:"
            f" {list(result.representative_conflict_free_expressive_order)}"
        )


def print_pool(result: ExplicitPoolBaselineResult) -> None:
    print(f"# {result.name}")
    print(f"pool_size: {result.pool_size}")
    print(f"family_size: {result.family_size}")
    print(f"selection_size: {result.selection_size}")
    print(f"unordered_subset_baseline: {result.unordered_subset_baseline}")
    print(f"total_orders: {result.total_orders}")
    print(f"expressive_orders: {result.expressive_orders}")
    print(f"best_unique_ordered_outcomes: {result.best_score.unique_ordered_outcomes}")
    print(
        "best_max_results_per_unordered_subset:"
        f" {result.best_score.max_results_per_unordered_subset}"
    )
    print(f"best_family: {list(result.best_family)}")
    print(f"best_order: {list(result.best_order)}")


def main() -> None:
    exhaustive_cases = [
        ("binary_len2_orders", (1, 2), (2,)),
        ("binary_len3_orders", (1, 2), (3,)),
        ("binary_len4_orders", (1, 2), (4,)),
        ("ternary_len2_orders", (1, 2, 3), (2,)),
        ("binary_len1_3_mixed", (1, 2), (1, 2, 3)),
        ("ternary_len1_2_mixed", (1, 2, 3), (1, 2)),
        ("binary_len1_4_mixed", (1, 2), (1, 2, 3, 4)),
        ("ternary_len1_3_mixed", (1, 2, 3), (1, 2, 3)),
    ]
    for name, alphabet, lengths in exhaustive_cases:
        print()
        print_exhaustive(exhaustive_conflict_boundary_case(name, alphabet, lengths))

    exact13_pool = build_exact13_overlap_pool()
    for result in [
        explicit_pool_baseline_case(
            "exact13_overlap_pool_m4_t2_baseline",
            exact13_pool,
            family_size=4,
            selection_size=2,
        ),
        explicit_pool_baseline_case(
            "exact13_overlap_pool_m5_t3_baseline",
            exact13_pool,
            family_size=5,
            selection_size=3,
        ),
    ]:
        print()
        print_pool(result)


if __name__ == "__main__":
    main()
