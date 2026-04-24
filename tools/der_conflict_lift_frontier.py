#!/usr/bin/env python3
"""
Probe whether the toy destructive-conflict gadget can be lifted into valid DER.

This follows frontier-10. The repo's working conjecture now says expressive
FindAndDelete behavior seems to require real destructive conflict. The next
question is whether a straightforward valid-DER lift of the toy conflict gadget
can realize that mechanism, or whether it still collapses back to the plain
subset baseline.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations, permutations, product
from pathlib import Path
import random
import sys


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from der_surface_frontier import FamilyScore, analyze_family  # type: ignore
from fad_mechanism_frontier import conflict_witness_for_order  # type: ignore
from secp256k1 import encode_der_sig  # type: ignore


UNORDERED_BASELINE_M4_T2 = 6


@dataclass(frozen=True)
class DirectLiftResult:
    name: str
    exact_len: int
    code_order: tuple[str, ...]
    score: FamilyScore
    conflict_found: bool
    order: tuple[str, ...]


@dataclass(frozen=True)
class ExhaustiveLiftResult:
    name: str
    exact_len: int
    alphabet: tuple[int, ...]
    pool_size: int
    total_orders: int
    expressive_orders: int
    best_score: FamilyScore
    best_order: tuple[str, ...]
    conflict_found: bool


@dataclass(frozen=True)
class SampledLiftResult:
    name: str
    exact_len: int
    alphabet: tuple[int, ...]
    pool_size: int
    trials: int
    expressive_samples: int
    best_score: FamilyScore
    best_order: tuple[str, ...]
    conflict_found: bool


def score_tuple(score: FamilyScore) -> tuple[int, int]:
    return (score.unique_ordered_outcomes, score.max_results_per_unordered_subset)


def coupled_anchor_token(exact_len: int, code: bytes) -> bytes:
    anchor = bytes([exact_len, 0x30, exact_len - 3, 0x02, 0x01])
    if len(code) != exact_len - 13:
        raise ValueError(
            f"expected code length {exact_len - 13} for exact_len={exact_len}, got {len(code)}"
        )
    r = code[0]
    s = int.from_bytes(anchor + code, "big")
    sig = encode_der_sig(r, s, sighash=0x03)
    if len(sig) != exact_len:
        raise AssertionError(f"expected exact payload length {exact_len}, got {len(sig)}")
    return sig


def is_expressive(score: FamilyScore) -> bool:
    return (
        score.unique_ordered_outcomes > UNORDERED_BASELINE_M4_T2
        or score.max_results_per_unordered_subset > 1
    )


def code_pool(exact_len: int, alphabet: tuple[int, ...]) -> tuple[bytes, ...]:
    return tuple(
        bytes(code) for code in product(alphabet, repeat=exact_len - 13)
    )


def direct_toy_lift() -> DirectLiftResult:
    codes = tuple(bytes.fromhex(value) for value in ["0101", "0102", "0303", "0203"])
    order = tuple(coupled_anchor_token(15, code) for code in codes)
    score = analyze_family(order, selection_size=2)
    return DirectLiftResult(
        name="exact15_direct_toy_conflict_lift",
        exact_len=15,
        code_order=tuple(code.hex() for code in codes),
        score=score,
        conflict_found=conflict_witness_for_order(order, selection_size=2) is not None,
        order=tuple(token.hex() for token in order),
    )


def exhaustive_case(
    name: str,
    exact_len: int,
    alphabet: tuple[int, ...],
) -> ExhaustiveLiftResult:
    pool = tuple(coupled_anchor_token(exact_len, code) for code in code_pool(exact_len, alphabet))
    total_orders = 0
    expressive_orders = 0
    best_score: FamilyScore | None = None
    best_order: tuple[str, ...] | None = None
    conflict_found = False

    for family in combinations(pool, 4):
        for order in permutations(family):
            total_orders += 1
            score = analyze_family(order, selection_size=2)
            if is_expressive(score):
                expressive_orders += 1
            if best_score is None or score_tuple(score) > score_tuple(best_score):
                best_score = score
                best_order = tuple(token.hex() for token in order)
            if conflict_witness_for_order(order, selection_size=2) is not None:
                conflict_found = True

    if best_score is None or best_order is None:
        raise RuntimeError(f"no exhaustive result for {name}")

    return ExhaustiveLiftResult(
        name=name,
        exact_len=exact_len,
        alphabet=alphabet,
        pool_size=len(pool),
        total_orders=total_orders,
        expressive_orders=expressive_orders,
        best_score=best_score,
        best_order=best_order,
        conflict_found=conflict_found,
    )


def sampled_case(
    name: str,
    exact_len: int,
    alphabet: tuple[int, ...],
    trials: int,
    seed: int,
) -> SampledLiftResult:
    pool = tuple(coupled_anchor_token(exact_len, code) for code in code_pool(exact_len, alphabet))
    rng = random.Random(seed + exact_len + len(alphabet))
    expressive_samples = 0
    best_score: FamilyScore | None = None
    best_order: tuple[str, ...] | None = None
    conflict_found = False

    for _ in range(trials):
        family = list(rng.sample(pool, 4))
        rng.shuffle(family)
        order = tuple(family)
        score = analyze_family(order, selection_size=2)
        if is_expressive(score):
            expressive_samples += 1
        if best_score is None or score_tuple(score) > score_tuple(best_score):
            best_score = score
            best_order = tuple(token.hex() for token in order)
        if conflict_witness_for_order(order, selection_size=2) is not None:
            conflict_found = True
            break

    if best_score is None or best_order is None:
        raise RuntimeError(f"no sampled result for {name}")

    return SampledLiftResult(
        name=name,
        exact_len=exact_len,
        alphabet=alphabet,
        pool_size=len(pool),
        trials=trials,
        expressive_samples=expressive_samples,
        best_score=best_score,
        best_order=best_order,
        conflict_found=conflict_found,
    )


def print_direct(result: DirectLiftResult) -> None:
    print(f"# {result.name}")
    print(f"exact_len: {result.exact_len}")
    print(f"unordered_subset_baseline: {UNORDERED_BASELINE_M4_T2}")
    print(f"code_order: {list(result.code_order)}")
    print(f"unique_ordered_outcomes: {result.score.unique_ordered_outcomes}")
    print(
        "max_results_per_unordered_subset:"
        f" {result.score.max_results_per_unordered_subset}"
    )
    print(f"conflict_found: {str(result.conflict_found).lower()}")
    print(f"order: {list(result.order)}")


def print_exhaustive(result: ExhaustiveLiftResult) -> None:
    print(f"# {result.name}")
    print(f"exact_len: {result.exact_len}")
    print(f"alphabet: {list(result.alphabet)}")
    print(f"pool_size: {result.pool_size}")
    print(f"total_orders: {result.total_orders}")
    print(f"unordered_subset_baseline: {UNORDERED_BASELINE_M4_T2}")
    print(f"expressive_orders: {result.expressive_orders}")
    print(f"best_unique_ordered_outcomes: {result.best_score.unique_ordered_outcomes}")
    print(
        "best_max_results_per_unordered_subset:"
        f" {result.best_score.max_results_per_unordered_subset}"
    )
    print(f"conflict_found: {str(result.conflict_found).lower()}")
    print(f"best_order: {list(result.best_order)}")


def print_sampled(result: SampledLiftResult) -> None:
    print(f"# {result.name}")
    print(f"exact_len: {result.exact_len}")
    print(f"alphabet: {list(result.alphabet)}")
    print(f"pool_size: {result.pool_size}")
    print(f"trials: {result.trials}")
    print(f"unordered_subset_baseline: {UNORDERED_BASELINE_M4_T2}")
    print(f"expressive_samples: {result.expressive_samples}")
    print(f"best_unique_ordered_outcomes: {result.best_score.unique_ordered_outcomes}")
    print(
        "best_max_results_per_unordered_subset:"
        f" {result.best_score.max_results_per_unordered_subset}"
    )
    print(f"conflict_found: {str(result.conflict_found).lower()}")
    print(f"best_order: {list(result.best_order)}")


def main() -> None:
    print()
    print_direct(direct_toy_lift())

    for result in [
        exhaustive_case("exact14_coupled_anchor_exhaustive", 14, (1, 2, 3, 4)),
        exhaustive_case("exact15_coupled_anchor_exhaustive", 15, (1, 2, 3)),
        exhaustive_case("exact16_coupled_anchor_exhaustive", 16, (1, 2)),
    ]:
        print()
        print_exhaustive(result)

    for result in [
        sampled_case(
            "exact15_coupled_anchor_sampled",
            15,
            (1, 2, 3, 4),
            trials=10_000,
            seed=20_260_424,
        ),
        sampled_case(
            "exact16_coupled_anchor_sampled",
            16,
            (1, 2, 3),
            trials=10_000,
            seed=20_260_424,
        ),
        sampled_case(
            "exact17_coupled_anchor_sampled",
            17,
            (1, 2, 3),
            trials=10_000,
            seed=20_260_424,
        ),
        sampled_case(
            "exact18_coupled_anchor_sampled",
            18,
            (1, 2, 3),
            trials=10_000,
            seed=20_260_424,
        ),
    ]:
        print()
        print_sampled(result)


if __name__ == "__main__":
    main()
