#!/usr/bin/env python3
"""
Probe double-anchor DER families for destructive-conflict structure.

This follows frontier-11. The single-anchor DER gadget lift failed, so the next
question is whether explicitly planting the pushed-token anchor twice inside the
same valid DER payload changes the FindAndDelete surface in a meaningful way.
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
class TemplateSpec:
    name: str
    exact_len: int
    mid_len: int
    tail_len: int


@dataclass(frozen=True)
class ExhaustiveTemplateResult:
    template_name: str
    exact_len: int
    alphabet: tuple[int, ...]
    pool_size: int
    total_orders: int
    expressive_orders: int
    best_score: FamilyScore
    best_order: tuple[str, ...]
    conflict_found: bool


@dataclass(frozen=True)
class SampledTemplateResult:
    template_name: str
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


def is_expressive(score: FamilyScore) -> bool:
    return (
        score.unique_ordered_outcomes > UNORDERED_BASELINE_M4_T2
        or score.max_results_per_unordered_subset > 1
    )


def make_double_anchor_token(
    exact_len: int,
    mid: bytes,
    tail: bytes,
) -> bytes:
    anchor = bytes([exact_len, 0x30, exact_len - 3, 0x02, 0x01])
    code = mid + anchor + tail
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


def template_pool(spec: TemplateSpec, alphabet: tuple[int, ...]) -> tuple[bytes, ...]:
    return tuple(
        make_double_anchor_token(spec.exact_len, bytes(mid), bytes(tail))
        for mid in product(alphabet, repeat=spec.mid_len)
        for tail in product(alphabet, repeat=spec.tail_len)
    )


def exhaustive_case(
    spec: TemplateSpec,
    alphabet: tuple[int, ...],
) -> ExhaustiveTemplateResult:
    pool = template_pool(spec, alphabet)
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
        raise RuntimeError(f"no exhaustive result for {spec.name}")

    return ExhaustiveTemplateResult(
        template_name=spec.name,
        exact_len=spec.exact_len,
        alphabet=alphabet,
        pool_size=len(pool),
        total_orders=total_orders,
        expressive_orders=expressive_orders,
        best_score=best_score,
        best_order=best_order,
        conflict_found=conflict_found,
    )


def sampled_case(
    spec: TemplateSpec,
    alphabet: tuple[int, ...],
    trials: int,
    seed: int,
) -> SampledTemplateResult:
    pool = template_pool(spec, alphabet)
    rng = random.Random(seed + spec.exact_len + spec.mid_len * 10 + spec.tail_len)
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
        raise RuntimeError(f"no sampled result for {spec.name}")

    return SampledTemplateResult(
        template_name=spec.name,
        exact_len=spec.exact_len,
        alphabet=alphabet,
        pool_size=len(pool),
        trials=trials,
        expressive_samples=expressive_samples,
        best_score=best_score,
        best_order=best_order,
        conflict_found=conflict_found,
    )


def print_exhaustive(result: ExhaustiveTemplateResult) -> None:
    print(f"# {result.template_name}_exhaustive")
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


def print_sampled(result: SampledTemplateResult) -> None:
    print(f"# {result.template_name}_sampled")
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
    exhaustive_specs = [
        (TemplateSpec("exact20_split1_1", exact_len=20, mid_len=1, tail_len=1), (1, 2, 3)),
        (TemplateSpec("exact21_split1_2", exact_len=21, mid_len=1, tail_len=2), (1, 2)),
        (TemplateSpec("exact21_split2_1", exact_len=21, mid_len=2, tail_len=1), (1, 2)),
        (TemplateSpec("exact22_split2_2", exact_len=22, mid_len=2, tail_len=2), (1, 2)),
    ]
    for spec, alphabet in exhaustive_specs:
        print()
        print_exhaustive(exhaustive_case(spec, alphabet))

    sampled_specs = [
        (TemplateSpec("exact20_split1_1", exact_len=20, mid_len=1, tail_len=1), (1, 2, 3, 4)),
        (TemplateSpec("exact21_split1_2", exact_len=21, mid_len=1, tail_len=2), (1, 2, 3)),
        (TemplateSpec("exact21_split2_1", exact_len=21, mid_len=2, tail_len=1), (1, 2, 3)),
        (TemplateSpec("exact22_split2_2", exact_len=22, mid_len=2, tail_len=2), (1, 2, 3)),
    ]
    for spec, alphabet in sampled_specs:
        print()
        print_sampled(sampled_case(spec, alphabet, trials=20_000, seed=20_260_424))


if __name__ == "__main__":
    main()
