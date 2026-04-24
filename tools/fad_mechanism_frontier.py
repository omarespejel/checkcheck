#!/usr/bin/env python3
"""
Classify the mechanisms behind FindAndDelete expressivity.

This follows frontier-8. The next question is whether cascade-bearing is the
real invariant behind expressive families, or whether there is a broader
mechanism. The tool distinguishes two ways order can matter:

1. Fresh-occurrence cascade: a deletion creates a new later-match occurrence.
2. Destructive conflict: a deletion destroys an already-existing occurrence of a
   different still-live token.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import permutations, product
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

from bitcoin_tx import push_data  # type: ignore
from der_overlap_threshold_frontier import build_exact13_overlap_pool  # type: ignore
from der_surface_frontier import exact_r_pools, sample_exact_payload_sig  # type: ignore
from fad_cascade_frontier import (  # type: ignore
    CascadeWitness,
    cascade_witness_for_order,
    find_and_delete_annotated,
    occurrence_index_tuples,
)


@dataclass(frozen=True)
class ConflictWitness:
    selection_order: tuple[int, ...]
    step_index: int
    deleted_token_index: int
    destroyed_token_index: int
    destroyed_occurrence_indices: tuple[int, ...]


@dataclass(frozen=True)
class ExhaustiveClassification:
    name: str
    total_orders: int
    expressive_orders: int
    expressive_with_conflict_only: int
    expressive_with_cascade_and_conflict: int
    expressive_with_cascade_only: int
    expressive_without_mechanism: int
    representative_conflict_only_order: tuple[str, ...] | None
    representative_conflict_only_witness: ConflictWitness | None
    representative_both_order: tuple[str, ...] | None
    representative_both_cascade: CascadeWitness | None
    representative_both_conflict: ConflictWitness | None
    representative_no_mechanism_order: tuple[str, ...] | None


@dataclass(frozen=True)
class DerMechanismProbe:
    name: str
    family_size: int
    selection_size: int
    conflict_found: bool
    conflict_witness: ConflictWitness | None
    script_order: tuple[str, ...]


@dataclass(frozen=True)
class RandomDerMechanismProbe:
    name: str
    payload_len: int
    family_size: int
    selection_size: int
    trials: int
    conflict_found: bool


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


def expressive(order: tuple[bytes, ...], selection_size: int) -> bool:
    patterns = tuple(push_data(token) for token in order)
    script = b"".join(patterns)
    outcomes = set()
    subset_to_outcomes: dict[frozenset[int], set[bytes]] = {}
    for selection in permutations(range(len(order)), selection_size):
        cur = script
        for idx in selection:
            cur = find_and_delete_pattern(cur, patterns[idx])
        outcomes.add(cur)
        subset_to_outcomes.setdefault(frozenset(selection), set()).add(cur)
    subset_baseline = 1
    for factor in range(selection_size):
        subset_baseline *= len(order) - factor
    # convert ordered baseline m!/(m-t)! to unordered C(m,t)
    for factor in range(2, selection_size + 1):
        subset_baseline //= factor
    if len(outcomes) > subset_baseline:
        return True
    return max(len(v) for v in subset_to_outcomes.values()) > 1


def conflict_witness_for_order(
    tokens_in_script_order: tuple[bytes, ...],
    selection_size: int,
) -> ConflictWitness | None:
    patterns = tuple(push_data(token) for token in tokens_in_script_order)
    base_script = b"".join(patterns)
    base_indices = tuple(range(len(base_script)))
    for selection in permutations(range(len(patterns)), selection_size):
        cur_script = base_script
        cur_indices = base_indices
        for step_index, deleted_idx in enumerate(selection):
            next_script, next_indices = find_and_delete_annotated(
                cur_script,
                cur_indices,
                patterns[deleted_idx],
            )
            remaining = set(range(len(patterns))) - set(selection[: step_index + 1])
            for target_idx in remaining:
                previous = set(
                    occurrence_index_tuples(cur_script, cur_indices, patterns[target_idx])
                )
                current = set(
                    occurrence_index_tuples(next_script, next_indices, patterns[target_idx])
                )
                destroyed = [occ for occ in previous if occ not in current]
                if destroyed:
                    return ConflictWitness(
                        selection_order=selection,
                        step_index=step_index,
                        deleted_token_index=deleted_idx,
                        destroyed_token_index=target_idx,
                        destroyed_occurrence_indices=destroyed[0],
                    )
            cur_script = next_script
            cur_indices = next_indices
    return None


def exhaustive_case(
    name: str,
    alphabet: tuple[int, ...],
    payload_len: int,
) -> ExhaustiveClassification:
    payloads = tuple(bytes(tup) for tup in product(alphabet, repeat=payload_len))
    total_orders = 0
    expressive_orders = 0
    expressive_with_conflict_only = 0
    expressive_with_cascade_and_conflict = 0
    expressive_with_cascade_only = 0
    expressive_without_mechanism = 0

    representative_conflict_only_order = None
    representative_conflict_only_witness = None
    representative_both_order = None
    representative_both_cascade = None
    representative_both_conflict = None
    representative_no_mechanism_order = None

    for order in permutations(payloads, 4):
        total_orders += 1
        is_expressive = expressive(order, selection_size=2)
        cascade = cascade_witness_for_order(order, selection_size=2)
        conflict = conflict_witness_for_order(order, selection_size=2)
        if not is_expressive:
            continue
        expressive_orders += 1
        if cascade is not None and conflict is not None:
            expressive_with_cascade_and_conflict += 1
            if representative_both_order is None:
                representative_both_order = tuple(token.hex() for token in order)
                representative_both_cascade = cascade
                representative_both_conflict = conflict
            continue
        if cascade is not None:
            expressive_with_cascade_only += 1
            continue
        if conflict is not None:
            expressive_with_conflict_only += 1
            if representative_conflict_only_order is None:
                representative_conflict_only_order = tuple(token.hex() for token in order)
                representative_conflict_only_witness = conflict
            continue
        expressive_without_mechanism += 1
        if representative_no_mechanism_order is None:
            representative_no_mechanism_order = tuple(token.hex() for token in order)

    return ExhaustiveClassification(
        name=name,
        total_orders=total_orders,
        expressive_orders=expressive_orders,
        expressive_with_conflict_only=expressive_with_conflict_only,
        expressive_with_cascade_and_conflict=expressive_with_cascade_and_conflict,
        expressive_with_cascade_only=expressive_with_cascade_only,
        expressive_without_mechanism=expressive_without_mechanism,
        representative_conflict_only_order=representative_conflict_only_order,
        representative_conflict_only_witness=representative_conflict_only_witness,
        representative_both_order=representative_both_order,
        representative_both_cascade=representative_both_cascade,
        representative_both_conflict=representative_both_conflict,
        representative_no_mechanism_order=representative_no_mechanism_order,
    )


def explicit_der_probe(
    name: str,
    family_size: int,
    selection_size: int,
) -> DerMechanismProbe:
    pool = build_exact13_overlap_pool()
    fallback_order = tuple(token.hex() for token in pool[:family_size])
    for family in permutations(pool, family_size):
        conflict = conflict_witness_for_order(family, selection_size=selection_size)
        if conflict is not None:
            return DerMechanismProbe(
                name=name,
                family_size=family_size,
                selection_size=selection_size,
                conflict_found=True,
                conflict_witness=conflict,
                script_order=tuple(token.hex() for token in family),
            )
    return DerMechanismProbe(
        name=name,
        family_size=family_size,
        selection_size=selection_size,
        conflict_found=False,
        conflict_witness=None,
        script_order=fallback_order,
    )


def random_der_probe(
    name: str,
    payload_len: int,
    family_size: int,
    selection_size: int,
    trials: int,
    seed: int,
) -> RandomDerMechanismProbe:
    rng = random.Random(seed + payload_len * 100 + family_size * 10 + selection_size)
    r_len1, r_len2 = exact_r_pools()
    for _ in range(trials):
        family = set()
        while len(family) < family_size:
            family.add(sample_exact_payload_sig(payload_len, rng, r_len1, r_len2))
        order = list(family)
        rng.shuffle(order)
        if conflict_witness_for_order(tuple(order), selection_size=selection_size) is not None:
            return RandomDerMechanismProbe(
                name=name,
                payload_len=payload_len,
                family_size=family_size,
                selection_size=selection_size,
                trials=trials,
                conflict_found=True,
            )
    return RandomDerMechanismProbe(
        name=name,
        payload_len=payload_len,
        family_size=family_size,
        selection_size=selection_size,
        trials=trials,
        conflict_found=False,
    )


def print_exhaustive(case: ExhaustiveClassification) -> None:
    print(f"# {case.name}")
    print(f"total_orders: {case.total_orders}")
    print(f"expressive_orders: {case.expressive_orders}")
    print(f"expressive_with_conflict_only: {case.expressive_with_conflict_only}")
    print(
        "expressive_with_cascade_and_conflict:"
        f" {case.expressive_with_cascade_and_conflict}"
    )
    print(f"expressive_with_cascade_only: {case.expressive_with_cascade_only}")
    print(f"expressive_without_mechanism: {case.expressive_without_mechanism}")
    if case.representative_conflict_only_order is not None:
        print(
            "representative_conflict_only_order:"
            f" {list(case.representative_conflict_only_order)}"
        )
        if case.representative_conflict_only_witness is not None:
            print(
                "representative_conflict_only_witness:"
                f" selection_order={list(case.representative_conflict_only_witness.selection_order)}"
                f" step_index={case.representative_conflict_only_witness.step_index}"
                f" deleted_token_index={case.representative_conflict_only_witness.deleted_token_index}"
                f" destroyed_token_index={case.representative_conflict_only_witness.destroyed_token_index}"
                f" destroyed_occurrence_indices={list(case.representative_conflict_only_witness.destroyed_occurrence_indices)}"
            )
    if case.representative_both_order is not None:
        print(f"representative_both_order: {list(case.representative_both_order)}")
        if case.representative_both_cascade is not None:
            print(
                "representative_both_cascade:"
                f" selection_order={list(case.representative_both_cascade.selection_order)}"
                f" step_index={case.representative_both_cascade.step_index}"
                f" deleted_token_index={case.representative_both_cascade.deleted_token_index}"
                f" created_token_index={case.representative_both_cascade.created_token_index}"
                f" fresh_occurrence_indices={list(case.representative_both_cascade.fresh_occurrence_indices)}"
            )
        if case.representative_both_conflict is not None:
            print(
                "representative_both_conflict:"
                f" selection_order={list(case.representative_both_conflict.selection_order)}"
                f" step_index={case.representative_both_conflict.step_index}"
                f" deleted_token_index={case.representative_both_conflict.deleted_token_index}"
                f" destroyed_token_index={case.representative_both_conflict.destroyed_token_index}"
                f" destroyed_occurrence_indices={list(case.representative_both_conflict.destroyed_occurrence_indices)}"
            )
    if case.representative_no_mechanism_order is not None:
        print(
            "representative_no_mechanism_order:"
            f" {list(case.representative_no_mechanism_order)}"
        )


def print_der_probe(probe: DerMechanismProbe) -> None:
    print(f"# {probe.name}")
    print(f"family_size: {probe.family_size}")
    print(f"selection_size: {probe.selection_size}")
    print(f"conflict_found: {str(probe.conflict_found).lower()}")
    print(f"script_order: {list(probe.script_order)}")
    if probe.conflict_witness is not None:
        print(
            "conflict_witness:"
            f" selection_order={list(probe.conflict_witness.selection_order)}"
            f" step_index={probe.conflict_witness.step_index}"
            f" deleted_token_index={probe.conflict_witness.deleted_token_index}"
            f" destroyed_token_index={probe.conflict_witness.destroyed_token_index}"
            f" destroyed_occurrence_indices={list(probe.conflict_witness.destroyed_occurrence_indices)}"
        )


def print_random_der_probe(probe: RandomDerMechanismProbe) -> None:
    print(f"# {probe.name}")
    print(f"payload_len: {probe.payload_len}")
    print(f"family_size: {probe.family_size}")
    print(f"selection_size: {probe.selection_size}")
    print(f"trials: {probe.trials}")
    print(f"conflict_found: {str(probe.conflict_found).lower()}")


def main() -> None:
    for case in [
        exhaustive_case("binary_len2_orders", (1, 2), 2),
        exhaustive_case("binary_len3_orders", (1, 2), 3),
        exhaustive_case("binary_len4_orders", (1, 2), 4),
        exhaustive_case("ternary_len2_orders", (1, 2, 3), 2),
    ]:
        print()
        print_exhaustive(case)

    for probe in [
        explicit_der_probe("exact13_overlap_pool_m4_t2", family_size=4, selection_size=2),
        explicit_der_probe("exact13_overlap_pool_m5_t3", family_size=5, selection_size=3),
    ]:
        print()
        print_der_probe(probe)

    for probe in [
        random_der_probe(
            "random_exact13_m4_t2",
            payload_len=13,
            family_size=4,
            selection_size=2,
            trials=2_000,
            seed=20_260_424,
        ),
        random_der_probe(
            "random_exact14_m4_t2",
            payload_len=14,
            family_size=4,
            selection_size=2,
            trials=2_000,
            seed=20_260_424,
        ),
        random_der_probe(
            "random_exact15_m4_t2",
            payload_len=15,
            family_size=4,
            selection_size=2,
            trials=1_500,
            seed=20_260_424,
        ),
        random_der_probe(
            "random_exact13_m5_t3",
            payload_len=13,
            family_size=5,
            selection_size=3,
            trials=1_000,
            seed=20_260_424,
        ),
    ]:
        print()
        print_random_der_probe(probe)


if __name__ == "__main__":
    main()
