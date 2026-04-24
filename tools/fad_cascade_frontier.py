#!/usr/bin/env python3
"""
Probe fresh-occurrence cascades under FindAndDelete.

This follows frontier-7. The question is no longer whether valid DER surfaces
 can contain overlaps. The question is whether those overlaps ever create fresh
 deletable occurrences after a prior deletion. That is the first mechanized
 explanation for why overlap-bearing DER families may still collapse to plain
 subset behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations, permutations
from pathlib import Path
import random
import sys


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from der_overlap_threshold_frontier import build_exact13_overlap_pool  # type: ignore
from der_surface_frontier import exact_r_pools, sample_exact_payload_sig  # type: ignore
from fad_overlap_search import toy_overlap_search  # type: ignore

UPSTREAM_PIPELINE = ROOT / "third_party" / "qsb-avihu" / "pipeline"
if str(UPSTREAM_PIPELINE) not in sys.path:
    sys.path.insert(0, str(UPSTREAM_PIPELINE))

from bitcoin_tx import push_data  # type: ignore


@dataclass(frozen=True)
class CascadeWitness:
    selection_order: tuple[int, ...]
    step_index: int
    deleted_token_index: int
    created_token_index: int
    fresh_occurrence_indices: tuple[int, ...]


@dataclass(frozen=True)
class FamilyCascadeResult:
    name: str
    family_size: int
    selection_size: int
    cascade_found: bool
    witness: CascadeWitness | None
    family: tuple[str, ...]
    script_order: tuple[str, ...]


@dataclass(frozen=True)
class RandomCascadeResult:
    name: str
    payload_len: int
    family_size: int
    selection_size: int
    trials: int
    cascade_found: bool


def find_and_delete_annotated(
    script: bytes,
    indices: tuple[int, ...],
    pattern: bytes,
) -> tuple[bytes, tuple[int, ...]]:
    out_bytes = bytearray()
    out_indices: list[int] = []
    plen = len(pattern)
    i = 0
    while i <= len(script) - plen:
        if script[i : i + plen] == pattern:
            i += plen
        else:
            out_bytes.append(script[i])
            out_indices.append(indices[i])
            i += 1
    out_bytes.extend(script[i:])
    out_indices.extend(indices[i:])
    return bytes(out_bytes), tuple(out_indices)


def occurrence_index_tuples(
    script: bytes,
    indices: tuple[int, ...],
    pattern: bytes,
) -> tuple[tuple[int, ...], ...]:
    matches: list[tuple[int, ...]] = []
    plen = len(pattern)
    for i in range(len(script) - plen + 1):
        if script[i : i + plen] == pattern:
            matches.append(tuple(indices[i : i + plen]))
    return tuple(matches)


def cascade_witness_for_order(
    tokens_in_script_order: tuple[bytes, ...],
    selection_size: int,
) -> CascadeWitness | None:
    patterns = tuple(push_data(token) for token in tokens_in_script_order)
    base_script = b"".join(patterns)
    base_indices = tuple(range(len(base_script)))
    original_occurrences = {
        idx: set(occurrence_index_tuples(base_script, base_indices, pattern))
        for idx, pattern in enumerate(patterns)
    }
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
                fresh = [
                    occ
                    for occ in current
                    if occ not in previous and occ not in original_occurrences[target_idx]
                ]
                if fresh:
                    return CascadeWitness(
                        selection_order=selection,
                        step_index=step_index,
                        deleted_token_index=deleted_idx,
                        created_token_index=target_idx,
                        fresh_occurrence_indices=fresh[0],
                    )
            cur_script = next_script
            cur_indices = next_indices
    return None


def first_cascade_in_pool(
    name: str,
    pool: tuple[bytes, ...],
    family_size: int,
    selection_size: int,
) -> FamilyCascadeResult:
    first_family: tuple[str, ...] | None = None
    first_order: tuple[str, ...] | None = None
    for family in combinations(pool, family_size):
        for order in permutations(family):
            witness = cascade_witness_for_order(order, selection_size=selection_size)
            if first_family is None:
                first_family = tuple(token.hex() for token in family)
            if first_order is None:
                first_order = tuple(token.hex() for token in order)
            if witness is None:
                continue
            return FamilyCascadeResult(
                name=name,
                family_size=family_size,
                selection_size=selection_size,
                cascade_found=True,
                witness=witness,
                family=tuple(token.hex() for token in family),
                script_order=tuple(token.hex() for token in order),
            )
    if first_family is None or first_order is None:
        raise RuntimeError(f"empty pool for {name}")
    return FamilyCascadeResult(
        name=name,
        family_size=family_size,
        selection_size=selection_size,
        cascade_found=False,
        witness=None,
        family=first_family,
        script_order=first_order,
    )


def random_cascade_search(
    name: str,
    payload_len: int,
    family_size: int,
    selection_size: int,
    trials: int,
    seed: int,
) -> RandomCascadeResult:
    rng = random.Random(seed + payload_len * 100 + family_size * 10 + selection_size)
    r_len1, r_len2 = exact_r_pools()
    for _ in range(trials):
        family = set()
        while len(family) < family_size:
            family.add(sample_exact_payload_sig(payload_len, rng, r_len1, r_len2))
        order = list(family)
        rng.shuffle(order)
        if cascade_witness_for_order(tuple(order), selection_size=selection_size) is not None:
            return RandomCascadeResult(
                name=name,
                payload_len=payload_len,
                family_size=family_size,
                selection_size=selection_size,
                trials=trials,
                cascade_found=True,
            )
    return RandomCascadeResult(
        name=name,
        payload_len=payload_len,
        family_size=family_size,
        selection_size=selection_size,
        trials=trials,
        cascade_found=False,
    )


def print_family_result(result: FamilyCascadeResult) -> None:
    print(f"# {result.name}")
    print(f"family_size: {result.family_size}")
    print(f"selection_size: {result.selection_size}")
    print(f"cascade_found: {str(result.cascade_found).lower()}")
    print(f"family: {list(result.family)}")
    print(f"script_order: {list(result.script_order)}")
    if result.witness is not None:
        print(f"selection_order: {list(result.witness.selection_order)}")
        print(f"step_index: {result.witness.step_index}")
        print(f"deleted_token_index: {result.witness.deleted_token_index}")
        print(f"created_token_index: {result.witness.created_token_index}")
        print(
            "fresh_occurrence_indices:"
            f" {list(result.witness.fresh_occurrence_indices)}"
        )


def print_random_result(result: RandomCascadeResult) -> None:
    print(f"# {result.name}")
    print(f"payload_len: {result.payload_len}")
    print(f"family_size: {result.family_size}")
    print(f"selection_size: {result.selection_size}")
    print(f"trials: {result.trials}")
    print(f"cascade_found: {str(result.cascade_found).lower()}")


def main() -> None:
    toy = toy_overlap_search()
    toy_order = tuple(bytes.fromhex(token) for token in toy.script_perm)
    toy_result = FamilyCascadeResult(
        name="toy_overlap_best_m4_t2",
        family_size=4,
        selection_size=2,
        cascade_found=False,
        witness=None,
        family=tuple(toy.payloads),
        script_order=tuple(toy.script_perm),
    )
    toy_witness = cascade_witness_for_order(toy_order, selection_size=2)
    if toy_witness is not None:
        toy_result = FamilyCascadeResult(
            name="toy_overlap_best_m4_t2",
            family_size=4,
            selection_size=2,
            cascade_found=True,
            witness=toy_witness,
            family=tuple(toy.payloads),
            script_order=tuple(toy.script_perm),
        )

    print_family_result(toy_result)

    for result in [
        first_cascade_in_pool(
            name="exact13_overlap_pool_m4_t2",
            pool=build_exact13_overlap_pool(),
            family_size=4,
            selection_size=2,
        ),
        first_cascade_in_pool(
            name="exact13_overlap_pool_m5_t3",
            pool=build_exact13_overlap_pool(),
            family_size=5,
            selection_size=3,
        ),
    ]:
        print()
        print_family_result(result)

    for result in [
        random_cascade_search(
            name="random_exact13_m4_t2",
            payload_len=13,
            family_size=4,
            selection_size=2,
            trials=2_000,
            seed=20_260_424,
        ),
        random_cascade_search(
            name="random_exact14_m4_t2",
            payload_len=14,
            family_size=4,
            selection_size=2,
            trials=2_000,
            seed=20_260_424,
        ),
        random_cascade_search(
            name="random_exact15_m4_t2",
            payload_len=15,
            family_size=4,
            selection_size=2,
            trials=1_500,
            seed=20_260_424,
        ),
        random_cascade_search(
            name="random_exact13_m5_t3",
            payload_len=13,
            family_size=5,
            selection_size=3,
            trials=1_000,
            seed=20_260_424,
        ),
    ]:
        print()
        print_random_result(result)


if __name__ == "__main__":
    main()
