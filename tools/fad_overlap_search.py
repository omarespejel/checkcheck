#!/usr/bin/env python3
"""
Searches for overlap-coded FindAndDelete behavior.

The goal is to answer four progressively narrower questions:

1. Can FindAndDelete be more expressive than plain subset deletion in toy byte
   constructions?
2. Does that overlap survive once all selectable payloads have the same length?
3. Can engineered arbitrary 9-byte payloads still realize overlap?
4. Does the actual QSB minimal 9-byte dummy-signature surface expose any of
   that additional expressivity, or is it structurally overlap-free?
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations, permutations, product
from math import comb
from pathlib import Path
import hashlib
import random
import sys
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_PIPELINE = ROOT / "third_party" / "qsb-avihu" / "pipeline"

if str(UPSTREAM_PIPELINE) not in sys.path:
    sys.path.insert(0, str(UPSTREAM_PIPELINE))

from bitcoin_tx import (  # type: ignore
    QSBScriptBuilder,
    _encode_9byte_sig,
    _valid_small_r_values,
    find_and_delete,
    push_data,
)


@dataclass(frozen=True)
class ToyOverlapResult:
    unique_ordered_outcomes: int
    max_results_per_unordered_subset: int
    payloads: tuple[str, ...]
    script_perm: tuple[str, ...]
    script_hex: str
    witness_subset: tuple[str, ...]
    order_a: tuple[str, ...]
    outcome_a: str
    order_b: tuple[str, ...]
    outcome_b: str


@dataclass(frozen=True)
class FamilyOverlapResult:
    name: str
    unique_ordered_outcomes: int
    subset_baseline: int
    max_results_per_unordered_subset: int
    payloads: tuple[str, ...]
    script_perm: tuple[str, ...]
    script_hex: str
    witness_subset: tuple[str, ...] | None
    order_a: tuple[str, ...] | None
    outcome_a: str | None
    order_b: tuple[str, ...] | None
    outcome_b: str | None


@dataclass(frozen=True)
class SurfaceOverlapResult:
    name: str
    surface_size: int
    token_size: int
    cross_bifix_free: bool
    max_distinct_overlap: int
    overlap_a: str | None
    overlap_b: str | None
    overlap_len: int | None


@dataclass(frozen=True)
class QSBProbeResult:
    name: str
    ordered_queries: int
    unique_scriptcodes: int
    subset_target: int
    multiplicity: int


def find_and_delete_pattern(script: bytes, pattern: bytes) -> bytes:
    """FindAndDelete against an already-pushed pattern."""
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


def analyze_pattern_family(
    name: str,
    patterns_in_script_order: tuple[bytes, ...],
    selection_size: int,
    family_payloads: tuple[bytes, ...] | None = None,
) -> FamilyOverlapResult:
    script = b"".join(patterns_in_script_order)
    outcomes = set()
    subset_to_outcomes: dict[frozenset[bytes], dict[bytes, list[tuple[str, ...]]]] = {}
    for selection in permutations(patterns_in_script_order, selection_size):
        cur = script
        for pattern in selection:
            cur = find_and_delete_pattern(cur, pattern)
        outcomes.add(cur)
        bucket = subset_to_outcomes.setdefault(frozenset(selection), {})
        bucket.setdefault(cur, []).append(tuple(x[1:].hex() for x in selection))

    witness_subset = None
    order_a = None
    outcome_a = None
    order_b = None
    outcome_b = None
    for subset, outcome_map in subset_to_outcomes.items():
        if len(outcome_map) <= 1:
            continue
        items = list(outcome_map.items())
        witness_subset = tuple(sorted(x[1:].hex() for x in subset))
        outcome_a = items[0][0].hex()
        order_a = items[0][1][0]
        outcome_b = items[1][0].hex()
        order_b = items[1][1][0]
        break

    return FamilyOverlapResult(
        name=name,
        unique_ordered_outcomes=len(outcomes),
        subset_baseline=comb(len(patterns_in_script_order), selection_size),
        max_results_per_unordered_subset=max(len(v) for v in subset_to_outcomes.values()),
        payloads=tuple(payload.hex() for payload in (family_payloads or tuple(pattern[1:] for pattern in patterns_in_script_order))),
        script_perm=tuple(pattern[1:].hex() for pattern in patterns_in_script_order),
        script_hex=script.hex(),
        witness_subset=witness_subset,
        order_a=order_a,
        outcome_a=outcome_a,
        order_b=order_b,
        outcome_b=outcome_b,
    )


def toy_overlap_search() -> ToyOverlapResult:
    alphabet = [1, 2]
    payloads = []
    for length in [1, 2]:
        for tup in product(alphabet, repeat=length):
            payloads.append(bytes(tup))

    best: ToyOverlapResult | None = None
    for chosen in combinations(payloads, 4):
        for script_perm in permutations(chosen):
            script = b"".join(push_data(p) for p in script_perm)
            outcomes = set()
            subset_to_outcomes: dict[frozenset[bytes], dict[bytes, list[tuple[str, ...]]]] = {}
            for sel in permutations(chosen, 2):
                cur = script
                for payload in sel:
                    cur = find_and_delete(cur, payload)
                outcomes.add(cur)
                bucket = subset_to_outcomes.setdefault(frozenset(sel), {})
                bucket.setdefault(cur, []).append(tuple(x.hex() for x in sel))

            max_per_subset = max(len(v) for v in subset_to_outcomes.values())
            if best is not None and (
                len(outcomes),
                max_per_subset,
            ) <= (
                best.unique_ordered_outcomes,
                best.max_results_per_unordered_subset,
            ):
                continue

            witness_subset = None
            order_a = None
            order_b = None
            outcome_a = None
            outcome_b = None
            for subset, outcome_map in subset_to_outcomes.items():
                if len(outcome_map) <= 1:
                    continue
                items = list(outcome_map.items())
                witness_subset = tuple(sorted(x.hex() for x in subset))
                outcome_a = items[0][0].hex()
                order_a = items[0][1][0]
                outcome_b = items[1][0].hex()
                order_b = items[1][1][0]
                break

            if (
                witness_subset is None
                or order_a is None
                or order_b is None
                or outcome_a is None
                or outcome_b is None
            ):
                continue

            best = ToyOverlapResult(
                unique_ordered_outcomes=len(outcomes),
                max_results_per_unordered_subset=max_per_subset,
                payloads=tuple(p.hex() for p in chosen),
                script_perm=tuple(p.hex() for p in script_perm),
                script_hex=script.hex(),
                witness_subset=witness_subset,
                order_a=order_a,
                outcome_a=outcome_a,
                order_b=order_b,
                outcome_b=outcome_b,
            )
    if best is None:
        raise RuntimeError("no toy overlap result found")
    return best


def fixed_length_case_search(name: str, alphabet: tuple[int, ...], payload_length: int) -> FamilyOverlapResult:
    payloads = [bytes(tup) for tup in product(alphabet, repeat=payload_length)]
    best: FamilyOverlapResult | None = None
    for chosen in combinations(payloads, 4):
        chosen_patterns = tuple(push_data(payload) for payload in chosen)
        for script_perm in permutations(chosen_patterns):
            result = analyze_pattern_family(
                name,
                script_perm,
                selection_size=2,
                family_payloads=tuple(sorted(chosen)),
            )
            if best is not None and (
                result.unique_ordered_outcomes,
                result.max_results_per_unordered_subset,
            ) <= (
                best.unique_ordered_outcomes,
                best.max_results_per_unordered_subset,
            ):
                continue
            best = result
    if best is None:
        raise RuntimeError(f"no fixed-length result found for {name}")
    return best


def random_fixed_length_search(
    name: str,
    alphabet: tuple[int, ...],
    payload_length: int,
    trials: int,
    seed: int,
) -> FamilyOverlapResult:
    rng = random.Random(seed)
    best: FamilyOverlapResult | None = None
    for _ in range(trials):
        chosen = set()
        while len(chosen) < 4:
            chosen.add(bytes(rng.choice(alphabet) for _ in range(payload_length)))
        chosen_payloads = tuple(sorted(chosen))
        script_perm = list(chosen_payloads)
        rng.shuffle(script_perm)
        result = analyze_pattern_family(
            name,
            tuple(push_data(payload) for payload in script_perm),
            selection_size=2,
            family_payloads=chosen_payloads,
        )
        if best is not None and (
            result.unique_ordered_outcomes,
            result.max_results_per_unordered_subset,
        ) <= (
            best.unique_ordered_outcomes,
            best.max_results_per_unordered_subset,
        ):
            continue
        best = result
    if best is None:
        raise RuntimeError(f"no random result found for {name}")
    return best


def random_payload_pool_search(
    name: str,
    payload_pool: Sequence[bytes],
    trials: int,
    seed: int,
) -> FamilyOverlapResult:
    rng = random.Random(seed)
    pool = tuple(payload_pool)
    best: FamilyOverlapResult | None = None
    for _ in range(trials):
        chosen_payloads = tuple(sorted(rng.sample(pool, 4)))
        script_perm = list(chosen_payloads)
        rng.shuffle(script_perm)
        result = analyze_pattern_family(
            name,
            tuple(push_data(payload) for payload in script_perm),
            selection_size=2,
            family_payloads=chosen_payloads,
        )
        if best is not None and (
            result.unique_ordered_outcomes,
            result.max_results_per_unordered_subset,
        ) <= (
            best.unique_ordered_outcomes,
            best.max_results_per_unordered_subset,
        ):
            continue
        best = result
    if best is None:
        raise RuntimeError(f"no random pool result found for {name}")
    return best


def all_valid_minimal_der_sigs() -> list[bytes]:
    sigs = []
    for r in _valid_small_r_values():
        for s in range(1, 128):
            sigs.append(_encode_9byte_sig(r, s, sighash=0x03))
    return sigs


def cross_bifix_report(name: str, payloads: list[bytes]) -> SurfaceOverlapResult:
    patterns = [push_data(payload) for payload in payloads]
    token_size = len(patterns[0])
    prefixes: dict[int, dict[bytes, list[int]]] = {
        overlap_len: defaultdict(list) for overlap_len in range(1, token_size)
    }
    for idx, pattern in enumerate(patterns):
        for overlap_len in range(1, token_size):
            prefixes[overlap_len][pattern[:overlap_len]].append(idx)

    max_distinct_overlap = 0
    overlap_a = None
    overlap_b = None
    overlap_len_out = None
    for idx, pattern in enumerate(patterns):
        for overlap_len in range(1, token_size):
            matches = prefixes[overlap_len].get(pattern[-overlap_len:], [])
            distinct_match = next((match for match in matches if match != idx), None)
            if distinct_match is None:
                continue
            if overlap_len > max_distinct_overlap:
                max_distinct_overlap = overlap_len
                overlap_a = pattern.hex()
                overlap_b = patterns[distinct_match].hex()
                overlap_len_out = overlap_len

    return SurfaceOverlapResult(
        name=name,
        surface_size=len(payloads),
        token_size=token_size,
        cross_bifix_free=max_distinct_overlap == 0,
        max_distinct_overlap=max_distinct_overlap,
        overlap_a=overlap_a,
        overlap_b=overlap_b,
        overlap_len=overlap_len_out,
    )


def qsb_pair_probe() -> QSBProbeResult:
    builder = QSBScriptBuilder(n=150, t1_signed=8, t1_bonus=1, t2_signed=7, t2_bonus=2)
    builder.generate_keys()
    round_script = builder.build_round_script(0, bytes.fromhex("30" + "44" + "22" * 68))
    patterns = [push_data(sig) for sig in builder.dummy_sigs[0]]
    seen = set()
    for i, j in permutations(range(len(patterns)), 2):
        cur = round_script.replace(patterns[i], b"")
        cur = cur.replace(patterns[j], b"")
        seen.add(hashlib.sha256(cur).digest())
    ordered = len(patterns) * (len(patterns) - 1)
    target = comb(len(patterns), 2)
    return QSBProbeResult(
        name="qsb_configA_round1_pairs_n150",
        ordered_queries=ordered,
        unique_scriptcodes=len(seen),
        subset_target=target,
        multiplicity=ordered // len(seen),
    )


def qsb_triple_probe(n: int) -> QSBProbeResult:
    builder = QSBScriptBuilder(n=n, t1_signed=8, t1_bonus=0, t2_signed=8, t2_bonus=0)
    builder.generate_keys()
    round_script = builder.build_round_script(0, bytes.fromhex("30" + "44" + "22" * 68))
    patterns = [push_data(sig) for sig in builder.dummy_sigs[0][:n]]
    seen = set()
    for i, j, k in permutations(range(len(patterns)), 3):
        cur = round_script.replace(patterns[i], b"")
        cur = cur.replace(patterns[j], b"")
        cur = cur.replace(patterns[k], b"")
        seen.add(hashlib.sha256(cur).digest())
    ordered = n * (n - 1) * (n - 2)
    target = comb(n, 3)
    return QSBProbeResult(
        name=f"qsb_baseline_round1_triples_n{n}",
        ordered_queries=ordered,
        unique_scriptcodes=len(seen),
        subset_target=target,
        multiplicity=ordered // len(seen),
    )


def print_family_result(result: FamilyOverlapResult) -> None:
    print(f"# {result.name}")
    print(f"unique_ordered_outcomes: {result.unique_ordered_outcomes}")
    print(f"unordered_subset_baseline: {result.subset_baseline}")
    print(f"max_results_per_unordered_subset: {result.max_results_per_unordered_subset}")
    print(f"payloads: {list(result.payloads)}")
    print(f"script_perm: {list(result.script_perm)}")
    print(f"script_hex: {result.script_hex}")
    if result.witness_subset is not None:
        print(f"witness_subset: {list(result.witness_subset)}")
        print(f"order_a: {list(result.order_a or ())}")
        print(f"outcome_a: {result.outcome_a}")
        print(f"order_b: {list(result.order_b or ())}")
        print(f"outcome_b: {result.outcome_b}")


def print_surface_result(result: SurfaceOverlapResult) -> None:
    print(f"# {result.name}")
    print(f"surface_size: {result.surface_size}")
    print(f"token_size: {result.token_size}")
    print(f"cross_bifix_free: {str(result.cross_bifix_free).lower()}")
    print(f"max_distinct_overlap: {result.max_distinct_overlap}")
    if result.overlap_a is not None and result.overlap_b is not None and result.overlap_len is not None:
        print(f"overlap_a: {result.overlap_a}")
        print(f"overlap_b: {result.overlap_b}")
        print(f"overlap_len: {result.overlap_len}")


def main() -> None:
    arbitrary_fixed9 = random_fixed_length_search(
        "arbitrary_fixed9_random",
        (1, 2, 9),
        9,
        trials=50_000,
        seed=20_260_424,
    )
    valid_minimal_der = random_payload_pool_search(
        "valid_minimal_der_random",
        all_valid_minimal_der_sigs(),
        trials=200_000,
        seed=20_260_424,
    )

    toy = toy_overlap_search()
    print("# toy-overlap-search")
    print(f"unique_ordered_outcomes: {toy.unique_ordered_outcomes}")
    print(f"unordered_subset_baseline: {comb(4, 2)}")
    print(f"max_results_per_unordered_subset: {toy.max_results_per_unordered_subset}")
    print(f"payloads: {list(toy.payloads)}")
    print(f"script_perm: {list(toy.script_perm)}")
    print(f"script_hex: {toy.script_hex}")
    print(f"witness_subset: {list(toy.witness_subset)}")
    print(f"order_a: {list(toy.order_a)}")
    print(f"outcome_a: {toy.outcome_a}")
    print(f"order_b: {list(toy.order_b)}")
    print(f"outcome_b: {toy.outcome_b}")

    for result in [
        fixed_length_case_search("fixed_binary_len2", (1, 2), 2),
        fixed_length_case_search("fixed_binary_len3", (1, 2), 3),
        fixed_length_case_search("fixed_binary_len4", (1, 2), 4),
        fixed_length_case_search("fixed_ternary_len2", (1, 2, 3), 2),
        fixed_length_case_search("fixed_ternary_len3", (1, 2, 3), 3),
        arbitrary_fixed9,
        valid_minimal_der,
    ]:
        print()
        print_family_result(result)

    for result in [
        cross_bifix_report(
            "arbitrary_fixed9_best_cross_bifix",
            [bytes.fromhex(hex_payload) for hex_payload in arbitrary_fixed9.payloads],
        ),
        cross_bifix_report("valid_minimal_der_surface", all_valid_minimal_der_sigs()),
    ]:
        print()
        print_surface_result(result)

    for probe in [qsb_pair_probe(), qsb_triple_probe(20), qsb_triple_probe(50)]:
        print()
        print(f"# {probe.name}")
        print(f"ordered_queries: {probe.ordered_queries}")
        print(f"unique_scriptcodes: {probe.unique_scriptcodes}")
        print(f"subset_target: {probe.subset_target}")
        print(f"multiplicity: {probe.multiplicity}")


if __name__ == "__main__":
    main()
