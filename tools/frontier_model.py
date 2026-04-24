#!/usr/bin/env python3
"""
Calibrated frontier model for no-softfork hash-based Bitcoin spend constructions.

This tool now does three things:

1. Calibrates the public QSB baseline against the imported upstream builder.
2. Compares HORS-style subset entropy with grouped-choice under the same option
   and reveal budgets.
3. Shows an optimistic tree-style control to clarify that the real blocker for
   modern limited-use hash signatures on Bitcoin is Script expressivity, not
   just high-level signature design.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import permutations
from math import ceil, lgamma, log, log2
from pathlib import Path
from typing import Iterable
import sys


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_PIPELINE = ROOT / "third_party" / "qsb-avihu" / "pipeline"
_QSB_PRIMITIVES: tuple[object, object, object] | None = None


def log2_binom(n: int, k: int) -> float:
    if k < 0 or k > n:
        raise ValueError(f"invalid binomial parameters: n={n}, k={k}")
    return (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)) / log(2)


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def grouped_choice_max_bits(total_options: int, reveals: int) -> float:
    if reveals <= 0:
        raise ValueError("reveals must be positive")
    base = total_options / reveals
    if base <= 1:
        return 0.0
    return reveals * log2(base)


def required_grouped_options(target_bits: float, reveals: int) -> int:
    if reveals <= 0:
        raise ValueError("reveals must be positive")
    return ceil(reveals * (2 ** (target_bits / reveals)))


def per_choice_static_bytes(commitment_len: int = 20, dummy_sig_len: int = 9) -> int:
    # In the upstream builder, these choices are hardcoded directly into the
    # locking script using minimal pushes.
    return (1 + commitment_len) + (1 + dummy_sig_len)


def sig_of_len(total_len: int, fill: int) -> bytes:
    if total_len < 2:
        raise ValueError("signature length must be at least 2 bytes")
    return bytes([0x30, total_len - 2]) + bytes([fill]) * (total_len - 2)


@dataclass(frozen=True)
class QSBConfig:
    name: str
    n: int
    t1_signed: int
    t1_bonus: int
    t2_signed: int
    t2_bonus: int


@dataclass(frozen=True)
class QSBMetrics:
    config: QSBConfig
    pinning_bytes: int
    round1_bytes: int
    round2_bytes: int
    full_script_bytes: int
    total_ops: int
    signed_digest_bits: float
    subset_search_bits: float

    @property
    def static_choice_bytes(self) -> int:
        return self.config.n * per_choice_static_bytes() * 2


@dataclass(frozen=True)
class GroupedChoiceComparison:
    reveals: int
    baseline_options: int
    target_bits: float
    grouped_max_bits_same_options: float
    required_options_to_match: int

    @property
    def entropy_gap_bits(self) -> float:
        return self.target_bits - self.grouped_max_bits_same_options

    @property
    def option_multiplier(self) -> float:
        return self.required_options_to_match / self.baseline_options

    @property
    def required_static_bytes(self) -> int:
        return self.required_options_to_match * per_choice_static_bytes()


@dataclass(frozen=True)
class OptimisticTreeControl:
    reveals: int
    target_bits: float
    leaves_per_tree: int
    depth: int
    total_root_bytes: int
    optimistic_witness_path_bytes: int
    optimistic_hash_steps: int


@dataclass(frozen=True)
class GroupedChoiceFrontierPoint:
    reveals_round1: int
    reveals_round2: int
    options_round1: int
    options_round2: int
    total_ops: int
    estimated_script_bytes: int
    digest_bits: float


def load_qsb_builder():
    global _QSB_PRIMITIVES
    if _QSB_PRIMITIVES is not None:
        return _QSB_PRIMITIVES
    if not UPSTREAM_PIPELINE.exists():
        raise FileNotFoundError(f"missing upstream pipeline at {UPSTREAM_PIPELINE}")
    sys.path.insert(0, str(UPSTREAM_PIPELINE))
    from bitcoin_tx import QSBScriptBuilder, push_data, push_number  # type: ignore
    _QSB_PRIMITIVES = (QSBScriptBuilder, push_data, push_number)
    return _QSB_PRIMITIVES


def qsb_total_ops(cfg: QSBConfig) -> int:
    def round_ops(signed: int, bonus: int) -> int:
        # Upstream script accounting:
        #   signed selection: 9
        #   bonus selection: 3
        #   puzzle prelude: 3
        #   CHECKMULTISIG section: 2 * (t_total) + 5
        # => 11*signed + 5*bonus + 8
        return 11 * signed + 5 * bonus + 8

    return 5 + round_ops(cfg.t1_signed, cfg.t1_bonus) + round_ops(cfg.t2_signed, cfg.t2_bonus)


def qsb_signed_digest_bits(cfg: QSBConfig) -> float:
    return log2_binom(cfg.n, cfg.t1_signed) + log2_binom(cfg.n, cfg.t2_signed)


def qsb_subset_search_bits(cfg: QSBConfig) -> float:
    t1 = cfg.t1_signed + cfg.t1_bonus
    t2 = cfg.t2_signed + cfg.t2_bonus
    return log2_binom(cfg.n, t1) + log2_binom(cfg.n, t2)


def calibrate_qsb_configs() -> list[QSBMetrics]:
    builder_cls, _, _ = load_qsb_builder()
    configs = [
        QSBConfig("baseline_8_8", n=150, t1_signed=8, t1_bonus=0, t2_signed=8, t2_bonus=0),
        QSBConfig("configA_8p1b_7p2b", n=150, t1_signed=8, t1_bonus=1, t2_signed=7, t2_bonus=2),
        QSBConfig("alt_8p1b_8", n=150, t1_signed=8, t1_bonus=1, t2_signed=8, t2_bonus=0),
    ]

    pin_sig = sig_of_len(70, 0x11)
    round1_sig = sig_of_len(70, 0x22)
    round2_sig = sig_of_len(71, 0x33)

    results: list[QSBMetrics] = []
    for cfg in configs:
        builder = builder_cls(
            n=cfg.n,
            t1_signed=cfg.t1_signed,
            t1_bonus=cfg.t1_bonus,
            t2_signed=cfg.t2_signed,
            t2_bonus=cfg.t2_bonus,
        )
        builder.generate_keys()
        pinning = builder.build_pinning_script(pin_sig)
        round1 = builder.build_round_script(0, round1_sig)
        round2 = builder.build_round_script(1, round2_sig)
        full = builder.build_full_script(pin_sig, round1_sig, round2_sig)
        results.append(
            QSBMetrics(
                config=cfg,
                pinning_bytes=len(pinning),
                round1_bytes=len(round1),
                round2_bytes=len(round2),
                full_script_bytes=len(full),
                total_ops=qsb_total_ops(cfg),
                signed_digest_bits=qsb_signed_digest_bits(cfg),
                subset_search_bits=qsb_subset_search_bits(cfg),
            )
        )
    return results


def qsb_round_bytes_exact(
    n: int,
    t_signed: int,
    t_bonus: int,
    sig_len: int,
) -> int:
    _, push_data, push_number = load_qsb_builder()
    t_total = t_signed + t_bonus
    total = 0
    total += n * len(push_data(b"\x00" * 20))
    total += n * len(push_data(b"\x00" * 9))
    total += 1  # OP_0
    total += len(push_data(b"\x11" * sig_len))

    for i in range(t_signed):
        idx_pos = 2 * n + 1 - i
        sanitize = n - i
        preimage_pos = 2 * n + 1 + t_total - 2 * i
        total += len(push_number(idx_pos))
        total += 1  # OP_ROLL
        total += len(push_number(sanitize))
        total += 1  # OP_MIN
        total += 1  # OP_DUP
        total += len(push_number(n + 1))
        total += 1  # OP_ADD
        total += 1  # OP_ROLL
        total += len(push_number(preimage_pos))
        total += 1  # OP_ROLL
        total += 1  # OP_HASH160
        total += 1  # OP_EQUALVERIFY
        total += 1  # OP_ROLL

    for i in range(t_bonus):
        j = t_signed + i
        idx_pos = 2 * n + 1 - j
        sanitize = n - j
        total += len(push_number(idx_pos))
        total += 1  # OP_ROLL
        total += len(push_number(sanitize))
        total += 1  # OP_MIN
        total += 1  # OP_ROLL

    puzzle_pos = 2 * n + 2
    puzzle_key_pos = puzzle_pos
    total += len(push_number(puzzle_pos))
    total += 1  # OP_ROLL
    total += 1  # OP_DUP
    total += 1  # OP_RIPEMD160
    total += len(push_number(puzzle_key_pos))
    total += 1  # OP_ROLL
    total += 1  # OP_CHECKSIGVERIFY

    m = t_total + 1
    total += len(push_number(m))
    total += 1  # OP_2
    total += 1  # OP_ROLL
    cms_roll_pos = 2 * n + 3
    for _ in range(t_total):
        total += len(push_number(cms_roll_pos))
        total += 1  # OP_ROLL
    total += len(push_number(m))
    total += 1  # OP_CHECKMULTISIG
    return total


def qsb_full_script_bytes_exact(cfg: QSBConfig) -> int:
    _, push_data, _ = load_qsb_builder()
    pinning = len(push_data(sig_of_len(70, 0x11))) + 5
    return (
        pinning
        + qsb_round_bytes_exact(cfg.n, cfg.t1_signed, cfg.t1_bonus, 70)
        + qsb_round_bytes_exact(cfg.n, cfg.t2_signed, cfg.t2_bonus, 71)
    )


def validate_exact_byte_model() -> list[str]:
    lines: list[str] = []
    for measured in calibrate_qsb_configs():
        exact = qsb_full_script_bytes_exact(measured.config)
        status = "ok" if exact == measured.full_script_bytes else "mismatch"
        lines.append(
            f"{measured.config.name}: measured={measured.full_script_bytes} exact={exact} status={status}"
        )
    return lines


def grouped_choice_comparison(total_options: int, reveals: int, target_bits: float) -> GroupedChoiceComparison:
    return GroupedChoiceComparison(
        reveals=reveals,
        baseline_options=total_options,
        target_bits=target_bits,
        grouped_max_bits_same_options=grouped_choice_max_bits(total_options, reveals),
        required_options_to_match=required_grouped_options(target_bits, reveals),
    )


def optimistic_tree_control(reveals: int, target_bits: float) -> OptimisticTreeControl:
    leaves = ceil(2 ** (target_bits / reveals))
    depth = ceil(log2(leaves))
    return OptimisticTreeControl(
        reveals=reveals,
        target_bits=target_bits,
        leaves_per_tree=leaves,
        depth=depth,
        total_root_bytes=reveals * 20,
        optimistic_witness_path_bytes=reveals * depth * 20,
        optimistic_hash_steps=reveals * depth,
    )


@dataclass(frozen=True)
class HorsSweepPoint:
    config: QSBConfig
    full_script_bytes: int
    total_ops: int
    signed_digest_bits: float
    subset_search_bits: float


def iter_feasible_round_configs(max_round_cost: int = 188) -> list[tuple[int, int, int]]:
    round_configs: list[tuple[int, int, int]] = []
    for signed in range(0, 18):
        bonus = 0
        while True:
            cost = 11 * signed + 5 * bonus + 8
            if cost > max_round_cost:
                break
            round_configs.append((signed, bonus, cost))
            bonus += 1
    return round_configs


def iter_hors_family_points(max_n: int = 170, max_script_bytes: int = 10_000, max_ops: int = 201):
    round_configs = iter_feasible_round_configs()
    for n in range(1, max_n + 1):
        round_metrics: list[tuple[int, int, int, float, float, int, int]] = []
        for signed, bonus, cost in round_configs:
            if signed + bonus == 0:
                continue
            if signed > n or signed + bonus > n:
                continue
            round_metrics.append(
                (
                    signed,
                    bonus,
                    cost,
                    log2_binom(n, signed),
                    log2_binom(n, signed + bonus),
                    qsb_round_bytes_exact(n, signed, bonus, 70),
                    qsb_round_bytes_exact(n, signed, bonus, 71),
                )
            )
        for s1, b1, cost1, signed1_bits, subset1_bits, round1_bytes, _ in round_metrics:
            for s2, b2, cost2, signed2_bits, subset2_bits, _, round2_bytes in round_metrics:
                total_ops = 5 + cost1 + cost2
                if total_ops > max_ops:
                    continue
                cfg = QSBConfig(
                    name=f"n={n}|r1={s1}+{b1}b|r2={s2}+{b2}b",
                    n=n,
                    t1_signed=s1,
                    t1_bonus=b1,
                    t2_signed=s2,
                    t2_bonus=b2,
                )
                full_bytes = 76 + round1_bytes + round2_bytes
                if full_bytes > max_script_bytes:
                    continue
                yield HorsSweepPoint(
                    config=cfg,
                    full_script_bytes=full_bytes,
                    total_ops=total_ops,
                    signed_digest_bits=signed1_bits + signed2_bits,
                    subset_search_bits=subset1_bits + subset2_bits,
                )


def update_top_points(
    current: list[HorsSweepPoint],
    point: HorsSweepPoint,
    *,
    sort_key,
    limit: int = 10,
) -> list[HorsSweepPoint]:
    current.append(point)
    current.sort(key=sort_key)
    del current[limit:]
    return current


def probe_order_invariance(n: int, t: int) -> tuple[int, int, int]:
    builder_cls, _, _ = load_qsb_builder()
    builder = builder_cls(n=n, t1_signed=t, t1_bonus=0, t2_signed=t, t2_bonus=0)
    builder.generate_keys()
    sig = sig_of_len(70, 0x22)
    codes: dict[bytes, int] = {}
    for ordered in permutations(range(n), t):
        selected = [builder.dummy_sigs[0][idx] for idx in ordered]
        code = builder.get_round_script_code(0, sig, selected)
        codes[code] = codes.get(code, 0) + 1
    multiplicities = set(codes.values())
    multiplicity = multiplicities.pop() if len(multiplicities) == 1 else -1
    return len(list(permutations(range(n), t))), len(codes), multiplicity


def optimistic_grouped_choice_bytes(
    options_round1: int,
    options_round2: int,
    reveals_round1: int,
    reveals_round2: int,
) -> int:
    pinning = 76
    # Calibrated from the all-signed upstream baseline:
    # round bytes ~= static choices + 184 fixed bytes + 13 bytes per signed reveal.
    round1 = per_choice_static_bytes() * options_round1 + 184 + 13 * reveals_round1
    round2 = per_choice_static_bytes() * options_round2 + 184 + 13 * reveals_round2
    return pinning + round1 + round2


def optimistic_grouped_choice_ops(reveals_round1: int, reveals_round2: int) -> int:
    # Reuse the upstream QSB round accounting with zero bonus slots.
    cfg = QSBConfig(
        name="optimistic_grouped",
        n=0,
        t1_signed=reveals_round1,
        t1_bonus=0,
        t2_signed=reveals_round2,
        t2_bonus=0,
    )
    return qsb_total_ops(cfg)


def search_grouped_choice_frontier(
    max_script_bytes: int = 10_000,
    max_ops: int = 201,
) -> GroupedChoiceFrontierPoint:
    best: GroupedChoiceFrontierPoint | None = None
    for g1 in range(1, 17):
        for g2 in range(1, 17):
            ops = optimistic_grouped_choice_ops(g1, g2)
            if ops > max_ops:
                continue
            for m1 in range(g1, 401):
                # Early prune using the smallest possible round 2.
                min_bytes = optimistic_grouped_choice_bytes(m1, g2, g1, g2)
                if min_bytes > max_script_bytes:
                    break
                for m2 in range(g2, 401):
                    est_bytes = optimistic_grouped_choice_bytes(m1, m2, g1, g2)
                    if est_bytes > max_script_bytes:
                        break
                    bits = grouped_choice_max_bits(m1, g1) + grouped_choice_max_bits(m2, g2)
                    point = GroupedChoiceFrontierPoint(
                        reveals_round1=g1,
                        reveals_round2=g2,
                        options_round1=m1,
                        options_round2=m2,
                        total_ops=ops,
                        estimated_script_bytes=est_bytes,
                        digest_bits=bits,
                    )
                    if best is None or point.digest_bits > best.digest_bits:
                        best = point
    if best is None:
        raise RuntimeError("no grouped-choice frontier point found")
    return best


def render_qsb_metrics(metrics: Iterable[QSBMetrics]) -> str:
    lines = ["# calibrated-qsb-baseline"]
    for entry in metrics:
        lines.extend(
            [
                "",
                f"name: {entry.config.name}",
                f"n: {entry.config.n}",
                f"rounds: ({entry.config.t1_signed}+{entry.config.t1_bonus}b, {entry.config.t2_signed}+{entry.config.t2_bonus}b)",
                f"pinning_bytes: {entry.pinning_bytes}",
                f"round1_bytes: {entry.round1_bytes}",
                f"round2_bytes: {entry.round2_bytes}",
                f"full_script_bytes: {entry.full_script_bytes}",
                f"total_ops: {entry.total_ops}",
                f"signed_digest_bits: {entry.signed_digest_bits:.2f}",
                f"subset_search_bits: {entry.subset_search_bits:.2f}",
                f"static_choice_bytes: {entry.static_choice_bytes}",
            ]
        )
    return "\n".join(lines)


def render_structural_comparisons() -> str:
    baseline_round = grouped_choice_comparison(total_options=150, reveals=8, target_bits=log2_binom(150, 8))
    config_a_round2 = grouped_choice_comparison(total_options=150, reveals=7, target_bits=log2_binom(150, 7))
    tree = optimistic_tree_control(reveals=8, target_bits=log2_binom(150, 8))
    frontier = search_grouped_choice_frontier()

    lines = [
        "# structural-comparisons",
        "",
        "hors_round_baseline:",
        f"  target_bits: {baseline_round.target_bits:.2f}",
        f"  grouped_max_bits_same_150_options: {baseline_round.grouped_max_bits_same_options:.2f}",
        f"  grouped_entropy_gap_bits: {baseline_round.entropy_gap_bits:.2f}",
        f"  grouped_required_options_to_match: {baseline_round.required_options_to_match}",
        f"  grouped_option_multiplier: {baseline_round.option_multiplier:.2f}",
        f"  grouped_required_static_bytes: {baseline_round.required_static_bytes}",
        "",
        "configA_round2_baseline:",
        f"  target_bits: {config_a_round2.target_bits:.2f}",
        f"  grouped_max_bits_same_150_options: {config_a_round2.grouped_max_bits_same_options:.2f}",
        f"  grouped_entropy_gap_bits: {config_a_round2.entropy_gap_bits:.2f}",
        f"  grouped_required_options_to_match: {config_a_round2.required_options_to_match}",
        f"  grouped_option_multiplier: {config_a_round2.option_multiplier:.2f}",
        f"  grouped_required_static_bytes: {config_a_round2.required_static_bytes}",
        "",
        "optimistic_grouped_choice_frontier_under_qsb_limits:",
        f"  reveals_round1: {frontier.reveals_round1}",
        f"  reveals_round2: {frontier.reveals_round2}",
        f"  options_round1: {frontier.options_round1}",
        f"  options_round2: {frontier.options_round2}",
        f"  total_ops: {frontier.total_ops}",
        f"  estimated_script_bytes: {frontier.estimated_script_bytes}",
        f"  digest_bits: {frontier.digest_bits:.2f}",
        "",
        "optimistic_tree_control_for_42bit_round:",
        f"  leaves_per_tree: {tree.leaves_per_tree}",
        f"  depth: {tree.depth}",
        f"  total_root_bytes: {tree.total_root_bytes}",
        f"  optimistic_witness_path_bytes: {tree.optimistic_witness_path_bytes}",
        f"  optimistic_hash_steps: {tree.optimistic_hash_steps}",
    ]
    return "\n".join(lines)


def render_hors_sweep() -> str:
    feasible_points = 0
    best_signed: HorsSweepPoint | None = None
    best_subset: HorsSweepPoint | None = None
    top_signed: list[HorsSweepPoint] = []
    threshold_bests: dict[int, HorsSweepPoint | None] = {80: None, 75: None, 70: None, 60: None}
    for point in iter_hors_family_points():
        feasible_points += 1
        if best_signed is None or (
            point.signed_digest_bits,
            -point.full_script_bytes,
            -point.subset_search_bits,
        ) > (
            best_signed.signed_digest_bits,
            -best_signed.full_script_bytes,
            -best_signed.subset_search_bits,
        ):
            best_signed = point
        if best_subset is None or (
            point.subset_search_bits,
            point.signed_digest_bits,
            -point.full_script_bytes,
        ) > (
            best_subset.subset_search_bits,
            best_subset.signed_digest_bits,
            -best_subset.full_script_bytes,
        ):
            best_subset = point
        update_top_points(
            top_signed,
            point,
            sort_key=lambda p: (
                -p.signed_digest_bits,
                p.full_script_bytes,
                p.total_ops,
                -p.subset_search_bits,
            ),
        )
        for threshold in threshold_bests:
            if point.signed_digest_bits < threshold:
                continue
            current = threshold_bests[threshold]
            if current is None or (
                point.subset_search_bits,
                point.signed_digest_bits,
                -point.full_script_bytes,
            ) > (
                current.subset_search_bits,
                current.signed_digest_bits,
                -current.full_script_bytes,
            ):
                threshold_bests[threshold] = point
    if best_signed is None or best_subset is None:
        raise RuntimeError("no feasible HORS-family points found")
    top_signed = sorted(
        top_signed,
        key=lambda p: (-p.signed_digest_bits, p.full_script_bytes, p.total_ops, -p.subset_search_bits),
    )
    exact_validation = validate_exact_byte_model()
    probe_6_3 = probe_order_invariance(6, 3)
    probe_7_3 = probe_order_invariance(7, 3)

    def fmt(point: HorsSweepPoint) -> str:
        cfg = point.config
        return (
            f"n={cfg.n} r1={cfg.t1_signed}+{cfg.t1_bonus}b r2={cfg.t2_signed}+{cfg.t2_bonus}b "
            f"bytes={point.full_script_bytes} ops={point.total_ops} "
            f"signed_bits={point.signed_digest_bits:.2f} subset_bits={point.subset_search_bits:.2f}"
        )

    lines = [
        "# hors-family-sweep",
        f"feasible_points: {feasible_points}",
        "",
        "exact_byte_validation:",
    ]
    lines.extend([f"  {line}" for line in exact_validation])
    lines.extend(
        [
            "",
            "best_signed_digest_point:",
            f"  {fmt(best_signed)}",
            "",
            "best_subset_search_point_any:",
            f"  {fmt(best_subset)}",
            "",
            "top_signed_digest_points:",
        ]
    )
    for point in top_signed:
        lines.append(f"  {fmt(point)}")
    lines.extend(["", "practical_subset_tradeoff_ladder:"])
    for threshold in sorted(threshold_bests.keys(), reverse=True):
        point = threshold_bests[threshold]
        if point is None:
            lines.append(f"  signed>={threshold}: none")
        else:
            lines.append(f"  signed>={threshold}: {fmt(point)}")
    lines.extend(
        [
            "",
            "order_invariance_probe:",
            f"  n=6,t=3 ordered={probe_6_3[0]} unique_scriptcodes={probe_6_3[1]} multiplicity={probe_6_3[2]}",
            f"  n=7,t=3 ordered={probe_7_3[0]} unique_scriptcodes={probe_7_3[1]} multiplicity={probe_7_3[2]}",
            "",
            "grouped_gap_formula:",
            "  subset beats grouped-choice by approximately r*log2(e) - 0.5*log2(2*pi*r) bits when M >> r.",
            f"  r=8 exact_gap={log2_binom(150, 8) - grouped_choice_max_bits(150, 8):.2f}",
            f"  r=7 exact_gap={log2_binom(150, 7) - grouped_choice_max_bits(150, 7):.2f}",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    calibrated = calibrate_qsb_configs()
    print(render_qsb_metrics(calibrated))
    print()
    print(render_structural_comparisons())
    print()
    print(render_hors_sweep())


if __name__ == "__main__":
    main()
