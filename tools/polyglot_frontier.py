#!/usr/bin/env python3
"""
Model the polyglot-digest frontier under current QSB-style Bitcoin limits.

This follows frontier-13. DER-shaped selectable blobs look close to exhausted,
so the next promising branch is the polyglot digest optimization described in
the upstream QSB paper:

- grind a preimage P_i such that HASH160(P_i) is a valid DER signature,
- use HASH160(P_i) as the hardcoded selectable element,
- use P_i as the revealed HORS preimage.

This merges the commitment and dummy signature into one element. The question
here is not FindAndDelete expressivity. It is whether the byte/op savings
materially reopen the security frontier under the same 201-opcode / 10,000-byte
budget.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import lgamma, log, log2
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
UPSTREAM_PIPELINE = ROOT / "third_party" / "qsb-avihu" / "pipeline"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
if str(UPSTREAM_PIPELINE) not in sys.path:
    sys.path.insert(0, str(UPSTREAM_PIPELINE))

from bitcoin_tx import push_number  # type: ignore
from frontier_model import calibrate_qsb_configs  # type: ignore


MAX_SCRIPT_BYTES = 10_000
MAX_OPS = 201
PINNING_BYTES = 76
PINNING_BITS = 46.4


def log2_binom(n: int, k: int) -> float:
    if k < 0 or k > n:
        raise ValueError(f"invalid binomial parameters: n={n}, k={k}")
    return (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)) / log(2)


def polyglot_round_ops(signed: int, bonus: int) -> int:
    # Signed selections save two non-push opcodes relative to QSB because the
    # same hardcoded element serves as both commitment and dummy signature.
    return 9 * signed + 5 * bonus + 8


def polyglot_round_bytes_exact(
    n: int,
    signed: int,
    bonus: int,
    sig_len: int,
) -> int:
    t_total = signed + bonus
    total = 0
    total += n * 21  # one 20-byte polyglot element plus its minimal push
    total += 1  # OP_0
    total += 1 + sig_len  # sig_nonce push

    # Signed selection:
    #   idx ROLL, sanitize MIN, ROLL polyglot, DUP, preimage ROLL, HASH160, EQUALVERIFY
    for i in range(signed):
        idx_pos = n + 1 - i
        sanitize = n - i
        preimage_pos = n + 1 + t_total - i
        total += len(push_number(idx_pos))
        total += 1  # OP_ROLL
        total += len(push_number(sanitize))
        total += 1  # OP_MIN
        total += 1  # OP_ROLL
        total += 1  # OP_DUP
        total += len(push_number(preimage_pos))
        total += 1  # OP_ROLL
        total += 1  # OP_HASH160
        total += 1  # OP_EQUALVERIFY

    # Bonus selection keeps the same 3-op shape as current QSB.
    for i in range(bonus):
        j = signed + i
        idx_pos = n + 1 - j
        sanitize = n - j
        total += len(push_number(idx_pos))
        total += 1  # OP_ROLL
        total += len(push_number(sanitize))
        total += 1  # OP_MIN
        total += 1  # OP_ROLL

    # Puzzle and CHECKMULTISIG section with one hardcoded zone instead of two.
    puzzle_pos = n + 2
    total += len(push_number(puzzle_pos))
    total += 1  # OP_ROLL
    total += 1  # OP_DUP
    total += 1  # OP_RIPEMD160
    total += len(push_number(puzzle_pos))
    total += 1  # OP_ROLL
    total += 1  # OP_CHECKSIGVERIFY

    m = t_total + 1
    total += len(push_number(m))
    total += 1  # OP_2
    total += 1  # OP_ROLL
    cms_roll_pos = n + 3
    for _ in range(t_total):
        total += len(push_number(cms_roll_pos))
        total += 1  # OP_ROLL
    total += len(push_number(m))
    total += 1  # OP_CHECKMULTISIG
    return total


@dataclass(frozen=True)
class PolyglotPoint:
    n: int
    t1_signed: int
    t1_bonus: int
    t2_signed: int
    t2_bonus: int
    total_ops: int
    full_script_bytes: int
    signed_digest_bits: float
    subset_search_bits: float

    @property
    def trusted_setup_bits(self) -> float:
        # Two rounds, n polyglot elements each. This is a one-time trusted
        # grinding cost over HASH160, not a per-spend search cost.
        return PINNING_BITS + log2(2 * self.n)

    @property
    def second_preimage_bits(self) -> float:
        return PINNING_BITS + self.signed_digest_bits

    @property
    def collision_bits(self) -> float:
        return PINNING_BITS + self.signed_digest_bits / 2


def make_point(n: int, t1_signed: int, t1_bonus: int, t2_signed: int, t2_bonus: int) -> PolyglotPoint:
    total_ops = (
        5
        + polyglot_round_ops(t1_signed, t1_bonus)
        + polyglot_round_ops(t2_signed, t2_bonus)
    )
    full_script_bytes = (
        PINNING_BYTES
        + polyglot_round_bytes_exact(n, t1_signed, t1_bonus, 70)
        + polyglot_round_bytes_exact(n, t2_signed, t2_bonus, 71)
    )
    return PolyglotPoint(
        n=n,
        t1_signed=t1_signed,
        t1_bonus=t1_bonus,
        t2_signed=t2_signed,
        t2_bonus=t2_bonus,
        total_ops=total_ops,
        full_script_bytes=full_script_bytes,
        signed_digest_bits=log2_binom(n, t1_signed) + log2_binom(n, t2_signed),
        subset_search_bits=log2_binom(n, t1_signed + t1_bonus) + log2_binom(n, t2_signed + t2_bonus),
    )


def fits(point: PolyglotPoint) -> bool:
    return point.total_ops <= MAX_OPS and point.full_script_bytes <= MAX_SCRIPT_BYTES


def best_symmetric_point(t: int, max_n: int = 260) -> PolyglotPoint:
    best: PolyglotPoint | None = None
    for n in range(t, max_n + 1):
        point = make_point(n, t, 0, t, 0)
        if not fits(point):
            continue
        best = point
    if best is None:
        raise RuntimeError(f"no symmetric polyglot point found for t={t}")
    return best


def min_n_for_round_target(t: int, round_target_bits: float = PINNING_BITS) -> PolyglotPoint:
    n = t
    while True:
        point = make_point(n, t, 0, t, 0)
        if fits(point) and log2_binom(n, t) >= round_target_bits:
            return point
        n += 1


def best_polyglot_point(max_n: int = 260) -> PolyglotPoint:
    best: PolyglotPoint | None = None
    for t1 in range(1, 20):
        for t2 in range(1, 20):
            for n in range(max(t1, t2), max_n + 1):
                point = make_point(n, t1, 0, t2, 0)
                if not fits(point):
                    continue
                if best is None or (
                    point.signed_digest_bits,
                    point.subset_search_bits,
                    -point.full_script_bytes,
                ) > (
                    best.signed_digest_bits,
                    best.subset_search_bits,
                    -best.full_script_bytes,
                ):
                    best = point
    if best is None:
        raise RuntimeError("no feasible polyglot point found")
    return best


def render_reference_qsb() -> str:
    lines = ["# reference-qsb"]
    for entry in calibrate_qsb_configs():
        lines.extend(
            [
                "",
                f"name: {entry.config.name}",
                f"bytes: {entry.full_script_bytes}",
                f"ops: {entry.total_ops}",
                f"signed_bits: {entry.signed_digest_bits:.2f}",
                f"subset_bits: {entry.subset_search_bits:.2f}",
            ]
        )
    return "\n".join(lines)


def render_polyglot_frontier() -> str:
    same_n_ten_ten = make_point(150, 10, 0, 10, 0)
    if not fits(same_n_ten_ten):
        raise RuntimeError("same-n 10/10 polyglot point unexpectedly does not fit")

    max_point = best_polyglot_point()
    symmetric_8 = best_symmetric_point(8)
    symmetric_9 = best_symmetric_point(9)
    symmetric_10 = best_symmetric_point(10)
    min_target_8 = min_n_for_round_target(8)
    min_target_9 = min_n_for_round_target(9)
    min_target_10 = min_n_for_round_target(10)

    def fmt(point: PolyglotPoint) -> str:
        return (
            f"n={point.n} r1={point.t1_signed}+{point.t1_bonus}b "
            f"r2={point.t2_signed}+{point.t2_bonus}b "
            f"ops={point.total_ops} bytes={point.full_script_bytes} "
            f"signed_bits={point.signed_digest_bits:.2f} subset_bits={point.subset_search_bits:.2f} "
            f"setup_bits={point.trusted_setup_bits:.2f}"
        )

    lines = [
        "# polyglot-frontier",
        "",
        "same_n_150_ten_ten:",
        f"  {fmt(same_n_ten_ten)}",
        f"  second_preimage_bits={same_n_ten_ten.second_preimage_bits:.2f}",
        f"  collision_bits={same_n_ten_ten.collision_bits:.2f}",
        "",
        "max_signed_point_under_limits:",
        f"  {fmt(max_point)}",
        f"  second_preimage_bits={max_point.second_preimage_bits:.2f}",
        f"  collision_bits={max_point.collision_bits:.2f}",
        "",
        "best_symmetric_points:",
        f"  t=8: {fmt(symmetric_8)}",
        f"  t=9: {fmt(symmetric_9)}",
        f"  t=10: {fmt(symmetric_10)}",
        "",
        "minimum_n_to_clear_round_target_46p4_bits:",
        f"  t=8: {fmt(min_target_8)}",
        f"  t=9: {fmt(min_target_9)}",
        f"  t=10: {fmt(min_target_10)}",
    ]
    return "\n".join(lines)


def main() -> None:
    print(render_reference_qsb())
    print()
    print(render_polyglot_frontier())


if __name__ == "__main__":
    main()
