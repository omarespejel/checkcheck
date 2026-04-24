#!/usr/bin/env python3
"""
Tighten the polyglot frontier with corrected security accounting and setup cost.

This follows frontier-14, which showed that the polyglot digest branch reopens
the byte/op frontier. The next job is stricter:

1. Correct the security accounting to match the upstream QSB paper.
2. Price trusted setup as actual HASH160 work and scenario time.
3. Explore a setup-aware partial-polyglot family.

The partial family studied here is intentionally narrow and explicit:

- signed selections come only from a trusted polyglot pool of size m,
- bonus selections come only from a separate dummy-signature pool of size q,
- bonus entries do not require trusted grinding or HORS commitments,
- the same split-pool round is used in both digest rounds.

This is not a full executable script builder. It is a tighter family model with
exact push-number byte accounting and corrected security metrics.
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

from bitcoin_tx import push_data, push_number  # type: ignore
from frontier_model import QSBConfig, calibrate_qsb_configs  # type: ignore


MAX_SCRIPT_BYTES = 10_000
MAX_OPS = 201
PINNING_BITS = 46.4
PINNING_BYTES = 76
HASHES_PER_ELEMENT = 2**PINNING_BITS
GHASH = 1_000_000_000
TEN_GHASH = 10_000_000_000
SEARCH_CAPS = (128, 160, 192, 224, 256, 300)
MAX_POLY_PER_ROUND = 180
MAX_BONUS_PER_ROUND = 3
MAX_SIGNED_PER_ROUND = 10
COMPRESSED_PUBKEY_PUSH = len(push_data(b"\x02" + b"\x00" * 32))
PREIMAGE_PUSH = len(push_data(b"\x00" * 20))


def log2_binom(n: int, k: int) -> float:
    if k < 0 or k > n:
        raise ValueError(f"invalid binomial parameters: n={n}, k={k}")
    return (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)) / log(2)


def setup_hashes_for(elements: int) -> float:
    return HASHES_PER_ELEMENT * elements


def setup_bits_for(elements: int) -> float:
    return PINNING_BITS + log2(elements)


def days_at_rate(hashes: float, rate_hps: float) -> float:
    return hashes / rate_hps / 86_400


def witness_round_bytes(max_index: int, signed: int, bonus: int) -> int:
    idx_push = len(push_number(max_index))
    t_total = signed + bonus
    return 2 * COMPRESSED_PUBKEY_PUSH + t_total * COMPRESSED_PUBKEY_PUSH + signed * PREIMAGE_PUSH + t_total * idx_push


def total_witness_bytes(
    max_index_round1: int,
    signed_round1: int,
    bonus_round1: int,
    max_index_round2: int,
    signed_round2: int,
    bonus_round2: int,
) -> int:
    return (
        witness_round_bytes(max_index_round2, signed_round2, bonus_round2)
        + witness_round_bytes(max_index_round1, signed_round1, bonus_round1)
        + 2 * COMPRESSED_PUBKEY_PUSH
    )


def reference_bonus_free_bits(cfg: QSBConfig) -> float:
    return log2_binom(cfg.n - cfg.t1_signed, cfg.t1_bonus) + log2_binom(cfg.n - cfg.t2_signed, cfg.t2_bonus)


def reference_assignment_bits(cfg: QSBConfig) -> float:
    t1_total = cfg.t1_signed + cfg.t1_bonus
    t2_total = cfg.t2_signed + cfg.t2_bonus
    return log2_binom(t1_total, cfg.t1_signed) + log2_binom(t2_total, cfg.t2_signed)


@dataclass(frozen=True)
class CorrectedReference:
    name: str
    bytes: int
    ops: int
    signed_digest_bits: float
    subset_search_bits: float
    bonus_free_bits: float
    assignment_bits: float
    second_preimage_bits: float
    collision_bits: float


def corrected_references() -> list[CorrectedReference]:
    refs: list[CorrectedReference] = []
    for metrics in calibrate_qsb_configs():
        cfg = metrics.config
        bonus_free_bits = reference_bonus_free_bits(cfg)
        assignment_bits = reference_assignment_bits(cfg)
        refs.append(
            CorrectedReference(
                name=cfg.name,
                bytes=metrics.full_script_bytes,
                ops=metrics.total_ops,
                signed_digest_bits=metrics.signed_digest_bits,
                subset_search_bits=metrics.subset_search_bits,
                bonus_free_bits=bonus_free_bits,
                assignment_bits=assignment_bits,
                second_preimage_bits=3 * PINNING_BITS - bonus_free_bits,
                collision_bits=PINNING_BITS + metrics.signed_digest_bits / 2 - assignment_bits,
            )
        )
    return refs


def polyglot_round_bytes_exact(
    n: int,
    signed: int,
    sig_len: int,
) -> int:
    total = 0
    total += n * 21
    total += 1
    total += 1 + sig_len

    t_total = signed
    for i in range(signed):
        idx_pos = n + 1 - i
        sanitize = n - i
        preimage_pos = n + 1 + t_total - i
        total += len(push_number(idx_pos))
        total += 1
        total += len(push_number(sanitize))
        total += 1
        total += 1
        total += 1
        total += len(push_number(preimage_pos))
        total += 1
        total += 1
        total += 1

    puzzle_pos = n + 2
    total += len(push_number(puzzle_pos))
    total += 1
    total += 1
    total += 1
    total += len(push_number(puzzle_pos))
    total += 1
    total += 1

    m = t_total + 1
    total += len(push_number(m))
    total += 1
    total += 1
    cms_roll_pos = n + 3
    for _ in range(t_total):
        total += len(push_number(cms_roll_pos))
        total += 1
    total += len(push_number(m))
    total += 1
    return total


@dataclass(frozen=True)
class FullPolyglotPoint:
    n: int
    t1: int
    t2: int
    ops: int
    bytes: int
    signed_digest_bits: float

    @property
    def setup_elements(self) -> int:
        return 2 * self.n

    @property
    def setup_hashes(self) -> float:
        return setup_hashes_for(self.setup_elements)

    @property
    def setup_bits(self) -> float:
        return setup_bits_for(self.setup_elements)

    @property
    def second_preimage_bits(self) -> float:
        return 3 * PINNING_BITS

    @property
    def collision_bits(self) -> float:
        return PINNING_BITS + self.signed_digest_bits / 2

    @property
    def witness_bytes(self) -> int:
        return total_witness_bytes(self.n - 1, self.t1, 0, self.n - 1, self.t2, 0)


def full_polyglot_point(n: int, t1: int, t2: int) -> FullPolyglotPoint:
    ops = 5 + (9 * t1 + 8) + (9 * t2 + 8)
    bytes_ = PINNING_BYTES + polyglot_round_bytes_exact(n, t1, 70) + polyglot_round_bytes_exact(n, t2, 71)
    return FullPolyglotPoint(
        n=n,
        t1=t1,
        t2=t2,
        ops=ops,
        bytes=bytes_,
        signed_digest_bits=log2_binom(n, t1) + log2_binom(n, t2),
    )


def min_bonus_pool_for(target_bits: float, bonus: int, max_q: int = 1_000) -> int | None:
    if bonus == 0:
        return 0 if target_bits <= 0 else None
    q = bonus
    while q <= max_q:
        if log2_binom(q, bonus) >= target_bits:
            return q
        q += 1
    return None


def split_round_bytes_exact(
    poly: int,
    bonus_pool: int,
    signed: int,
    bonus: int,
    sig_len: int,
) -> int:
    t_total = signed + bonus
    total = 0
    total += bonus_pool * 10
    total += poly * 21
    total += 1
    total += 1 + sig_len

    hardcoded = poly + bonus_pool
    for i in range(signed):
        idx_pos = hardcoded + 1 - i
        sanitize = poly - i
        preimage_pos = hardcoded + 1 + t_total - i
        total += len(push_number(idx_pos))
        total += 1
        total += len(push_number(sanitize))
        total += 1
        total += 1
        total += 1
        total += len(push_number(preimage_pos))
        total += 1
        total += 1
        total += 1

    bonus_offset = poly - signed
    for i in range(bonus):
        idx_pos = hardcoded + 1 - signed - i
        sanitize = bonus_pool - i
        total += len(push_number(idx_pos))
        total += 1
        total += len(push_number(sanitize))
        total += 1
        total += len(push_number(bonus_offset))
        total += 1
        total += 1
        total += 1

    puzzle_pos = hardcoded + 2
    total += len(push_number(puzzle_pos))
    total += 1
    total += 1
    total += 1
    total += len(push_number(puzzle_pos))
    total += 1
    total += 1

    m = t_total + 1
    total += len(push_number(m))
    total += 1
    total += 1
    cms_roll_pos = hardcoded + 3
    for _ in range(t_total):
        total += len(push_number(cms_roll_pos))
        total += 1
    total += len(push_number(m))
    total += 1
    return total


@dataclass(frozen=True)
class SymmetricSplitPoolPoint:
    poly_per_round: int
    bonus_pool_per_round: int
    signed_per_round: int
    bonus_per_round: int
    ops: int
    bytes: int
    signed_digest_bits: float
    bonus_free_bits: float
    honest_round_bits: float

    @property
    def setup_elements(self) -> int:
        return 2 * self.poly_per_round

    @property
    def setup_hashes(self) -> float:
        return setup_hashes_for(self.setup_elements)

    @property
    def setup_bits(self) -> float:
        return setup_bits_for(self.setup_elements)

    @property
    def second_preimage_bits(self) -> float:
        return 3 * PINNING_BITS - self.bonus_free_bits

    @property
    def collision_bits(self) -> float:
        return PINNING_BITS + self.signed_digest_bits / 2

    @property
    def witness_bytes(self) -> int:
        max_index = max(self.poly_per_round, self.bonus_pool_per_round) - 1
        return total_witness_bytes(
            max_index,
            self.signed_per_round,
            self.bonus_per_round,
            max_index,
            self.signed_per_round,
            self.bonus_per_round,
        )


def symmetric_split_pool_point(poly: int, signed: int, bonus: int) -> SymmetricSplitPoolPoint | None:
    signed_bits_round = log2_binom(poly, signed)
    needed_bonus_bits = PINNING_BITS - signed_bits_round
    bonus_pool = min_bonus_pool_for(needed_bonus_bits, bonus)
    if bonus_pool is None:
        return None

    ops = 5 + 2 * (9 * signed + 6 * bonus + 8)
    bytes_ = (
        PINNING_BYTES
        + split_round_bytes_exact(poly, bonus_pool, signed, bonus, 70)
        + split_round_bytes_exact(poly, bonus_pool, signed, bonus, 71)
    )
    if ops > MAX_OPS or bytes_ > MAX_SCRIPT_BYTES:
        return None

    honest_round_bits = signed_bits_round + log2_binom(bonus_pool, bonus)
    return SymmetricSplitPoolPoint(
        poly_per_round=poly,
        bonus_pool_per_round=bonus_pool,
        signed_per_round=signed,
        bonus_per_round=bonus,
        ops=ops,
        bytes=bytes_,
        signed_digest_bits=2 * signed_bits_round,
        bonus_free_bits=2 * log2_binom(bonus_pool, bonus),
        honest_round_bits=honest_round_bits,
    )


def best_symmetric_split_pool_under_cap(cap: int) -> SymmetricSplitPoolPoint | None:
    best: SymmetricSplitPoolPoint | None = None
    for poly in range(1, cap // 2 + 1):
        for signed in range(1, min(10, poly) + 1):
            for bonus in range(0, 7):
                point = symmetric_split_pool_point(poly, signed, bonus)
                if point is None or point.setup_elements > cap:
                    continue
                if best is None or (
                    point.collision_bits,
                    point.second_preimage_bits,
                    -point.bytes,
                ) > (
                    best.collision_bits,
                    best.second_preimage_bits,
                    -best.bytes,
                ):
                    best = point
    return best


@dataclass(frozen=True)
class RoundCandidate:
    poly: int
    bonus_pool: int
    signed: int
    bonus: int
    ops: int
    bytes70: int
    bytes71: int
    witness_bytes: int
    signed_bits: float
    bonus_free_bits: float

    @property
    def max_index(self) -> int:
        return max(self.poly, self.bonus_pool) - 1


@dataclass(frozen=True)
class AsymmetricSplitPoolPoint:
    round1: RoundCandidate
    round2: RoundCandidate
    ops: int
    bytes: int

    @property
    def witness_bytes(self) -> int:
        return total_witness_bytes(
            self.round1.max_index,
            self.round1.signed,
            self.round1.bonus,
            self.round2.max_index,
            self.round2.signed,
            self.round2.bonus,
        )

    @property
    def setup_elements(self) -> int:
        return self.round1.poly + self.round2.poly

    @property
    def setup_hashes(self) -> float:
        return setup_hashes_for(self.setup_elements)

    @property
    def setup_bits(self) -> float:
        return setup_bits_for(self.setup_elements)

    @property
    def signed_digest_bits(self) -> float:
        return self.round1.signed_bits + self.round2.signed_bits

    @property
    def bonus_free_bits(self) -> float:
        return self.round1.bonus_free_bits + self.round2.bonus_free_bits

    @property
    def second_preimage_bits(self) -> float:
        return 3 * PINNING_BITS - self.bonus_free_bits

    @property
    def collision_bits(self) -> float:
        return PINNING_BITS + self.signed_digest_bits / 2


def round_candidates(max_poly: int = MAX_POLY_PER_ROUND) -> list[RoundCandidate]:
    candidates: list[RoundCandidate] = []
    for poly in range(1, max_poly + 1):
        for signed in range(1, min(MAX_SIGNED_PER_ROUND, poly) + 1):
            signed_bits = log2_binom(poly, signed)
            for bonus in range(0, MAX_BONUS_PER_ROUND + 1):
                bonus_pool = min_bonus_pool_for(PINNING_BITS - signed_bits, bonus)
                if bonus_pool is None:
                    continue
                candidates.append(
                    RoundCandidate(
                        poly=poly,
                        bonus_pool=bonus_pool,
                        signed=signed,
                        bonus=bonus,
                        ops=9 * signed + 6 * bonus + 8,
                        bytes70=split_round_bytes_exact(poly, bonus_pool, signed, bonus, 70),
                        bytes71=split_round_bytes_exact(poly, bonus_pool, signed, bonus, 71),
                        witness_bytes=witness_round_bytes(max(poly, bonus_pool) - 1, signed, bonus),
                        signed_bits=signed_bits,
                        bonus_free_bits=0.0 if bonus == 0 else log2_binom(bonus_pool, bonus),
                    )
                )

    pruned: list[RoundCandidate] = []
    for candidate in candidates:
        dominated = False
        for incumbent in pruned[:]:
            if (
                incumbent.poly <= candidate.poly
                and incumbent.ops <= candidate.ops
                and incumbent.bytes70 <= candidate.bytes70
                and incumbent.bytes71 <= candidate.bytes71
                and incumbent.witness_bytes <= candidate.witness_bytes
                and incumbent.signed_bits >= candidate.signed_bits
                and incumbent.bonus_free_bits <= candidate.bonus_free_bits
                and (
                    incumbent.poly < candidate.poly
                    or incumbent.ops < candidate.ops
                    or incumbent.bytes70 < candidate.bytes70
                    or incumbent.bytes71 < candidate.bytes71
                    or incumbent.witness_bytes < candidate.witness_bytes
                    or incumbent.signed_bits > candidate.signed_bits
                    or incumbent.bonus_free_bits < candidate.bonus_free_bits
                )
            ):
                dominated = True
                break
            if (
                candidate.poly <= incumbent.poly
                and candidate.ops <= incumbent.ops
                and candidate.bytes70 <= incumbent.bytes70
                and candidate.bytes71 <= incumbent.bytes71
                and candidate.witness_bytes <= incumbent.witness_bytes
                and candidate.signed_bits >= incumbent.signed_bits
                and candidate.bonus_free_bits <= incumbent.bonus_free_bits
                and (
                    candidate.poly < incumbent.poly
                    or candidate.ops < incumbent.ops
                    or candidate.bytes70 < incumbent.bytes70
                    or candidate.bytes71 < incumbent.bytes71
                    or candidate.witness_bytes < incumbent.witness_bytes
                    or candidate.signed_bits > incumbent.signed_bits
                    or candidate.bonus_free_bits < incumbent.bonus_free_bits
                )
            ):
                pruned.remove(incumbent)
        if not dominated:
            pruned.append(candidate)
    return pruned


def best_asymmetric_points_by_setup_total(max_setup_total: int = SEARCH_CAPS[-1]) -> dict[int, AsymmetricSplitPoolPoint]:
    candidates = round_candidates(max_poly=max_setup_total - 1)
    best: dict[int, AsymmetricSplitPoolPoint] = {}
    for round1 in candidates:
        for round2 in candidates:
            setup_total = round1.poly + round2.poly
            if setup_total > max_setup_total:
                continue
            ops = 5 + round1.ops + round2.ops
            bytes_ = PINNING_BYTES + round1.bytes70 + round2.bytes71
            if ops > MAX_OPS or bytes_ > MAX_SCRIPT_BYTES:
                continue
            point = AsymmetricSplitPoolPoint(round1=round1, round2=round2, ops=ops, bytes=bytes_)
            incumbent = best.get(setup_total)
            if incumbent is None or (
                point.collision_bits,
                point.second_preimage_bits,
                -point.bytes,
                -point.witness_bytes,
            ) > (
                incumbent.collision_bits,
                incumbent.second_preimage_bits,
                -incumbent.bytes,
                -incumbent.witness_bytes,
            ):
                best[setup_total] = point
    return best


def fmt_time(point_hashes: float) -> str:
    return (
        f"{days_at_rate(point_hashes, GHASH):.1f}d@1GH/s "
        f"{days_at_rate(point_hashes, TEN_GHASH):.1f}d@10GH/s"
    )


def render_references() -> str:
    lines = ["# corrected-reference-qsb", ""]
    for ref in corrected_references():
        lines.extend(
            [
                f"name: {ref.name}",
                f"  bytes={ref.bytes}",
                f"  ops={ref.ops}",
                f"  signed_bits={ref.signed_digest_bits:.2f}",
                f"  subset_bits={ref.subset_search_bits:.2f}",
                f"  second_preimage_bits={ref.second_preimage_bits:.2f}",
                f"  collision_bits={ref.collision_bits:.2f}",
                f"  bonus_free_bits={ref.bonus_free_bits:.2f}",
                f"  assignment_bits={ref.assignment_bits:.2f}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def render_corrected_full_polyglot() -> str:
    same_n = full_polyglot_point(150, 10, 10)
    lines = [
        "# corrected-full-polyglot",
        "",
        "same_n_150_ten_ten:",
        f"  bytes={same_n.bytes}",
        f"  ops={same_n.ops}",
        f"  signed_bits={same_n.signed_digest_bits:.2f}",
        f"  second_preimage_bits={same_n.second_preimage_bits:.2f}",
        f"  collision_bits={same_n.collision_bits:.2f}",
        f"  witness_bytes={same_n.witness_bytes}",
        f"  setup_elements={same_n.setup_elements}",
        f"  setup_bits={same_n.setup_bits:.2f}",
        f"  setup_time={fmt_time(same_n.setup_hashes)}",
    ]
    return "\n".join(lines)


def render_split_pool_frontier() -> str:
    refs = {ref.name: ref for ref in corrected_references()}
    config_a = refs["configA_8p1b_7p2b"]
    baseline = refs["baseline_8_8"]

    points = [(cap, best_symmetric_split_pool_under_cap(cap)) for cap in SEARCH_CAPS]
    first_beats_config_a = next(
        (
            (cap, point)
            for cap, point in points
            if point is not None
            and point.second_preimage_bits > config_a.second_preimage_bits
            and point.collision_bits > config_a.collision_bits
        ),
        None,
    )
    first_beats_baseline_collision = next(
        (
            (cap, point)
            for cap, point in points
            if point is not None and point.collision_bits > baseline.collision_bits
        ),
        None,
    )

    lines = [
        "# split-pool-partial-polyglot-frontier",
        "",
    ]

    if first_beats_config_a is not None:
        cap, point = first_beats_config_a
        lines.extend(
            [
                "first_point_beating_configA_on_second_preimage_and_collision:",
                f"  cap={cap}",
                f"  m={point.poly_per_round} q={point.bonus_pool_per_round} s={point.signed_per_round} b={point.bonus_per_round}",
                f"  bytes={point.bytes}",
                f"  ops={point.ops}",
                f"  signed_bits={point.signed_digest_bits:.2f}",
                f"  second_preimage_bits={point.second_preimage_bits:.2f}",
                f"  collision_bits={point.collision_bits:.2f}",
                f"  witness_bytes={point.witness_bytes}",
                f"  setup_elements={point.setup_elements}",
                f"  setup_bits={point.setup_bits:.2f}",
                f"  setup_time={fmt_time(point.setup_hashes)}",
                "",
            ]
        )

    if first_beats_baseline_collision is not None:
        cap, point = first_beats_baseline_collision
        lines.extend(
            [
                "first_point_beating_baseline_collision:",
                f"  cap={cap}",
                f"  m={point.poly_per_round} q={point.bonus_pool_per_round} s={point.signed_per_round} b={point.bonus_per_round}",
                f"  bytes={point.bytes}",
                f"  ops={point.ops}",
                f"  signed_bits={point.signed_digest_bits:.2f}",
                f"  second_preimage_bits={point.second_preimage_bits:.2f}",
                f"  collision_bits={point.collision_bits:.2f}",
                f"  witness_bytes={point.witness_bytes}",
                f"  setup_elements={point.setup_elements}",
                f"  setup_bits={point.setup_bits:.2f}",
                f"  setup_time={fmt_time(point.setup_hashes)}",
                "",
            ]
        )

    lines.append("best_symmetric_points_by_setup_cap:")
    for cap, point in points:
        if point is None:
            lines.append(f"  cap={cap}: none")
            continue
        lines.append(
            "  "
            + (
                f"cap={cap}: m={point.poly_per_round} q={point.bonus_pool_per_round} "
                f"s={point.signed_per_round} b={point.bonus_per_round} "
                f"bytes={point.bytes} ops={point.ops} "
                f"witness_bytes={point.witness_bytes} "
                f"signed_bits={point.signed_digest_bits:.2f} "
                f"second_preimage_bits={point.second_preimage_bits:.2f} "
                f"collision_bits={point.collision_bits:.2f} "
                f"setup_bits={point.setup_bits:.2f}"
            )
        )
    return "\n".join(lines)


def render_asymmetric_split_pool_frontier() -> str:
    refs = {ref.name: ref for ref in corrected_references()}
    config_a = refs["configA_8p1b_7p2b"]
    baseline = refs["baseline_8_8"]
    best_by_total = best_asymmetric_points_by_setup_total()

    first_beats_config_a = next(
        (
            (setup_total, point)
            for setup_total, point in sorted(best_by_total.items())
            if point.second_preimage_bits > config_a.second_preimage_bits
            and point.collision_bits > config_a.collision_bits
        ),
        None,
    )
    first_beats_baseline_collision = next(
        (
            (setup_total, point)
            for setup_total, point in sorted(best_by_total.items())
            if point.collision_bits > baseline.collision_bits
        ),
        None,
    )

    lines = [
        "# asymmetric-split-pool-frontier",
        "",
    ]

    if first_beats_config_a is not None:
        setup_total, point = first_beats_config_a
        lines.extend(
            [
                "first_point_beating_configA_on_second_preimage_and_collision:",
                f"  setup_total={setup_total}",
                (
                    f"  r1: m={point.round1.poly} q={point.round1.bonus_pool} "
                    f"s={point.round1.signed} b={point.round1.bonus}"
                ),
                (
                    f"  r2: m={point.round2.poly} q={point.round2.bonus_pool} "
                    f"s={point.round2.signed} b={point.round2.bonus}"
                ),
                f"  bytes={point.bytes}",
                f"  ops={point.ops}",
                f"  witness_bytes={point.witness_bytes}",
                f"  signed_bits={point.signed_digest_bits:.2f}",
                f"  second_preimage_bits={point.second_preimage_bits:.2f}",
                f"  collision_bits={point.collision_bits:.2f}",
                f"  setup_bits={point.setup_bits:.2f}",
                f"  setup_time={fmt_time(point.setup_hashes)}",
                "",
            ]
        )

    if first_beats_baseline_collision is not None:
        setup_total, point = first_beats_baseline_collision
        lines.extend(
            [
                "first_point_beating_baseline_collision:",
                f"  setup_total={setup_total}",
                (
                    f"  r1: m={point.round1.poly} q={point.round1.bonus_pool} "
                    f"s={point.round1.signed} b={point.round1.bonus}"
                ),
                (
                    f"  r2: m={point.round2.poly} q={point.round2.bonus_pool} "
                    f"s={point.round2.signed} b={point.round2.bonus}"
                ),
                f"  bytes={point.bytes}",
                f"  ops={point.ops}",
                f"  witness_bytes={point.witness_bytes}",
                f"  signed_bits={point.signed_digest_bits:.2f}",
                f"  second_preimage_bits={point.second_preimage_bits:.2f}",
                f"  collision_bits={point.collision_bits:.2f}",
                f"  setup_bits={point.setup_bits:.2f}",
                f"  setup_time={fmt_time(point.setup_hashes)}",
                "",
            ]
        )

    lines.append("best_asymmetric_points_by_setup_cap:")
    for cap in SEARCH_CAPS:
        point = best_by_total.get(cap)
        if point is None:
            lines.append(f"  cap={cap}: none")
            continue
        lines.append(
            "  "
            + (
                f"cap={cap}: "
                f"r1(m={point.round1.poly},q={point.round1.bonus_pool},s={point.round1.signed},b={point.round1.bonus}) "
                f"r2(m={point.round2.poly},q={point.round2.bonus_pool},s={point.round2.signed},b={point.round2.bonus}) "
                f"bytes={point.bytes} ops={point.ops} witness_bytes={point.witness_bytes} "
                f"signed_bits={point.signed_digest_bits:.2f} "
                f"second_preimage_bits={point.second_preimage_bits:.2f} "
                f"collision_bits={point.collision_bits:.2f} "
                f"setup_bits={point.setup_bits:.2f}"
            )
        )
    return "\n".join(lines)


def main() -> None:
    print(render_references())
    print()
    print(render_corrected_full_polyglot())
    print()
    print(render_split_pool_frontier())
    print()
    print(render_asymmetric_split_pool_frontier())


if __name__ == "__main__":
    main()
