#!/usr/bin/env python3
"""
Stack sanity checks for the QSB/polyglot frontier.

The frontier tools are useful budget models, but the next feasibility gate is
whether their position constants are compatible with an explicit Bitcoin Script
stack layout. This script intentionally checks only the stack movement layer:
it does not try to validate ECDSA, sighash, DER parsing, or transaction relay.

The checks use the witness layout documented by the vendored QSB pipeline:

    key_puzzle, key_nonce, dummy_pubkeys(rev), preimages(rev), indices(rev)

and the hardcoded layout used by the vendored QSB builder:

    HORS commitments(rev), dummy signatures(rev), OP_0, sig_nonce

That is enough to catch off-by-one and wrong-zone OP_ROLL constants before we
spend more time on setup economics.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from polyglot_setup_frontier import (  # type: ignore
    best_asymmetric_points_by_setup_total,
    corrected_references,
    fmt_time,
)


@dataclass(frozen=True)
class StackCheck:
    name: str
    ok: bool
    expected: str
    actual: str
    detail: str

    def render(self) -> str:
        status = "PASS" if self.ok else "FAIL"
        return (
            f"- {self.name}: {status}\n"
            f"  expected={self.expected}\n"
            f"  actual={self.actual}\n"
            f"  detail={self.detail}"
        )


def roll(stack: list[str], depth: int) -> str:
    """Execute OP_ROLL on a symbolic bottom-to-top stack."""
    if depth < 0 or depth >= len(stack):
        raise IndexError(f"OP_ROLL depth {depth} outside stack size {len(stack)}")
    item = stack.pop(len(stack) - 1 - depth)
    stack.append(item)
    return item


def position(stack: list[str], item: str) -> int:
    """Return Bitcoin OP_ROLL depth for an item on a bottom-to-top stack."""
    return len(stack) - 1 - stack.index(item)


def qsb_round_stack(n: int, signed: int, bonus: int) -> list[str]:
    """Symbolic stack just before the first QSB round selection executes."""
    total = signed + bonus
    stack: list[str] = []

    # Unlocking data, bottom to top, matching qsb_pipeline.py.
    stack.extend(["key_puzzle", "key_nonce"])
    stack.extend(f"pub{idx}" for idx in reversed(range(total)))
    stack.extend(f"pre{idx}" for idx in reversed(range(signed)))
    stack.extend(f"idx{idx}" for idx in reversed(range(total)))

    # Locking data, in the same push order as QSBScriptBuilder.build_round_script.
    stack.extend(f"H{idx}" for idx in reversed(range(n)))
    stack.extend(f"sig{idx}" for idx in reversed(range(n)))
    stack.extend(["OP_0", "sig_nonce"])
    return stack


def check_qsb_first_selection_roll(n: int = 5, signed: int = 2, bonus: int = 0) -> StackCheck:
    stack = qsb_round_stack(n, signed, bonus)
    depth = 2 * n + 1
    actual = roll(stack, depth)
    expected = "idx0"
    return StackCheck(
        name="vendored-qsb-first-selection-roll",
        ok=actual == expected,
        expected=expected,
        actual=actual,
        detail=(
            f"builder constant depth=2*n+1={depth}; documented witness puts "
            f"idx0 at depth {position(qsb_round_stack(n, signed, bonus), expected)}"
        ),
    )


def check_qsb_cms_key_nonce_roll(total: int = 3) -> StackCheck:
    # Minimal symbolic stack at the point described by the QSB builder comment:
    # key_nonce is on top after the puzzle check, selected signatures are below.
    stack = ["below", "OP_0", "sig_nonce"]
    stack.extend(f"selected_sig{idx}" for idx in range(total))
    stack.append("key_nonce")

    # Vendored QSB emits: <m> OP_2 OP_ROLL.
    stack.append("m")
    stack.append("2")
    stack.pop()
    actual = roll(stack, 2)
    expected = "key_nonce"
    return StackCheck(
        name="vendored-qsb-cms-key-nonce-roll",
        ok=actual == expected,
        expected=expected,
        actual=actual,
        detail="with <m> above key_nonce, OP_2 OP_ROLL moves the first selected signature, not key_nonce",
    )


def split_polyglot_round_stack(poly: int, bonus_pool: int, signed: int, bonus: int) -> list[str]:
    """Symbolic stack for the current split-pool model's literal layout."""
    total = signed + bonus
    stack: list[str] = []
    stack.extend(["key_puzzle", "key_nonce"])
    stack.extend(f"pub{idx}" for idx in reversed(range(total)))
    stack.extend(f"pre{idx}" for idx in reversed(range(signed)))
    stack.extend(f"idx{idx}" for idx in reversed(range(total)))

    # Literal order implied by split_round_bytes_exact: bonus pool, poly pool,
    # OP_0, sig_nonce. Reordering can be explored later, but the current model
    # does not yet provide an executable alternative.
    stack.extend(f"B{idx}" for idx in reversed(range(bonus_pool)))
    stack.extend(f"P{idx}" for idx in reversed(range(poly)))
    stack.extend(["OP_0", "sig_nonce"])
    return stack


def check_split_polyglot_first_roll(
    poly: int = 64,
    bonus_pool: int = 206,
    signed: int = 8,
    bonus: int = 2,
) -> StackCheck:
    stack = split_polyglot_round_stack(poly, bonus_pool, signed, bonus)
    hardcoded = poly + bonus_pool
    depth = hardcoded + 1
    actual = roll(stack, depth)
    expected = "idx0"
    return StackCheck(
        name="modeled-split-polyglot-first-selection-roll",
        ok=actual == expected,
        expected=expected,
        actual=actual,
        detail=(
            f"model constant depth=m+q+1={depth}; documented witness puts "
            f"idx0 at depth {position(split_polyglot_round_stack(poly, bonus_pool, signed, bonus), expected)}"
        ),
    )


def render_model_frontier_snapshot() -> str:
    refs = {ref.name: ref for ref in corrected_references()}
    config_a = refs["configA_8p1b_7p2b"]
    baseline = refs["baseline_8_8"]
    best_by_total = best_asymmetric_points_by_setup_total()

    first_config_a = next(
        (
            (setup_total, point)
            for setup_total, point in sorted(best_by_total.items())
            if point.second_preimage_bits > config_a.second_preimage_bits
            and point.collision_bits > config_a.collision_bits
        ),
        None,
    )
    first_baseline_collision = next(
        (
            (setup_total, point)
            for setup_total, point in sorted(best_by_total.items())
            if point.collision_bits > baseline.collision_bits
        ),
        None,
    )

    lines = ["# numeric-frontier-snapshot", ""]
    if first_config_a is not None:
        setup_total, point = first_config_a
        lines.extend(
            [
                "first_model_point_beating_configA:",
                f"  setup_total={setup_total}",
                (
                    f"  r1=m{point.round1.poly}/q{point.round1.bonus_pool}/"
                    f"s{point.round1.signed}/b{point.round1.bonus}"
                ),
                (
                    f"  r2=m{point.round2.poly}/q{point.round2.bonus_pool}/"
                    f"s{point.round2.signed}/b{point.round2.bonus}"
                ),
                f"  bytes={point.bytes}",
                f"  ops={point.ops}",
                f"  second_preimage_bits={point.second_preimage_bits:.2f}",
                f"  collision_bits={point.collision_bits:.2f}",
                f"  setup_time={fmt_time(point.setup_hashes)}",
                "",
            ]
        )
    if first_baseline_collision is not None:
        setup_total, point = first_baseline_collision
        lines.extend(
            [
                "first_model_point_beating_baseline_collision:",
                f"  setup_total={setup_total}",
                (
                    f"  r1=m{point.round1.poly}/q{point.round1.bonus_pool}/"
                    f"s{point.round1.signed}/b{point.round1.bonus}"
                ),
                (
                    f"  r2=m{point.round2.poly}/q{point.round2.bonus_pool}/"
                    f"s{point.round2.signed}/b{point.round2.bonus}"
                ),
                f"  bytes={point.bytes}",
                f"  ops={point.ops}",
                f"  second_preimage_bits={point.second_preimage_bits:.2f}",
                f"  collision_bits={point.collision_bits:.2f}",
                f"  setup_time={fmt_time(point.setup_hashes)}",
            ]
        )
    return "\n".join(lines)


def render_stack_gate() -> str:
    checks = [
        check_qsb_first_selection_roll(),
        check_qsb_cms_key_nonce_roll(),
        check_split_polyglot_first_roll(),
    ]
    failed = [check for check in checks if not check.ok]
    decision = "NO-GO" if failed else "GO"

    lines = [
        "# stack-feasibility-gate",
        "",
        f"decision={decision}",
        "",
        "checks:",
    ]
    lines.extend(check.render() for check in checks)
    lines.extend(
        [
            "",
            "interpretation:",
            (
                "- The asymmetric polyglot numbers are still useful as a budget frontier, "
                "but they are not yet an executable construction."
            ),
            (
                "- The next valid engineering step is a real stack-correct script builder "
                "or importing an upstream regtest-proven script, not more setup-frontier tuning."
            ),
        ]
    )
    return "\n".join(lines)


def main() -> None:
    print(render_model_frontier_snapshot())
    print()
    print(render_stack_gate())


if __name__ == "__main__":
    main()
