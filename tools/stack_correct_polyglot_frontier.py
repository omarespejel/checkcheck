#!/usr/bin/env python3
"""
Build a stack-correct polyglot round skeleton and rerun the frontier.

This is the implementation gate after frontier-17. The previous asymmetric
polyglot frontier was a budget model. Here we emit concrete Bitcoin Script
bytes for a conservative stack-correct split-pool round and simulate the stack
movements that matter:

- signed selections pick a trusted polyglot element with OP_PICK for the
  HASH160 equality check, then OP_ROLL the same hardcoded element into the
  CHECKMULTISIG signature zone;
- bonus selections OP_ROLL from a separate dummy-signature pool;
- the puzzle/CHECKMULTISIG tail uses OP_SWAP, not the broken OP_2 OP_ROLL
  movement found in frontier-17.

This is still not a regtest transaction builder. It deliberately stops at the
round-script execution layer: stack movement, script bytes, and opcode counts.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import lgamma, log
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
UPSTREAM_PIPELINE = ROOT / "third_party" / "qsb-avihu" / "pipeline"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
if str(UPSTREAM_PIPELINE) not in sys.path:
    sys.path.insert(0, str(UPSTREAM_PIPELINE))

from bitcoin_tx import (  # type: ignore
    OP_0,
    OP_ADD,
    OP_CHECKMULTISIG,
    OP_CHECKSIGVERIFY,
    OP_DUP,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_MIN,
    OP_RIPEMD160_OP,
    OP_ROLL,
    OP_SWAP,
    push_data,
    push_number,
)
from polyglot_setup_frontier import (  # type: ignore
    GHASH,
    MAX_BONUS_PER_ROUND,
    MAX_OPS,
    MAX_SCRIPT_BYTES,
    MAX_SIGNED_PER_ROUND,
    PINNING_BITS,
    PINNING_BYTES,
    SEARCH_CAPS,
    TEN_GHASH,
    corrected_references,
    days_at_rate,
    min_bonus_pool_for,
    setup_hashes_for,
)


OP_PICK = 0x79
MAX_POLY_PER_ROUND = 220


def log2_binom(n: int, k: int) -> float:
    if k < 0 or k > n:
        raise ValueError(f"invalid binomial parameters: n={n}, k={k}")
    return (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)) / log(2)


@dataclass(frozen=True)
class Item:
    kind: str
    name: str
    value: int | None = None
    target: str | None = None

    def __str__(self) -> str:
        if self.kind == "int":
            return str(self.value)
        if self.target is not None:
            return f"{self.name}->{self.target}"
        return self.name


def data(name: str) -> Item:
    return Item("data", name)


def int_item(value: int) -> Item:
    return Item("int", str(value), value=value)


def named_int(name: str, value: int) -> Item:
    return Item("int", name, value=value)


def preimage(name: str, target: str) -> Item:
    return Item("preimage", name, target=target)


def hash_item(target: str) -> Item:
    return Item("hash", f"H({target})", target=target)


def is_push_opcode(opcode: int) -> bool:
    return opcode == OP_0 or 0x01 <= opcode <= 0x60


@dataclass(frozen=True)
class RoundShape:
    poly: int
    bonus_pool: int
    signed: int
    bonus: int
    sig_len: int

    @property
    def total(self) -> int:
        return self.signed + self.bonus


@dataclass(frozen=True)
class RoundBuild:
    shape: RoundShape
    script_bytes: int
    ops: int
    witness_bytes: int
    selected_poly: tuple[str, ...]
    selected_bonus: tuple[str, ...]


class ScriptMachine:
    def __init__(self, stack: list[Item]) -> None:
        self.stack = stack
        self.script = bytearray()
        self.ops = 0

    def position(self, name: str) -> int:
        for idx, item in enumerate(self.stack):
            if item.name == name:
                return len(self.stack) - 1 - idx
        raise ValueError(f"missing stack item {name}")

    def push_data(self, item: Item, size: int) -> None:
        self.script.extend(push_data(bytes([0x42]) * size))
        self.stack.append(item)

    def push_int(self, value: int) -> None:
        self.script.extend(push_number(value))
        self.stack.append(int_item(value))

    def op(self, opcode: int) -> None:
        self.script.append(opcode)
        if not is_push_opcode(opcode):
            self.ops += 1

        if opcode == OP_ROLL:
            depth = self._pop_int("OP_ROLL")
            item = self.stack.pop(len(self.stack) - 1 - depth)
            self.stack.append(item)
        elif opcode == OP_PICK:
            depth = self._pop_int("OP_PICK")
            item = self.stack[len(self.stack) - 1 - depth]
            self.stack.append(item)
        elif opcode == OP_MIN:
            right = self._pop_int("OP_MIN")
            left = self._pop_int("OP_MIN")
            self.stack.append(int_item(min(left, right)))
        elif opcode == OP_ADD:
            right = self._pop_int("OP_ADD")
            left = self._pop_int("OP_ADD")
            self.stack.append(int_item(left + right))
        elif opcode == OP_DUP:
            self.stack.append(self.stack[-1])
        elif opcode == OP_HASH160:
            top = self.stack.pop()
            if top.kind != "preimage" or top.target is None:
                raise AssertionError(f"OP_HASH160 expected preimage, got {top}")
            self.stack.append(hash_item(top.target))
        elif opcode == OP_RIPEMD160_OP:
            top = self.stack.pop()
            self.stack.append(hash_item(top.name))
        elif opcode == OP_EQUALVERIFY:
            left = self.stack.pop()
            right = self.stack.pop()
            left_target = left.target if left.kind == "hash" else left.name
            right_target = right.target if right.kind == "hash" else right.name
            if left_target != right_target:
                raise AssertionError(f"OP_EQUALVERIFY mismatch: {left} != {right}")
        elif opcode == OP_SWAP:
            self.stack[-1], self.stack[-2] = self.stack[-2], self.stack[-1]
        elif opcode == OP_CHECKSIGVERIFY:
            key = self.stack.pop()
            sig = self.stack.pop()
            if key.kind != "data" or sig.kind != "hash":
                raise AssertionError(f"bad CHECKSIGVERIFY pair: sig={sig} key={key}")
        elif opcode == OP_CHECKMULTISIG:
            self._checkmultisig()
        else:
            raise NotImplementedError(f"opcode {opcode:#x} not implemented")

    def _pop_int(self, op_name: str) -> int:
        if not self.stack:
            raise AssertionError(f"{op_name} on empty stack")
        top = self.stack.pop()
        if top.kind != "int" or top.value is None:
            raise AssertionError(f"{op_name} expected int, got {top}")
        if top.value < 0 or top.value >= len(self.stack):
            raise AssertionError(f"{op_name} depth {top.value} outside stack size {len(self.stack)}")
        return top.value

    def _checkmultisig(self) -> None:
        n = self._pop_int("OP_CHECKMULTISIG n")
        pubkeys = [self.stack.pop() for _ in range(n)]
        m = self._pop_int("OP_CHECKMULTISIG m")
        sigs = [self.stack.pop() for _ in range(m)]
        dummy = self.stack.pop()
        if m != n:
            raise AssertionError(f"CHECKMULTISIG m/n mismatch: {m}/{n}")
        if dummy.name != "OP_0":
            raise AssertionError(f"CHECKMULTISIG dummy mismatch: {dummy}")
        if any(item.kind != "data" for item in pubkeys):
            raise AssertionError(f"CHECKMULTISIG pubkey zone contains non-data: {pubkeys}")
        if any(item.kind != "data" for item in sigs):
            raise AssertionError(f"CHECKMULTISIG signature zone contains non-data: {sigs}")
        self.stack.append(data("cms_true"))


def roll_named(machine: ScriptMachine, name: str) -> None:
    machine.push_int(machine.position(name))
    machine.op(OP_ROLL)


def pick_by_index_from_pool(machine: ScriptMachine, first_remaining_name: str) -> None:
    # Stack top is the sanitized index. OP_PICK consumes the computed depth but
    # leaves the original index underneath the copied pool element.
    machine.op(OP_DUP)
    offset = machine.position(first_remaining_name) - 1
    machine.push_int(offset)
    machine.op(OP_ADD)
    machine.op(OP_PICK)


def roll_by_index_from_pool(machine: ScriptMachine, first_remaining_name: str) -> None:
    # Stack top is the sanitized index. OP_ROLL consumes it and leaves only the
    # selected pool element in the CHECKMULTISIG signature zone.
    offset = machine.position(first_remaining_name) - 1
    machine.push_int(offset)
    machine.op(OP_ADD)
    machine.op(OP_ROLL)


def round_witness_stack(
    shape: RoundShape,
    signed_indices: tuple[int, ...],
    bonus_indices: tuple[int, ...],
    selected_poly: tuple[str, ...],
) -> list[Item]:
    stack: list[Item] = [data("key_puzzle"), data("key_nonce")]
    stack.extend(data(f"pub{i}") for i in reversed(range(shape.total)))
    stack.extend(
        preimage(f"pre{i}", selected_poly[i])
        for i in reversed(range(shape.signed))
    )
    index_values = tuple(signed_indices) + tuple(bonus_indices)
    stack.extend(named_int(f"idx{i}", index_values[i]) for i in reversed(range(shape.total)))
    return stack


def select_from_remaining(remaining: list[str], index: int) -> str:
    if index < 0 or index >= len(remaining):
        raise ValueError(f"index {index} outside remaining pool of {len(remaining)}")
    return remaining.pop(index)


def default_indices(count: int) -> tuple[int, ...]:
    # Always select the current shallowest remaining element. This exercises the
    # same script constants while keeping the witness compact and deterministic.
    return tuple(0 for _ in range(count))


def last_remaining_indices(pool_size: int, count: int) -> tuple[int, ...]:
    return tuple(pool_size - 1 - idx for idx in range(count))


def build_round(
    shape: RoundShape,
    signed_indices: tuple[int, ...] | None = None,
    bonus_indices: tuple[int, ...] | None = None,
) -> RoundBuild:
    signed_indices = signed_indices if signed_indices is not None else default_indices(shape.signed)
    bonus_indices = bonus_indices if bonus_indices is not None else default_indices(shape.bonus)
    if len(signed_indices) != shape.signed or len(bonus_indices) != shape.bonus:
        raise ValueError("index vector length does not match round shape")

    poly_remaining_for_witness = [f"P{i}" for i in range(shape.poly)]
    selected_poly = tuple(
        select_from_remaining(poly_remaining_for_witness, idx)
        for idx in signed_indices
    )
    bonus_remaining_for_witness = [f"B{i}" for i in range(shape.bonus_pool)]
    selected_bonus = tuple(
        select_from_remaining(bonus_remaining_for_witness, idx)
        for idx in bonus_indices
    )

    machine = ScriptMachine(round_witness_stack(shape, signed_indices, bonus_indices, selected_poly))

    for idx in range(shape.bonus_pool - 1, -1, -1):
        machine.push_data(data(f"B{idx}"), 9)
    for idx in range(shape.poly - 1, -1, -1):
        machine.push_data(data(f"P{idx}"), 20)
    machine.script.append(OP_0)
    machine.stack.append(data("OP_0"))
    machine.push_data(data("sig_nonce"), shape.sig_len)

    poly_remaining = [f"P{i}" for i in range(shape.poly)]
    for selection_index, witness_index in enumerate(signed_indices):
        selected = poly_remaining[witness_index]

        roll_named(machine, f"idx{selection_index}")
        machine.push_int(len(poly_remaining) - 1)
        machine.op(OP_MIN)

        pick_by_index_from_pool(machine, poly_remaining[0])
        roll_named(machine, f"pre{selection_index}")
        machine.op(OP_HASH160)
        machine.op(OP_EQUALVERIFY)

        roll_by_index_from_pool(machine, poly_remaining[0])
        actual = machine.stack[-1]
        if actual.name != selected:
            raise AssertionError(f"selected poly mismatch: expected {selected}, got {actual}")
        select_from_remaining(poly_remaining, witness_index)

    bonus_remaining = [f"B{i}" for i in range(shape.bonus_pool)]
    for bonus_index, witness_index in enumerate(bonus_indices):
        selected = bonus_remaining[witness_index]

        roll_named(machine, f"idx{shape.signed + bonus_index}")
        machine.push_int(len(bonus_remaining) - 1)
        machine.op(OP_MIN)
        roll_by_index_from_pool(machine, bonus_remaining[0])
        actual = machine.stack[-1]
        if actual.name != selected:
            raise AssertionError(f"selected bonus mismatch: expected {selected}, got {actual}")
        select_from_remaining(bonus_remaining, witness_index)

    roll_named(machine, "key_nonce")
    machine.op(OP_DUP)
    machine.op(OP_RIPEMD160_OP)
    roll_named(machine, "key_puzzle")
    machine.op(OP_CHECKSIGVERIFY)

    multisig_count = shape.total + 1
    machine.push_int(multisig_count)
    machine.op(OP_SWAP)
    for pub_index in range(shape.total):
        roll_named(machine, f"pub{pub_index}")
    machine.push_int(multisig_count)
    machine.op(OP_CHECKMULTISIG)

    # Legacy consensus only requires a truthy top stack item at script end.
    # Remaining hardcoded pool elements below it are harmless for this bare
    # non-standard script setting; CLEANSTACK is a policy layer, not the gate
    # this tool is trying to validate.
    if not machine.stack or machine.stack[-1].name != "cms_true":
        raise AssertionError(f"unexpected final stack: {machine.stack}")

    return RoundBuild(
        shape=shape,
        script_bytes=len(machine.script),
        ops=machine.ops,
        witness_bytes=witness_round_bytes(max(shape.poly, shape.bonus_pool) - 1, shape.signed, shape.bonus),
        selected_poly=selected_poly,
        selected_bonus=selected_bonus,
    )


def witness_round_bytes(max_index: int, signed: int, bonus: int) -> int:
    idx_push = len(push_number(max_index))
    pubkey_push = len(push_data(b"\x02" + b"\x00" * 32))
    preimage_push = len(push_data(b"\x00" * 20))
    total = signed + bonus
    return 2 * pubkey_push + total * pubkey_push + signed * preimage_push + total * idx_push


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
class StackCorrectPoint:
    round1: RoundCandidate
    round2: RoundCandidate
    ops: int
    bytes: int

    @property
    def setup_elements(self) -> int:
        return self.round1.poly + self.round2.poly

    @property
    def setup_hashes(self) -> float:
        return setup_hashes_for(self.setup_elements)

    @property
    def setup_bits(self) -> float:
        return PINNING_BITS + log(self.setup_elements, 2)

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

    @property
    def witness_bytes(self) -> int:
        return (
            self.round2.witness_bytes
            + self.round1.witness_bytes
            + 2 * len(push_data(b"\x02" + b"\x00" * 32))
        )


def round_candidates(max_poly: int = MAX_POLY_PER_ROUND) -> list[RoundCandidate]:
    candidates: list[RoundCandidate] = []
    for poly in range(1, max_poly + 1):
        for signed in range(1, min(MAX_SIGNED_PER_ROUND, poly) + 1):
            signed_bits = log2_binom(poly, signed)
            for bonus in range(0, MAX_BONUS_PER_ROUND + 1):
                bonus_pool = min_bonus_pool_for(PINNING_BITS - signed_bits, bonus)
                if bonus_pool is None:
                    continue
                try:
                    round70 = build_round(RoundShape(poly, bonus_pool, signed, bonus, 70))
                    round71 = build_round(RoundShape(poly, bonus_pool, signed, bonus, 71))
                except (AssertionError, ValueError):
                    continue
                candidates.append(
                    RoundCandidate(
                        poly=poly,
                        bonus_pool=bonus_pool,
                        signed=signed,
                        bonus=bonus,
                        ops=round70.ops,
                        bytes70=round70.script_bytes,
                        bytes71=round71.script_bytes,
                        witness_bytes=round70.witness_bytes,
                        signed_bits=signed_bits,
                        bonus_free_bits=0.0 if bonus == 0 else log2_binom(bonus_pool, bonus),
                    )
                )

    pruned: list[RoundCandidate] = []
    for candidate in candidates:
        dominated = False
        for incumbent in pruned[:]:
            if dominates(incumbent, candidate):
                dominated = True
                break
            if dominates(candidate, incumbent):
                pruned.remove(incumbent)
        if not dominated:
            pruned.append(candidate)
    return pruned


def dominates(left: RoundCandidate, right: RoundCandidate) -> bool:
    return (
        left.poly <= right.poly
        and left.ops <= right.ops
        and left.bytes70 <= right.bytes70
        and left.bytes71 <= right.bytes71
        and left.witness_bytes <= right.witness_bytes
        and left.signed_bits >= right.signed_bits
        and left.bonus_free_bits <= right.bonus_free_bits
        and (
            left.poly < right.poly
            or left.ops < right.ops
            or left.bytes70 < right.bytes70
            or left.bytes71 < right.bytes71
            or left.witness_bytes < right.witness_bytes
            or left.signed_bits > right.signed_bits
            or left.bonus_free_bits < right.bonus_free_bits
        )
    )


def best_points_by_setup_total(max_setup_total: int = SEARCH_CAPS[-1]) -> dict[int, StackCorrectPoint]:
    candidates = round_candidates(max_poly=min(MAX_POLY_PER_ROUND, max_setup_total - 1))
    best: dict[int, StackCorrectPoint] = {}
    for round1 in candidates:
        for round2 in candidates:
            setup_total = round1.poly + round2.poly
            if setup_total > max_setup_total:
                continue
            ops = 5 + round1.ops + round2.ops
            bytes_ = PINNING_BYTES + round1.bytes70 + round2.bytes71
            if ops > MAX_OPS or bytes_ > MAX_SCRIPT_BYTES:
                continue
            point = StackCorrectPoint(round1=round1, round2=round2, ops=ops, bytes=bytes_)
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


def fmt_time(hashes: float) -> str:
    return f"{days_at_rate(hashes, GHASH):.1f}d@1GH/s {days_at_rate(hashes, TEN_GHASH):.1f}d@10GH/s"


def render_stack_correct_builder_demo() -> str:
    shape = RoundShape(poly=64, bonus_pool=206, signed=8, bonus=2, sig_len=70)
    round_build = build_round(shape)
    alternate = build_round(
        shape,
        signed_indices=last_remaining_indices(shape.poly, shape.signed),
        bonus_indices=last_remaining_indices(shape.bonus_pool, shape.bonus),
    )
    alternate_status = (
        "pass"
        if (alternate.script_bytes, alternate.ops) == (round_build.script_bytes, round_build.ops)
        else "fail"
    )
    lines = [
        "# stack-correct-builder-demo",
        "",
        f"shape: m={shape.poly} q={shape.bonus_pool} s={shape.signed} b={shape.bonus}",
        f"round_script_bytes={round_build.script_bytes}",
        f"round_ops={round_build.ops}",
        f"round_witness_bytes={round_build.witness_bytes}",
        f"selected_poly={','.join(round_build.selected_poly)}",
        f"selected_bonus={','.join(round_build.selected_bonus)}",
        f"alternate_index_validation={alternate_status}",
        f"alternate_selected_poly={','.join(alternate.selected_poly)}",
        f"alternate_selected_bonus={','.join(alternate.selected_bonus)}",
    ]
    return "\n".join(lines)


def render_frontier() -> str:
    refs = {ref.name: ref for ref in corrected_references()}
    config_a = refs["configA_8p1b_7p2b"]
    baseline = refs["baseline_8_8"]
    best_by_total = best_points_by_setup_total()

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

    lines = ["# stack-correct-polyglot-frontier", ""]
    if first_config_a is None:
        lines.extend(["first_point_beating_configA: none", ""])
    else:
        setup_total, point = first_config_a
        lines.extend(render_point("first_point_beating_configA", setup_total, point))
        lines.append("")

    if first_baseline_collision is None:
        lines.extend(["first_point_beating_baseline_collision: none", ""])
    else:
        setup_total, point = first_baseline_collision
        lines.extend(render_point("first_point_beating_baseline_collision", setup_total, point))
        lines.append("")

    lines.append("best_stack_correct_points_by_setup_cap:")
    for cap in SEARCH_CAPS:
        feasible = [(setup, point) for setup, point in best_by_total.items() if setup <= cap]
        if not feasible:
            lines.append(f"  cap={cap}: none")
            continue
        setup, point = max(
            feasible,
            key=lambda item: (
                item[1].collision_bits,
                item[1].second_preimage_bits,
                -item[1].bytes,
                -item[1].witness_bytes,
            ),
        )
        lines.append(
            "  "
            + (
                f"cap={cap}: setup={setup} "
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


def render_point(name: str, setup_total: int, point: StackCorrectPoint) -> list[str]:
    return [
        f"{name}:",
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
    ]


def main() -> None:
    print(render_stack_correct_builder_demo())
    print()
    print(render_frontier())


if __name__ == "__main__":
    main()
