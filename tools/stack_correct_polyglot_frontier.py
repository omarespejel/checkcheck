#!/usr/bin/env python3
"""
Build a stack-correct polyglot round skeleton and rerun the frontier.

This is the implementation gate after frontier-17. The previous asymmetric
polyglot frontier was a budget model. Here we emit concrete Bitcoin Script
bytes for stack-correct split-pool rounds and simulate the stack movements
that matter.

Two signed-selection gadgets are implemented:

- signed selections pick a trusted polyglot element with OP_PICK for the
  HASH160 equality check, then OP_ROLL the same hardcoded element into the
  CHECKMULTISIG signature zone. This is conservative but too expensive;
- signed selections consume the index to OP_ROLL the trusted polyglot element
  once, then OP_DUP it before HASH160 equality checking. This avoids OP_PICK
  and the second pool OP_ROLL, and is the rescue gadget tested in frontier-19;
- bonus selections OP_ROLL from a separate dummy-signature pool;
- the puzzle/CHECKMULTISIG tail uses OP_SWAP, not the broken OP_2 OP_ROLL
  movement found in frontier-17.

This is still not a regtest transaction builder. It deliberately stops at the
round-script execution layer: stack movement, script bytes, and opcode counts.
"""

from __future__ import annotations

import argparse
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
    OP_OVER,
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


def qname(prefix: str, name: str) -> str:
    return f"{prefix}:{name}" if prefix else name


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

    @property
    def max_index(self) -> int:
        return max(self.poly, self.bonus_pool) - 1


@dataclass(frozen=True)
class RoundBuild:
    shape: RoundShape
    signed_gadget: str
    script: bytes
    script_bytes: int
    ops: int
    witness_bytes: int
    selected_poly: tuple[str, ...]
    selected_bonus: tuple[str, ...]


@dataclass(frozen=True)
class FullBuild:
    script: bytes
    script_bytes: int
    ops: int
    witness_bytes: int
    final_stack_depth: int


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
        elif opcode == OP_OVER:
            if len(self.stack) < 2:
                raise AssertionError("OP_OVER needs at least two stack items")
            self.stack.append(self.stack[-2])
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
            if key.kind != "data" or sig.kind not in {"data", "hash"}:
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
        # Bitcoin's MAX_OPS_PER_SCRIPT accounting charges CHECKMULTISIG by
        # pubkey count in addition to the opcode itself. python-bitcoinlib and
        # Bitcoin Core both add n here after the normal non-push opcode charge.
        self.ops += n
        pubkeys = [self.stack.pop() for _ in range(n)]
        m = self._pop_int("OP_CHECKMULTISIG m")
        sigs = [self.stack.pop() for _ in range(m)]
        dummy = self.stack.pop()
        if m != n:
            raise AssertionError(f"CHECKMULTISIG m/n mismatch: {m}/{n}")
        if dummy.name != "OP_0" and not dummy.name.endswith(":OP_0"):
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


def duplicate_selected_poly_by_index(machine: ScriptMachine, first_remaining_name: str) -> None:
    # Stack top is the sanitized index. This consumes the index to roll the
    # selected polyglot element once, then duplicates it. One copy is consumed
    # by HASH160/EQUALVERIFY and one remains as the CHECKMULTISIG signature.
    roll_by_index_from_pool(machine, first_remaining_name)
    machine.op(OP_DUP)


def round_witness_stack(
    shape: RoundShape,
    signed_indices: tuple[int, ...],
    bonus_indices: tuple[int, ...],
    selected_poly: tuple[str, ...],
    prefix: str = "",
) -> list[Item]:
    stack: list[Item] = [data(qname(prefix, "key_puzzle")), data(qname(prefix, "key_nonce"))]
    stack.extend(data(qname(prefix, f"pub{i}")) for i in reversed(range(shape.total)))
    stack.extend(
        preimage(qname(prefix, f"pre{i}"), selected_poly[i])
        for i in reversed(range(shape.signed))
    )
    index_values = tuple(signed_indices) + tuple(bonus_indices)
    stack.extend(named_int(qname(prefix, f"idx{i}"), index_values[i]) for i in reversed(range(shape.total)))
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


def selected_names(
    prefix: str,
    pool_prefix: str,
    pool_size: int,
    indices: tuple[int, ...],
) -> tuple[str, ...]:
    remaining = [qname(prefix, f"{pool_prefix}{i}") for i in range(pool_size)]
    return tuple(select_from_remaining(remaining, idx) for idx in indices)


def execute_round_script(
    machine: ScriptMachine,
    shape: RoundShape,
    signed_indices: tuple[int, ...],
    bonus_indices: tuple[int, ...],
    signed_gadget: str,
    prefix: str = "",
) -> RoundBuild:
    if signed_gadget not in {"copy_roll", "roll_dup"}:
        raise ValueError(f"unknown signed gadget: {signed_gadget}")
    if len(signed_indices) != shape.signed or len(bonus_indices) != shape.bonus:
        raise ValueError("index vector length does not match round shape")

    selected_poly = selected_names(prefix, "P", shape.poly, signed_indices)
    selected_bonus = selected_names(prefix, "B", shape.bonus_pool, bonus_indices)
    script_start = len(machine.script)
    ops_start = machine.ops

    for idx in range(shape.bonus_pool - 1, -1, -1):
        machine.push_data(data(qname(prefix, f"B{idx}")), 9)
    for idx in range(shape.poly - 1, -1, -1):
        machine.push_data(data(qname(prefix, f"P{idx}")), 20)
    machine.script.append(OP_0)
    machine.stack.append(data(qname(prefix, "OP_0")))
    machine.push_data(data(qname(prefix, "sig_nonce")), shape.sig_len)

    poly_remaining = [qname(prefix, f"P{i}") for i in range(shape.poly)]
    for selection_index, witness_index in enumerate(signed_indices):
        selected = poly_remaining[witness_index]

        roll_named(machine, qname(prefix, f"idx{selection_index}"))
        machine.push_int(len(poly_remaining) - 1)
        machine.op(OP_MIN)

        if signed_gadget == "copy_roll":
            pick_by_index_from_pool(machine, poly_remaining[0])
        else:
            duplicate_selected_poly_by_index(machine, poly_remaining[0])
        roll_named(machine, qname(prefix, f"pre{selection_index}"))
        machine.op(OP_HASH160)
        machine.op(OP_EQUALVERIFY)

        if signed_gadget == "copy_roll":
            roll_by_index_from_pool(machine, poly_remaining[0])
        actual = machine.stack[-1]
        if actual.name != selected:
            raise AssertionError(f"selected poly mismatch: expected {selected}, got {actual}")
        select_from_remaining(poly_remaining, witness_index)

    bonus_remaining = [qname(prefix, f"B{i}") for i in range(shape.bonus_pool)]
    for bonus_index, witness_index in enumerate(bonus_indices):
        selected = bonus_remaining[witness_index]

        roll_named(machine, qname(prefix, f"idx{shape.signed + bonus_index}"))
        machine.push_int(len(bonus_remaining) - 1)
        machine.op(OP_MIN)
        roll_by_index_from_pool(machine, bonus_remaining[0])
        actual = machine.stack[-1]
        if actual.name != selected:
            raise AssertionError(f"selected bonus mismatch: expected {selected}, got {actual}")
        select_from_remaining(bonus_remaining, witness_index)

    roll_named(machine, qname(prefix, "key_nonce"))
    machine.op(OP_DUP)
    machine.op(OP_RIPEMD160_OP)
    roll_named(machine, qname(prefix, "key_puzzle"))
    machine.op(OP_CHECKSIGVERIFY)

    multisig_count = shape.total + 1
    machine.push_int(multisig_count)
    machine.op(OP_SWAP)
    for pub_index in range(shape.total):
        roll_named(machine, qname(prefix, f"pub{pub_index}"))
    machine.push_int(multisig_count)
    machine.op(OP_CHECKMULTISIG)

    if not machine.stack or machine.stack[-1].name != "cms_true":
        raise AssertionError(f"unexpected final stack: {machine.stack}")

    return RoundBuild(
        shape=shape,
        signed_gadget=signed_gadget,
        script=bytes(machine.script[script_start:]),
        script_bytes=len(machine.script) - script_start,
        ops=machine.ops - ops_start,
        witness_bytes=witness_round_bytes(max(shape.poly, shape.bonus_pool) - 1, shape.signed, shape.bonus),
        selected_poly=selected_poly,
        selected_bonus=selected_bonus,
    )


def build_round(
    shape: RoundShape,
    signed_indices: tuple[int, ...] | None = None,
    bonus_indices: tuple[int, ...] | None = None,
    signed_gadget: str = "roll_dup",
) -> RoundBuild:
    signed_indices = signed_indices if signed_indices is not None else default_indices(shape.signed)
    bonus_indices = bonus_indices if bonus_indices is not None else default_indices(shape.bonus)
    selected_poly = selected_names("", "P", shape.poly, signed_indices)

    machine = ScriptMachine(round_witness_stack(shape, signed_indices, bonus_indices, selected_poly))
    return execute_round_script(machine, shape, signed_indices, bonus_indices, signed_gadget)


def witness_round_bytes(max_index: int, signed: int, bonus: int) -> int:
    idx_push = len(push_number(max_index))
    pubkey_push = len(push_data(b"\x02" + b"\x00" * 32))
    preimage_push = len(push_data(b"\x00" * 20))
    total = signed + bonus
    return 2 * pubkey_push + total * pubkey_push + signed * preimage_push + total * idx_push


def full_witness_stack(
    round1: RoundShape,
    round2: RoundShape,
    round1_signed_indices: tuple[int, ...],
    round1_bonus_indices: tuple[int, ...],
    round2_signed_indices: tuple[int, ...],
    round2_bonus_indices: tuple[int, ...],
) -> list[Item]:
    round1_selected_poly = selected_names("r1", "P", round1.poly, round1_signed_indices)
    round2_selected_poly = selected_names("r2", "P", round2.poly, round2_signed_indices)
    stack: list[Item] = []
    stack.extend(round_witness_stack(round2, round2_signed_indices, round2_bonus_indices, round2_selected_poly, "r2"))
    stack.extend(round_witness_stack(round1, round1_signed_indices, round1_bonus_indices, round1_selected_poly, "r1"))
    stack.extend([data("pin:key_puzzle"), data("pin:key_nonce")])
    return stack


def execute_pinning_script(machine: ScriptMachine, sig_len: int = 70) -> None:
    machine.push_data(data("pin:sig_nonce"), sig_len)
    machine.op(OP_OVER)
    machine.op(OP_CHECKSIGVERIFY)
    machine.op(OP_RIPEMD160_OP)
    machine.op(OP_SWAP)
    machine.op(OP_CHECKSIGVERIFY)


def build_full_script(
    round1: RoundShape,
    round2: RoundShape,
    signed_gadget: str = "roll_dup",
    round1_signed_indices: tuple[int, ...] | None = None,
    round1_bonus_indices: tuple[int, ...] | None = None,
    round2_signed_indices: tuple[int, ...] | None = None,
    round2_bonus_indices: tuple[int, ...] | None = None,
) -> FullBuild:
    round1_signed_indices = round1_signed_indices or default_indices(round1.signed)
    round1_bonus_indices = round1_bonus_indices or default_indices(round1.bonus)
    round2_signed_indices = round2_signed_indices or default_indices(round2.signed)
    round2_bonus_indices = round2_bonus_indices or default_indices(round2.bonus)

    machine = ScriptMachine(
        full_witness_stack(
            round1,
            round2,
            round1_signed_indices,
            round1_bonus_indices,
            round2_signed_indices,
            round2_bonus_indices,
        )
    )
    execute_pinning_script(machine)
    execute_round_script(
        machine,
        round1,
        round1_signed_indices,
        round1_bonus_indices,
        signed_gadget,
        "r1",
    )
    execute_round_script(
        machine,
        round2,
        round2_signed_indices,
        round2_bonus_indices,
        signed_gadget,
        "r2",
    )
    if not machine.stack or machine.stack[-1].name != "cms_true":
        raise AssertionError(f"unexpected full-script final stack: {machine.stack}")

    return FullBuild(
        script=bytes(machine.script),
        script_bytes=len(machine.script),
        ops=machine.ops,
        witness_bytes=(
            witness_round_bytes(round2.max_index, round2.signed, round2.bonus)
            + witness_round_bytes(round1.max_index, round1.signed, round1.bonus)
            + 2 * len(push_data(b"\x02" + b"\x00" * 32))
        ),
        final_stack_depth=len(machine.stack),
    )


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


def round_candidates(
    max_poly: int = MAX_POLY_PER_ROUND,
    signed_gadget: str = "roll_dup",
) -> list[RoundCandidate]:
    candidates: list[RoundCandidate] = []
    for poly in range(1, max_poly + 1):
        for signed in range(1, min(MAX_SIGNED_PER_ROUND, poly) + 1):
            signed_bits = log2_binom(poly, signed)
            for bonus in range(0, MAX_BONUS_PER_ROUND + 1):
                bonus_pool = min_bonus_pool_for(PINNING_BITS - signed_bits, bonus)
                if bonus_pool is None:
                    continue
                try:
                    round70 = build_round(
                        RoundShape(poly, bonus_pool, signed, bonus, 70),
                        signed_gadget=signed_gadget,
                    )
                    round71 = build_round(
                        RoundShape(poly, bonus_pool, signed, bonus, 71),
                        signed_gadget=signed_gadget,
                    )
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


def best_points_by_setup_total(
    max_setup_total: int = SEARCH_CAPS[-1],
    signed_gadget: str = "roll_dup",
    full_accounting: bool = False,
) -> dict[int, StackCorrectPoint]:
    candidates = round_candidates(
        max_poly=min(MAX_POLY_PER_ROUND, max_setup_total - 1),
        signed_gadget=signed_gadget,
    )
    best: dict[int, StackCorrectPoint] = {}
    for round1 in candidates:
        for round2 in candidates:
            setup_total = round1.poly + round2.poly
            if setup_total > max_setup_total:
                continue
            estimated_ops = 5 + round1.ops + round2.ops
            estimated_bytes = PINNING_BYTES + round1.bytes70 + round2.bytes71
            if estimated_ops > MAX_OPS or estimated_bytes > MAX_SCRIPT_BYTES + 750:
                continue
            if full_accounting:
                try:
                    full_build = build_full_script(
                        RoundShape(round1.poly, round1.bonus_pool, round1.signed, round1.bonus, 70),
                        RoundShape(round2.poly, round2.bonus_pool, round2.signed, round2.bonus, 71),
                        signed_gadget=signed_gadget,
                    )
                except (AssertionError, ValueError):
                    continue
                ops = full_build.ops
                bytes_ = full_build.script_bytes
            else:
                ops = estimated_ops
                bytes_ = estimated_bytes
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
    conservative = build_round(shape, signed_gadget="copy_roll")
    round_build = build_round(shape, signed_gadget="roll_dup")
    alternate = build_round(
        shape,
        signed_indices=last_remaining_indices(shape.poly, shape.signed),
        bonus_indices=last_remaining_indices(shape.bonus_pool, shape.bonus),
        signed_gadget="roll_dup",
    )
    alternate_status = (
        "pass"
        if alternate.script == round_build.script
        else "fail"
    )
    lines = [
        "# stack-correct-builder-demo",
        "",
        f"shape: m={shape.poly} q={shape.bonus_pool} s={shape.signed} b={shape.bonus}",
        f"conservative_round_script_bytes={conservative.script_bytes}",
        f"conservative_round_ops={conservative.ops}",
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


def render_frontier(signed_gadget: str = "roll_dup", full_accounting: bool = False) -> str:
    refs = {ref.name: ref for ref in corrected_references()}
    config_a = refs["configA_8p1b_7p2b"]
    baseline = refs["baseline_8_8"]
    best_by_total = best_points_by_setup_total(signed_gadget=signed_gadget, full_accounting=full_accounting)

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

    lines = [
        "# stack-correct-polyglot-frontier",
        "",
        f"signed_gadget={signed_gadget}",
        f"accounting={'full_script' if full_accounting else 'round_composed'}",
        "",
    ]
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


def validation_targets() -> tuple[tuple[str, RoundShape, RoundShape], ...]:
    return (
        (
            "configA_sigop_corrected_181",
            RoundShape(poly=79, bonus_pool=254, signed=7, bonus=2, sig_len=70),
            RoundShape(poly=102, bonus_pool=41, signed=9, bonus=1, sig_len=71),
        ),
        (
            "baseline_collision_sigop_corrected_258",
            RoundShape(poly=106, bonus_pool=308, signed=8, bonus=1, sig_len=70),
            RoundShape(poly=152, bonus_pool=0, signed=9, bonus=0, sig_len=71),
        ),
        (
            "cap300_sigop_corrected",
            RoundShape(poly=141, bonus_pool=30, signed=8, bonus=1, sig_len=70),
            RoundShape(poly=159, bonus_pool=0, signed=9, bonus=0, sig_len=71),
        ),
    )


def render_full_script_validation(signed_gadget: str = "roll_dup") -> str:
    lines = [
        "# full-script-validation",
        "",
        f"signed_gadget={signed_gadget}",
        "semantics=top_stack_truth",
        "",
    ]
    for name, round1, round2 in validation_targets():
        round1_build = build_round(round1, signed_gadget=signed_gadget)
        round2_build = build_round(round2, signed_gadget=signed_gadget)
        round_composed_bytes = PINNING_BYTES + round1_build.script_bytes + round2_build.script_bytes
        round_composed_ops = 5 + round1_build.ops + round2_build.ops
        default = build_full_script(round1, round2, signed_gadget=signed_gadget)
        alternate = build_full_script(
            round1,
            round2,
            signed_gadget=signed_gadget,
            round1_signed_indices=last_remaining_indices(round1.poly, round1.signed),
            round1_bonus_indices=last_remaining_indices(round1.bonus_pool, round1.bonus),
            round2_signed_indices=last_remaining_indices(round2.poly, round2.signed),
            round2_bonus_indices=last_remaining_indices(round2.bonus_pool, round2.bonus),
        )
        same_script = "pass" if default.script == alternate.script else "fail"
        limits = "pass" if default.ops <= MAX_OPS and default.script_bytes <= MAX_SCRIPT_BYTES else "fail"
        cleanstack = "pass" if default.final_stack_depth == 1 else "fail"
        lines.extend(
            [
                f"{name}:",
                f"  r1: m={round1.poly} q={round1.bonus_pool} s={round1.signed} b={round1.bonus}",
                f"  r2: m={round2.poly} q={round2.bonus_pool} s={round2.signed} b={round2.bonus}",
                f"  round_composed_bytes={round_composed_bytes}",
                f"  round_composed_ops={round_composed_ops}",
                f"  full_script_bytes={default.script_bytes}",
                f"  full_ops={default.ops}",
                f"  byte_delta={default.script_bytes - round_composed_bytes}",
                f"  op_delta={default.ops - round_composed_ops}",
                f"  witness_bytes={default.witness_bytes}",
                f"  final_stack_depth={default.final_stack_depth}",
                f"  consensus_limit_check={limits}",
                f"  cleanstack_depth_one_check={cleanstack}",
                f"  alternate_index_same_script={same_script}",
                f"  alternate_final_stack_depth={alternate.final_stack_depth}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


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
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--signed-gadget",
        choices=("roll_dup", "copy_roll"),
        default="roll_dup",
        help="signed-selection gadget to use for the frontier search",
    )
    args = parser.parse_args()
    print(render_stack_correct_builder_demo())
    print()
    print(render_frontier(signed_gadget=args.signed_gadget))
    print()
    print(render_full_script_validation(signed_gadget=args.signed_gadget))


if __name__ == "__main__":
    main()
