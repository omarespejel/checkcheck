#!/usr/bin/env python3
"""
Concrete byte-level interpreter gate for the polyglot frontier.

Frontier-20 validated stack movement symbolically. This tool emits concrete
script and scriptSig bytes for the strongest frontier-20 point, then runs those
bytes through python-bitcoinlib's Script evaluator with signature checks stubbed
out. That is intentionally narrower than a real spend: it validates script
parsing, push encodings, stack movement, HASH160/RIPEMD160 equality checks,
opcode accounting, and CLEANSTACK behavior, while explicitly not claiming ECDSA
or sighash validity.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import importlib.metadata
from pathlib import Path
import sys
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
UPSTREAM_PIPELINE = ROOT / "third_party" / "qsb-avihu" / "pipeline"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
if str(UPSTREAM_PIPELINE) not in sys.path:
    sys.path.insert(0, str(UPSTREAM_PIPELINE))

from bitcoin_tx import push_data, push_number  # type: ignore
from polyglot_setup_frontier import MAX_OPS, MAX_SCRIPT_BYTES  # type: ignore
from stack_correct_polyglot_frontier import (  # type: ignore
    FullBuild,
    Item,
    RoundShape,
    ScriptMachine,
    default_indices,
    execute_pinning_script,
    execute_round_script,
    full_witness_stack,
    last_remaining_indices,
    qname,
    selected_names,
    validation_targets,
)


TARGET_NAME = "baseline_collision_sigop_corrected_258"


@dataclass(frozen=True)
class ConcreteArtifact:
    name: str
    round1: RoundShape
    round2: RoundShape
    script_pubkey: bytes
    script_sig: bytes
    initial_stack: tuple[bytes, ...]
    full_build: FullBuild
    selection_mode: str


class ConcreteScriptMachine(ScriptMachine):
    def __init__(self, stack: list[Item], payloads: dict[str, bytes]) -> None:
        super().__init__(stack)
        self.payloads = payloads

    def push_data(self, item: Item, size: int) -> None:
        payload = self.payloads[item.name]
        if len(payload) != size:
            raise AssertionError(
                f"payload size mismatch for {item.name}: expected {size}, got {len(payload)}"
            )
        self.script.extend(push_data(payload))
        self.stack.append(item)


def hash160(value: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(value).digest()).digest()


def deterministic_bytes(name: str, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(hashlib.sha256(f"checkcheck:{name}:{counter}".encode()).digest())
        counter += 1
    return bytes(out[:size])


def deterministic_pubkey(name: str) -> bytes:
    return bytes([0x02]) + deterministic_bytes(name, 32)


def script_num_bytes(value: int) -> bytes:
    if value == 0:
        return b""
    if value < 0:
        raise ValueError("negative script numbers are not used here")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "little")
    if raw[-1] & 0x80:
        raw += b"\x00"
    return raw


def item_payload(item: Item, payloads: dict[str, bytes]) -> bytes:
    if item.kind == "int":
        if item.value is None:
            raise AssertionError(f"missing int value for {item.name}")
        return script_num_bytes(item.value)
    if item.name.endswith(":OP_0") or item.name == "OP_0":
        return b""
    return payloads[item.name]


def script_sig_from_stack(stack: list[Item], payloads: dict[str, bytes]) -> bytes:
    script = bytearray()
    for item in stack:
        script.extend(push_data(item_payload(item, payloads)))
    return bytes(script)


def add_round_payloads(
    payloads: dict[str, bytes],
    shape: RoundShape,
    prefix: str,
    signed_indices: tuple[int, ...],
) -> None:
    selected_poly = selected_names(prefix, "P", shape.poly, signed_indices)

    payloads[qname(prefix, "key_puzzle")] = deterministic_pubkey(qname(prefix, "key_puzzle"))
    payloads[qname(prefix, "key_nonce")] = deterministic_pubkey(qname(prefix, "key_nonce"))
    payloads[qname(prefix, "sig_nonce")] = deterministic_bytes(qname(prefix, "sig_nonce"), shape.sig_len)

    for pub_index in range(shape.total):
        payloads[qname(prefix, f"pub{pub_index}")] = deterministic_pubkey(qname(prefix, f"pub{pub_index}"))

    for bonus_index in range(shape.bonus_pool):
        payloads[qname(prefix, f"B{bonus_index}")] = deterministic_bytes(qname(prefix, f"B{bonus_index}"), 9)

    poly_secrets: dict[str, bytes] = {}
    for poly_index in range(shape.poly):
        poly_name = qname(prefix, f"P{poly_index}")
        secret = deterministic_bytes(qname(prefix, f"S{poly_index}"), 20)
        poly_secrets[poly_name] = secret
        payloads[poly_name] = hash160(secret)

    for pre_index, poly_name in enumerate(selected_poly):
        pre_name = qname(prefix, f"pre{pre_index}")
        payloads[pre_name] = poly_secrets[poly_name]


def payloads_for_full_script(
    round1: RoundShape,
    round2: RoundShape,
    round1_signed_indices: tuple[int, ...],
    round2_signed_indices: tuple[int, ...],
) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {
        "pin:key_puzzle": deterministic_pubkey("pin:key_puzzle"),
        "pin:key_nonce": deterministic_pubkey("pin:key_nonce"),
        "pin:sig_nonce": deterministic_bytes("pin:sig_nonce", 70),
    }
    add_round_payloads(payloads, round1, "r1", round1_signed_indices)
    add_round_payloads(payloads, round2, "r2", round2_signed_indices)
    return payloads


def target_shapes() -> tuple[RoundShape, RoundShape]:
    for name, round1, round2 in validation_targets():
        if name == TARGET_NAME:
            return round1, round2
    raise RuntimeError(f"missing validation target {TARGET_NAME}")


def indices_for(mode: str, shape: RoundShape) -> tuple[tuple[int, ...], tuple[int, ...]]:
    if mode == "default":
        return default_indices(shape.signed), default_indices(shape.bonus)
    if mode == "last":
        return (
            last_remaining_indices(shape.poly, shape.signed),
            last_remaining_indices(shape.bonus_pool, shape.bonus),
        )
    raise ValueError(f"unknown selection mode: {mode}")


def build_concrete_artifact(selection_mode: str = "default") -> ConcreteArtifact:
    round1, round2 = target_shapes()
    r1_signed, r1_bonus = indices_for(selection_mode, round1)
    r2_signed, r2_bonus = indices_for(selection_mode, round2)
    payloads = payloads_for_full_script(round1, round2, r1_signed, r2_signed)
    initial_stack = full_witness_stack(round1, round2, r1_signed, r1_bonus, r2_signed, r2_bonus)
    machine = ConcreteScriptMachine(initial_stack.copy(), payloads)

    execute_pinning_script(machine)
    execute_round_script(machine, round1, r1_signed, r1_bonus, "roll_dup", "r1")
    execute_round_script(machine, round2, r2_signed, r2_bonus, "roll_dup", "r2")

    script_sig = script_sig_from_stack(initial_stack, payloads)
    stack_payloads = tuple(item_payload(item, payloads) for item in initial_stack)
    return ConcreteArtifact(
        name=TARGET_NAME,
        round1=round1,
        round2=round2,
        script_pubkey=bytes(machine.script),
        script_sig=script_sig,
        initial_stack=stack_payloads,
        full_build=FullBuild(
            script=bytes(machine.script),
            script_bytes=len(machine.script),
            ops=machine.ops,
            witness_bytes=sum(len(push_data(item)) for item in stack_payloads),
            final_stack_depth=len(machine.stack),
        ),
        selection_mode=selection_mode,
    )


def require_python_bitcoinlib() -> tuple[object, object, object, object]:
    try:
        from bitcoin.core import CMutableTransaction, CMutableTxIn, CMutableTxOut
        from bitcoin.core import COutPoint
        from bitcoin.core.script import CScript
        import bitcoin.core.scripteval as scripteval
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "missing dependency: python-bitcoinlib. "
            "Install with `python3 -m pip install -r requirements-interpreter.txt`."
        ) from exc
    return CScript, CMutableTransaction, (CMutableTxIn, CMutableTxOut, COutPoint), scripteval


def run_verify_script(
    artifact: ConcreteArtifact,
    *,
    cleanstack: bool,
    stub_signatures: bool,
) -> tuple[bool, str]:
    CScript, _, tx_types, scripteval = require_python_bitcoinlib()
    from bitcoin.core import CMutableTransaction

    txin_type, txout_type, outpoint_type = tx_types
    tx = CMutableTransaction(
        [txin_type(outpoint_type(b"\x00" * 32, 0), b"", 0xFFFFFFFF)],
        [txout_type(1, b"\x51")],
    )
    flags: tuple[object, ...] = ()
    if cleanstack:
        flags = (scripteval.SCRIPT_VERIFY_P2SH, scripteval.SCRIPT_VERIFY_CLEANSTACK)

    original_checksig: Callable[..., bool] | None = None
    if stub_signatures:
        original_checksig = scripteval._CheckSig
        scripteval._CheckSig = lambda *args, **kwargs: True
    try:
        scripteval.VerifyScript(
            CScript(artifact.script_sig),
            CScript(artifact.script_pubkey),
            tx,
            0,
            flags=flags,
        )
    except Exception as exc:  # noqa: BLE001 - report the external interpreter error.
        return False, f"{exc.__class__.__name__}: {exc}"
    finally:
        if original_checksig is not None:
            scripteval._CheckSig = original_checksig
    return True, "pass"


def render_gate(selection_mode: str = "default") -> str:
    artifact = build_concrete_artifact(selection_mode)
    try:
        pybitcoinlib_version = importlib.metadata.version("python-bitcoinlib")
    except importlib.metadata.PackageNotFoundError:
        pybitcoinlib_version = "missing"
    consensus_stubbed = run_verify_script(artifact, cleanstack=False, stub_signatures=True)
    cleanstack_stubbed = run_verify_script(artifact, cleanstack=True, stub_signatures=True)
    real_crypto = run_verify_script(artifact, cleanstack=False, stub_signatures=False)
    alternate = build_concrete_artifact("last" if selection_mode == "default" else "default")

    lines = [
        "# polyglot-interpreter-gate",
        "",
        f"target={artifact.name}",
        f"selection_mode={artifact.selection_mode}",
        f"python_bitcoinlib_version={pybitcoinlib_version}",
        f"script_pubkey_bytes={len(artifact.script_pubkey)}",
        f"script_sig_bytes={len(artifact.script_sig)}",
        f"initial_stack_items={len(artifact.initial_stack)}",
        f"consensus_counted_ops={artifact.full_build.ops}",
        f"final_symbolic_stack_depth={artifact.full_build.final_stack_depth}",
        f"consensus_limit_check={'pass' if len(artifact.script_pubkey) <= MAX_SCRIPT_BYTES and artifact.full_build.ops <= MAX_OPS else 'fail'}",
        f"alternate_selection_same_script={'pass' if artifact.script_pubkey == alternate.script_pubkey else 'fail'}",
        "",
        "external_interpreter_results:",
        f"  stubbed_signatures_no_cleanstack={status_line(consensus_stubbed)}",
        f"  stubbed_signatures_with_cleanstack={status_line(cleanstack_stubbed)}",
        f"  real_crypto_no_cleanstack={status_line(real_crypto)}",
        "",
        "script_pubkey_prefix_hex=" + artifact.script_pubkey[:40].hex(),
        "script_pubkey_suffix_hex=" + artifact.script_pubkey[-40:].hex(),
    ]
    return "\n".join(lines)


def status_line(result: tuple[bool, str]) -> str:
    ok, detail = result
    return "pass" if ok else f"fail ({detail})"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection-mode", choices=("default", "last"), default="default")
    args = parser.parse_args()
    print(render_gate(args.selection_mode))


if __name__ == "__main__":
    main()
