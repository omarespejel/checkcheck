#!/usr/bin/env python3
"""
Trusted-setup sizing and toy probe for the polyglot frontier.

This tool does not try to finish the real setup on a laptop. The corrected
frontier needs hundreds of HASH160 preimages whose 20-byte commitments also
parse as ECDSA signatures. That is a ~2^54-class setup for the first corrected
baseline-collision point. The tool makes that cost explicit, benchmarks the
local HASH160 loop, and runs a smaller toy predicate to validate the artifact
shape without pretending the real search completed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from math import log2
from pathlib import Path
import secrets
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
UPSTREAM_PIPELINE = ROOT / "third_party" / "qsb-avihu" / "pipeline"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
if str(UPSTREAM_PIPELINE) not in sys.path:
    sys.path.insert(0, str(UPSTREAM_PIPELINE))

from polyglot_setup_frontier import GHASH, TEN_GHASH, days_at_rate, setup_hashes_for  # type: ignore
from secp256k1 import P, is_valid_der_sig  # type: ignore
from stack_correct_polyglot_frontier import RoundShape, validation_targets  # type: ignore


@dataclass(frozen=True)
class SetupTarget:
    name: str
    round1: RoundShape
    round2: RoundShape

    @property
    def setup_elements(self) -> int:
        return self.round1.poly + self.round2.poly


@dataclass(frozen=True)
class ToyHit:
    index: int
    secret_hex: str
    commitment_hex: str
    trials: int


def hash160(value: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(value).digest()).digest()


def der_integer_encoding_count(length: int) -> int:
    if length < 1:
        return 0
    # Positive non-negative encodings without avoidable leading zeroes.
    # For length 1, exclude zero because ECDSA r/s=0 cannot verify.
    high_bit_clear_nonzero = 127 * (256 ** (length - 1))
    if length == 1:
        return high_bit_clear_nonzero
    leading_zero_for_positive_high_bit = 128 * (256 ** (length - 2))
    return high_bit_clear_nonzero + leading_zero_for_positive_high_bit


def valid_der20_structural_count() -> int:
    total = 0
    for r_len in range(1, 13):
        s_len = 13 - r_len
        if s_len < 1:
            continue
        total += der_integer_encoding_count(r_len) * der_integer_encoding_count(s_len)
    # Last sighash byte is unconstrained at consensus level.
    return total * 256


def der20_probability_bits() -> float:
    return 160 - log2(valid_der20_structural_count())


def valid_r_x_coordinate(sig: bytes) -> bool:
    if not is_valid_der_sig(sig):
        return False
    idx = 2
    if sig[idx] != 0x02:
        return False
    r_len = sig[idx + 1]
    r = int.from_bytes(sig[idx + 2 : idx + 2 + r_len], "big")
    if r <= 0 or r >= P:
        return False
    y_sq = (pow(r, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    return pow(y, 2, P) == y_sq


def benchmark_hash160(duration_seconds: float) -> tuple[int, float]:
    start = time.perf_counter()
    deadline = start + duration_seconds
    trials = 0
    seed = secrets.token_bytes(32)
    while time.perf_counter() < deadline:
        material = seed + trials.to_bytes(8, "little")
        hash160(material)
        trials += 1
    elapsed = max(time.perf_counter() - start, 1e-9)
    return trials, trials / elapsed


def toy_predicate(commitment: bytes, bits: int) -> bool:
    whole_bytes, extra_bits = divmod(bits, 8)
    if whole_bytes and commitment[:whole_bytes] != b"\x00" * whole_bytes:
        return False
    if extra_bits == 0:
        return True
    mask = 0xFF << (8 - extra_bits) & 0xFF
    return commitment[whole_bytes] & mask == 0


def run_toy_setup(count: int, bits: int) -> tuple[list[ToyHit], int, float]:
    hits: list[ToyHit] = []
    trials = 0
    start = time.perf_counter()
    while len(hits) < count:
        secret = secrets.token_bytes(20)
        commitment = hash160(secret)
        trials += 1
        if toy_predicate(commitment, bits):
            hits.append(
                ToyHit(
                    index=len(hits),
                    secret_hex=secret.hex(),
                    commitment_hex=commitment.hex(),
                    trials=trials,
                )
            )
    elapsed = max(time.perf_counter() - start, 1e-9)
    return hits, trials, elapsed


def limited_real_der_probe(max_trials: int) -> tuple[int, int]:
    structural_hits = 0
    recoverable_hits = 0
    for _ in range(max_trials):
        commitment = hash160(secrets.token_bytes(20))
        if is_valid_der_sig(commitment):
            structural_hits += 1
            if valid_r_x_coordinate(commitment):
                recoverable_hits += 1
    return structural_hits, recoverable_hits


def target_by_name(name: str) -> SetupTarget:
    for target_name, round1, round2 in validation_targets():
        if target_name == name:
            return SetupTarget(target_name, round1, round2)
    choices = ", ".join(target_name for target_name, _, _ in validation_targets())
    raise SystemExit(f"unknown target {name!r}; choices: {choices}")


def fmt_days(hashes: float, rate: float) -> str:
    return f"{days_at_rate(hashes, rate):.2f}d"


def render_probe(args: argparse.Namespace) -> str:
    target = target_by_name(args.target)
    der_bits = der20_probability_bits()
    expected_setup_hashes = setup_hashes_for(target.setup_elements)
    expected_recoverable_setup_hashes = expected_setup_hashes * 2
    benchmark_trials, benchmark_rate = benchmark_hash160(args.benchmark_seconds)
    local_days = expected_setup_hashes / benchmark_rate / 86_400
    toy_hits, toy_trials, toy_elapsed = run_toy_setup(args.toy_count, args.toy_bits)
    real_structural_hits, real_recoverable_hits = limited_real_der_probe(args.real_probe_trials)

    expected_toy_trials = args.toy_count * (2 ** args.toy_bits)
    toy_ratio = toy_trials / expected_toy_trials if expected_toy_trials else 0.0

    lines = [
        "# polyglot-trusted-setup-probe",
        "",
        f"target={target.name}",
        f"setup_elements={target.setup_elements}",
        f"r1=m{target.round1.poly}/q{target.round1.bonus_pool}/s{target.round1.signed}/b{target.round1.bonus}",
        f"r2=m{target.round2.poly}/q{target.round2.bonus_pool}/s{target.round2.signed}/b{target.round2.bonus}",
        "",
        "real_der20_target:",
        f"  structural_probability_bits={der_bits:.4f}",
        f"  expected_setup_hashes=2^{log2(expected_setup_hashes):.2f}",
        f"  approx_recoverable_setup_hashes=2^{log2(expected_recoverable_setup_hashes):.2f}",
        f"  expected_setup_days_at_1GH={fmt_days(expected_setup_hashes, GHASH)}",
        f"  expected_setup_days_at_10GH={fmt_days(expected_setup_hashes, TEN_GHASH)}",
        f"  expected_setup_hours_at_1TH={expected_setup_hashes / 1_000_000_000_000 * 24 / 86_400:.2f}",
        "",
        "local_benchmark:",
        f"  duration_seconds={args.benchmark_seconds:.2f}",
        f"  trials={benchmark_trials}",
        f"  hash160_per_second={benchmark_rate:.0f}",
        f"  estimated_local_days_for_real_setup={local_days:.1f}",
        "",
        "toy_setup_probe:",
        f"  toy_bits={args.toy_bits}",
        f"  requested_hits={args.toy_count}",
        f"  trials={toy_trials}",
        f"  elapsed_seconds={toy_elapsed:.3f}",
        f"  expected_trials={expected_toy_trials:.0f}",
        f"  observed_over_expected={toy_ratio:.3f}",
        f"  first_hit_secret={toy_hits[0].secret_hex if toy_hits else 'none'}",
        f"  first_hit_commitment={toy_hits[0].commitment_hex if toy_hits else 'none'}",
        "",
        "limited_real_der_probe:",
        f"  trials={args.real_probe_trials}",
        f"  structural_hits={real_structural_hits}",
        f"  recoverable_r_hits={real_recoverable_hits}",
        "",
        "decision:",
        "  local_full_setup=NO-GO",
        "  gpu_or_distributed_setup=REQUIRED",
        "  next_crypto_gate=export target-specific GPU setup artifacts, not more script tuning",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target",
        default="baseline_collision_sigop_corrected_258",
        help="validation target from stack_correct_polyglot_frontier.py",
    )
    parser.add_argument("--benchmark-seconds", type=float, default=0.5)
    parser.add_argument("--toy-count", type=int, default=4)
    parser.add_argument("--toy-bits", type=int, default=16)
    parser.add_argument("--real-probe-trials", type=int, default=100_000)
    args = parser.parse_args()
    print(render_probe(args))


if __name__ == "__main__":
    main()
