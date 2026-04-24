#!/usr/bin/env python3
"""
Frontier model for no-softfork hash-based Bitcoin spend constructions.

This tool is intentionally small and dependency-free. The initial numbers are
model values, not calibrated generator outputs. The goal in v0 is to compare
candidate families under the same assumptions and make the tradeoffs explicit.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import lgamma, log, log2
from typing import Iterable


def log2_binom(n: int, k: int) -> float:
    if k < 0 or k > n:
        raise ValueError(f"invalid binomial parameters: n={n}, k={k}")
    return (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)) / log(2)


def sum_log2(values: Iterable[int]) -> float:
    total = 0.0
    for value in values:
        if value <= 0:
            raise ValueError(f"group size must be positive, got {value}")
        total += log2(value)
    return total


@dataclass(frozen=True)
class Limits:
    max_non_push_opcodes: int = 201
    max_script_bytes: int = 10_000


@dataclass(frozen=True)
class CandidateReport:
    name: str
    digest_bits: float
    estimated_script_bytes: int
    estimated_non_push_opcodes: int
    tuning_slack_bits: float
    notes: str

    def render(self) -> str:
        return "\n".join(
            [
                f"name: {self.name}",
                f"digest_bits: {self.digest_bits:.2f}",
                f"estimated_script_bytes: {self.estimated_script_bytes}",
                f"estimated_non_push_opcodes: {self.estimated_non_push_opcodes}",
                f"tuning_slack_bits: {self.tuning_slack_bits:.2f}",
                f"notes: {self.notes}",
            ]
        )


def hors_baseline_report(
    n: int,
    k_per_round: list[int],
    estimated_script_bytes: int,
    estimated_non_push_opcodes: int,
    puzzle_target_bits: float = 46.4,
) -> CandidateReport:
    digest_bits = sum(log2_binom(n, k) for k in k_per_round)
    # Slack here captures how tightly each round can be matched to the fixed
    # hash-to-signature puzzle target. Lower absolute slack is better.
    tuning_slack_bits = sum(abs(log2_binom(n, k) - puzzle_target_bits) for k in k_per_round)
    return CandidateReport(
        name=f"hors(n={n}, rounds={k_per_round})",
        digest_bits=digest_bits,
        estimated_script_bytes=estimated_script_bytes,
        estimated_non_push_opcodes=estimated_non_push_opcodes,
        tuning_slack_bits=tuning_slack_bits,
        notes="Raw combinatorial subset entropy. Calibrate against imported QSB scripts before mapping to effective digest/security bits.",
    )


def grouped_choice_report(
    group_sizes: list[int],
    estimated_script_bytes: int,
    estimated_non_push_opcodes: int,
    puzzle_target_bits: float = 46.4,
) -> CandidateReport:
    digest_bits = sum_log2(group_sizes)
    # For grouped-choice candidates, tuning slack is the absolute gap between
    # achievable choice entropy and the desired search target.
    tuning_slack_bits = abs(digest_bits - puzzle_target_bits)
    return CandidateReport(
        name=f"grouped_choice(groups={group_sizes})",
        digest_bits=digest_bits,
        estimated_script_bytes=estimated_script_bytes,
        estimated_non_push_opcodes=estimated_non_push_opcodes,
        tuning_slack_bits=tuning_slack_bits,
        notes="Raw grouped-choice entropy. Needs a calibrated security model for limited-use reuse and collision bounds.",
    )


def main() -> None:
    reports = [
        hors_baseline_report(
            n=150,
            k_per_round=[9, 9],
            estimated_script_bytes=9_500,
            estimated_non_push_opcodes=201,
        ),
        grouped_choice_report(
            group_sizes=[8] * 15,
            estimated_script_bytes=7_800,
            estimated_non_push_opcodes=168,
        ),
    ]

    print("# frontier-model")
    for report in reports:
        print()
        print(report.render())


if __name__ == "__main__":
    main()
