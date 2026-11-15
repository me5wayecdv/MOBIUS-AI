"""Benchmark harness: the only place precision is allowed to be a number.

The project's claims audit says "MOBIUS reduces false positives" becomes true when it is
measured on a held-out set. This module is the measuring instrument, and it is built to make
the absence of a corpus loud rather than quiet:

* an empty corpus returns ``measured=False`` and no metrics at all, never ``1.0``;
* every rate is reported with the count it came from, so ``precision 1.00`` on two samples
  is visible as ``1 of 1`` rather than as a result;
* a sample that failed to analyse is ``error``, not ``benign`` - a crash must not look like
  a correct rejection.

What is measured is deliberately narrow: whether the pipeline reports at least one confirmed
finding for a sample labelled vulnerable, and none for a sample labelled benign. It does not
measure whether the *right* weakness was named, because no labelled findings exist yet.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

VULNERABLE = "vulnerable"
BENIGN = "benign"
LABELS = (VULNERABLE, BENIGN)


@dataclass(frozen=True, slots=True)
class Sample:
    """One APK with a human-assigned label."""

    name: str
    label: str
    apk_path: str
    #: Free-text: who labelled it and why. Required, because an unlabelled "benign" is a
    #: guess and this harness must not turn guesses into precision.
    note: str = ""

    def validate(self) -> None:
        if self.label not in LABELS:
            raise ValueError(f"sample {self.name!r}: label must be one of {LABELS}")
        if not self.note.strip():
            raise ValueError(
                f"sample {self.name!r}: a label without a stated basis is a guess; "
                "record who assigned it and on what evidence"
            )


@dataclass(frozen=True, slots=True)
class Outcome:
    name: str
    label: str
    confirmed: int
    manual_review: int = 0
    error: str | None = None

    @property
    def flagged(self) -> bool:
        return self.confirmed > 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "confirmed": self.confirmed,
            "manual_review": self.manual_review,
            "flagged": self.flagged,
            "error": self.error,
        }


#: Takes APK bytes and returns the pipeline's counts. Injected so the metric logic is
#: testable without an APK, a database or a toolchain.
Analyser = Callable[[bytes], Mapping[str, int]]


@dataclass(frozen=True, slots=True)
class Result:
    outcomes: tuple[Outcome, ...]
    measured: bool
    metrics: dict[str, Any] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "measured": self.measured,
            "samples": len(self.outcomes),
            "metrics": self.metrics,
            "outcomes": [o.as_dict() for o in self.outcomes],
            "notes": list(self.notes),
        }


def measure(samples: Iterable[Sample], analyser: Analyser) -> Result:
    """Run every sample through the analyser and compute the rates.

    Raises:
        ValueError: a sample has an unknown label or no stated basis for it.
    """
    checked = list(samples)
    for sample in checked:
        sample.validate()

    outcomes: list[Outcome] = []
    for sample in checked:
        try:
            with open(sample.apk_path, "rb") as handle:
                counts = analyser(handle.read())
        except Exception as exc:  # noqa: BLE001 - a failure is data, not a crash
            outcomes.append(
                Outcome(sample.name, sample.label, 0, 0, f"{type(exc).__name__}: {exc}")
            )
            continue
        outcomes.append(
            Outcome(
                sample.name,
                sample.label,
                int(counts.get("confirmed", 0)),
                int(counts.get("manual_review", 0)),
            )
        )

    return summarise(tuple(outcomes))


def summarise(outcomes: tuple[Outcome, ...]) -> Result:
    """Compute the rates from outcomes. Pure, so it can be reviewed on its own."""
    if not outcomes:
        return Result(
            outcomes=(),
            measured=False,
            notes=(
                "no corpus: precision and recall are UNMEASURED. No number in this project "
                "may be cited as a benchmark result until this harness is given labelled "
                "samples.",
            ),
        )

    errors = [o for o in outcomes if o.error is not None]
    scored = [o for o in outcomes if o.error is None]
    if not scored:
        return Result(
            outcomes=outcomes,
            measured=False,
            notes=(
                f"all {len(errors)} sample(s) failed to analyse; there is nothing to score. "
                "A failed analysis is not a correct rejection.",
            ),
        )

    true_pos = [o for o in scored if o.label == VULNERABLE and o.flagged]
    false_pos = [o for o in scored if o.label == BENIGN and o.flagged]
    false_neg = [o for o in scored if o.label == VULNERABLE and not o.flagged]
    true_neg = [o for o in scored if o.label == BENIGN and not o.flagged]

    notes: list[str] = []
    if errors:
        notes.append(
            f"{len(errors)} of {len(outcomes)} sample(s) could not be analysed and are "
            "excluded from the rates below, not counted as rejections"
        )

    def rate(numerator: int, denominator: int) -> float | None:
        return None if denominator == 0 else round(numerator / denominator, 4)

    # Precision over flagged samples: of everything the pipeline flagged, how much was
    # actually vulnerable. Undefined when nothing was flagged - not 1.0.
    precision = rate(len(true_pos), len(true_pos) + len(false_pos))
    recall = rate(len(true_pos), len(true_pos) + len(false_neg))
    # The number the claims audit actually cares about: how many benign controls were left
    # alone.
    specificity = rate(len(true_neg), len(true_neg) + len(false_pos))

    metrics = {
        "precision": precision,
        "recall": recall,
        "benign_specificity": specificity,
        "flagged": len(true_pos) + len(false_pos),
        "counts": {
            "true_positive": len(true_pos),
            "false_positive": len(false_pos),
            "false_negative": len(false_neg),
            "true_negative": len(true_neg),
            "error": len(errors),
        },
    }
    if precision is None:
        notes.append("precision undefined: the pipeline flagged nothing")
    if recall is None:
        notes.append("recall undefined: the corpus contains no vulnerable sample")
    if specificity is None:
        notes.append(
            "benign specificity undefined: the corpus contains no benign sample, so false "
            "positives were never tested"
        )
    notes.append(
        "rates count samples flagged as a whole, not the correctness of individual "
        "findings: a scan that confirms the wrong weakness still counts as flagged"
    )

    return Result(outcomes=outcomes, measured=True, metrics=metrics, notes=tuple(notes))


def load_corpus(payload: Mapping[str, Any]) -> list[Sample]:
    """Parse a corpus manifest: ``{"samples": [...]}``."""
    samples = []
    for raw in payload.get("samples", []):
        samples.append(
            Sample(
                name=raw["name"],
                label=raw["label"],
                apk_path=raw["apk_path"],
                note=raw.get("note", ""),
            )
        )
    return samples


__all__ = ["Sample", "Outcome", "Result", "measure", "summarise", "load_corpus"]
