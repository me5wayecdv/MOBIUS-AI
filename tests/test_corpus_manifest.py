"""The corpus manifest is an input to a measurement, so it is tested like one.

These checks are cheap and they prevent the most likely failure: a corpus that silently stops
being what the published numbers were computed on.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

MANIFEST = Path(__file__).resolve().parent.parent / "corpus" / "corpus.json"
SHA = re.compile(r"^[0-9a-f]{64}$")


@pytest.fixture(scope="module")
def corpus() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_every_sample_pins_a_full_sha256(corpus):
    for sample in corpus["samples"]:
        assert SHA.match(sample["sha256"]), f"{sample['name']}: hash is not a pinned sha256"


def test_every_sample_states_the_basis_of_its_label(corpus):
    """A label without a stated basis is a guess, and a guess becomes a precision figure."""
    for sample in corpus["samples"]:
        assert sample["note"].strip(), f"{sample['name']}: label has no stated basis"
        assert len(sample["note"]) > 40, f"{sample['name']}: note is too thin to audit"


def test_labels_are_ones_the_harness_accepts(corpus):
    from mobius.services.benchmark import LABELS

    for sample in corpus["samples"]:
        assert sample["label"] in LABELS


def test_sample_names_are_unique(corpus):
    names = [s["name"] for s in corpus["samples"]]
    assert len(names) == len(set(names))


def test_files_are_unique(corpus):
    """Two samples sharing a file would be one sample counted twice."""
    files = [s["file"] for s in corpus["samples"]]
    assert len(files) == len(set(files))


def test_the_corpus_contains_both_labels(corpus):
    labels = {s["label"] for s in corpus["samples"]}
    assert labels == {"vulnerable", "benign"}, (
        "a corpus with one label cannot measure precision or specificity"
    )


def test_the_manifest_loads_through_the_harness_loader(corpus):
    from mobius.services.benchmark import load_corpus

    samples = load_corpus(corpus)
    for sample in samples:
        sample.validate()  # raises if a label is unknown or a note is missing
    assert len(samples) == len(corpus["samples"])


def test_the_results_document_quotes_this_corpus_size(corpus):
    """Guard against the results file drifting away from the corpus it describes."""
    results = (MANIFEST.parent.parent / "docs" / "BENCHMARK_RESULTS.md").read_text(encoding="utf-8")
    assert f"`corpus/corpus.json` ({len(corpus['samples'])} samples" in results
