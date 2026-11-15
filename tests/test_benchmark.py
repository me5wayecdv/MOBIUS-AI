"""The benchmark harness must fail loudly rather than produce a flattering number.

Precision is the number the project's claims audit hangs on, so these tests are mostly about
what the harness refuses to compute.
"""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from mobius.services.benchmark import (
    Outcome,
    Sample,
    load_corpus,
    measure,
    summarise,
)
from mobius.tools.benchmark import main

FIXTURE_DEX = Path(__file__).parent / "fixtures" / "dex" / "AnalysisTest.dex"


def _sample(tmp_path: Path, name: str, label: str, note: str = "labelled by hand") -> Sample:
    apk = tmp_path / f"{name}.apk"
    apk.write_bytes(b"not really an apk")
    return Sample(name=name, label=label, apk_path=str(apk), note=note)


# -- an empty corpus is not a perfect score -------------------------------------------


def test_no_corpus_means_unmeasured_not_zero_or_one():
    result = measure([], lambda _apk: {"confirmed": 0})

    assert result.measured is False
    assert result.metrics == {}
    assert any("UNMEASURED" in note for note in result.notes)


def test_the_cli_prints_unmeasured_when_given_nothing(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "measured: False" in out
    assert "UNMEASURED" in out


def test_the_cli_reads_a_corpus_file(tmp_path, capsys):
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps({"samples": []}), encoding="utf-8")
    assert main([str(corpus), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["measured"] is False


def test_a_missing_corpus_file_is_an_error_not_an_empty_result(tmp_path, capsys):
    assert main([str(tmp_path / "nope.json")]) == 2
    assert "not found" in capsys.readouterr().err


# -- labels must have a basis ---------------------------------------------------------


def test_a_label_without_a_stated_basis_is_refused(tmp_path):
    sample = _sample(tmp_path, "x", "benign", note="")
    with pytest.raises(ValueError, match="stated basis"):
        measure([sample], lambda _apk: {"confirmed": 0})


def test_an_unknown_label_is_refused(tmp_path):
    sample = _sample(tmp_path, "x", "probably-fine")
    with pytest.raises(ValueError, match="label must be"):
        measure([sample], lambda _apk: {"confirmed": 0})


# -- the rates ------------------------------------------------------------------------


def _outcomes(*pairs: tuple[str, str, int]) -> tuple[Outcome, ...]:
    return tuple(
        Outcome(name=f"s{i}", label=label, confirmed=confirmed)
        for i, (label, _name, confirmed) in enumerate(pairs)
    )


def test_a_hit_and_a_correct_rejection_score_perfectly():
    result = summarise(
        (
            Outcome("vuln", "vulnerable", confirmed=1),
            Outcome("clean", "benign", confirmed=0),
        )
    )

    assert result.measured is True
    assert result.metrics["precision"] == 1.0
    assert result.metrics["recall"] == 1.0
    assert result.metrics["benign_specificity"] == 1.0


def test_a_false_positive_lowers_precision_and_is_counted():
    result = summarise(
        (
            Outcome("vuln", "vulnerable", confirmed=1),
            Outcome("clean", "benign", confirmed=2),
        )
    )

    assert result.metrics["precision"] == 0.5
    assert result.metrics["counts"]["false_positive"] == 1
    assert result.metrics["benign_specificity"] == 0.0


def test_flagging_nothing_leaves_precision_undefined_rather_than_one():
    result = summarise((Outcome("vuln", "vulnerable", confirmed=0),))

    assert result.metrics["precision"] is None
    assert any("precision undefined" in note for note in result.notes)
    assert result.metrics["recall"] == 0.0


def test_a_corpus_without_benign_samples_says_false_positives_were_never_tested():
    result = summarise((Outcome("vuln", "vulnerable", confirmed=1),))

    assert result.metrics["benign_specificity"] is None
    assert any("never tested" in note for note in result.notes)


def test_a_failed_analysis_is_not_a_correct_rejection(tmp_path):
    def exploding(_apk: bytes):
        raise RuntimeError("dex unreadable")

    result = measure([_sample(tmp_path, "broken", "benign")], exploding)

    assert result.measured is False
    assert result.outcomes[0].error.startswith("RuntimeError")
    assert any("not a correct rejection" in note for note in result.notes)


def test_errors_are_excluded_from_rates_but_still_reported(tmp_path):
    def sometimes(_apk: bytes):
        if _apk == b"not really an apk":
            return {"confirmed": 0}
        raise RuntimeError("boom")

    sample = _sample(tmp_path, "bad", "benign")
    bad = Sample("bad2", "benign", str(tmp_path / "missing.apk"), "labelled by hand")
    result = measure([sample, bad], sometimes)

    assert result.measured is True
    assert result.metrics["counts"]["true_negative"] == 1
    assert result.metrics["counts"]["error"] == 1
    assert any("could not be analysed" in note for note in result.notes)


def test_the_note_says_rates_are_per_sample_not_per_finding():
    result = summarise((Outcome("vuln", "vulnerable", confirmed=1),))
    assert any("not the correctness of individual findings" in note for note in result.notes)


# -- corpus parsing -------------------------------------------------------------------


def test_corpus_manifest_round_trips(tmp_path):
    samples = load_corpus(
        {
            "samples": [
                {"name": "a", "label": "vulnerable", "apk_path": "/tmp/a.apk", "note": "DIVA"},
                {"name": "b", "label": "benign", "apk_path": "/tmp/b.apk", "note": "hello world"},
            ]
        }
    )

    assert [s.label for s in samples] == ["vulnerable", "benign"]
    assert samples[0].note == "DIVA"


# -- the real pipeline, on an APK that has no sink -------------------------------------


def _apk_with_fixture_dex() -> bytes:
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.demo"><application>'
        '<activity android:name="AnalysisTest" android:exported="true"/>'
        "</application></manifest>"
    )
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", FIXTURE_DEX.read_bytes())
    return buf.getvalue()


def test_the_harness_drives_the_real_pipeline(tmp_path):
    """Not a stub: upload -> RECON -> NEXUS in an in-memory database."""
    from mobius.tools.benchmark import pipeline_analyser

    apk = tmp_path / "control.apk"
    apk.write_bytes(_apk_with_fixture_dex())

    result = measure(
        [Sample("control", "benign", str(apk), "synthetic control with a real dex")],
        pipeline_analyser(tmp_path),
    )

    assert result.measured is True
    # AnalysisTest has no lifecycle entry point, so nothing may be confirmed.
    assert result.outcomes[0].confirmed == 0
    assert result.metrics["benign_specificity"] == 1.0


# -- intervals --------------------------------------------------------------------------


def test_a_perfect_rate_over_one_sample_reports_an_honest_interval():
    """Precision 100% from a single flagged sample could be as low as ~21%."""
    from mobius.services.benchmark import wilson_interval

    low, high = wilson_interval(1, 1)
    assert 0.19 < low < 0.22
    assert high == 1.0


def test_an_interval_narrows_as_the_sample_grows():
    from mobius.services.benchmark import wilson_interval

    small = wilson_interval(1, 1)
    larger = wilson_interval(20, 20)
    assert larger[0] > small[0]


def test_an_undefined_rate_has_no_interval():
    from mobius.services.benchmark import wilson_interval

    assert wilson_interval(0, 0) is None


def test_every_rate_is_reported_with_its_denominator():
    result = summarise(
        (
            Outcome("vuln", "vulnerable", confirmed=1),
            Outcome("clean", "benign", confirmed=0),
            Outcome("clean2", "benign", confirmed=1),
        )
    )
    assert result.metrics["denominators"] == {
        "precision": 2,
        "recall": 1,
        "specificity": 2,
    }
    assert result.metrics["precision_ci95"] is not None
    assert any("read the 95% interval" in note for note in result.notes)
