"""Run the benchmark corpus through the real pipeline and print the metrics.

    python -m mobius.tools.benchmark corpus.json [--json]

The corpus is a JSON file: ``{"samples": [{"name", "label", "apk_path", "note"}]}``.
With no corpus file there is nothing to print but the truth: precision is unmeasured.

This wires the *real* pipeline - upload, RECON, NEXUS - into an in-memory database, so the
number it produces is the number the product would produce. It is only as good as the labels
it is given, which is why a sample without a stated basis is refused rather than defaulted.
"""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from ..adapters.models import Base
from ..services.artifacts import ArtifactStore
from ..services.benchmark import Sample, load_corpus, measure
from ..services.intake import IntakeService
from ..services.nexus import NexusService
from ..services.recon import ReconService


def pipeline_analyser(workdir: Path):
    """Build an analyser that runs the real RECON -> NEXUS pipeline on one APK."""
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    store = ArtifactStore(workdir / "artifacts")
    counter = {"n": 0}

    def analyse(apk: bytes) -> dict[str, int]:
        counter["n"] += 1
        session = factory()
        try:
            intake = IntakeService(session, store)
            app, _ = intake.create_application(
                apk, f"sample-{counter['n']}.apk", uploaded_by="benchmark"
            )
            auth = intake.create_authorization(
                apk_sha256=app.sha256,
                target_package=app.package_name or "unknown",
                scope_text="Benchmark corpus supplied by the project; static analysis only.",
                statement="Labelled corpus, analysed for measurement.",
                max_intensity=0,
                granted_by="benchmark",
                expires_at=(datetime.now(timezone.utc) + timedelta(days=1))
                .isoformat()
                .replace("+00:00", "Z"),
            )
            investigation = intake.create_investigation(
                application_id=app.id,
                authorization_id=auth.id,
                objective="Benchmark: does this application reach a privileged sink from an "
                "exported entry point with no caller check?",
                intensity=0,
                created_by="benchmark",
            )
            intake.start(investigation.id)
            ReconService(session, store).run(investigation.id)
            result = NexusService(session, store).run(investigation.id)
            session.commit()
            findings = result["findings"]
            return {
                "confirmed": int(findings["confirmed"]),
                "rejected": int(findings["rejected"]),
                "manual_review": int(findings["manual_review"]),
            }
        finally:
            session.close()

    return analyse


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]

    if not argv:
        payload: dict[str, Any] = {"samples": []}
    else:
        path = Path(argv[0])
        if not path.is_file():
            print(f"corpus file not found: {path}", file=sys.stderr)
            return 2
        payload = json.loads(path.read_text(encoding="utf-8"))

    samples = load_corpus(payload)
    if not samples:
        result = measure(samples, lambda _apk: {"confirmed": 0})
        print(json.dumps(result.as_dict(), indent=2) if as_json else _render(result.as_dict()))
        return 0

    with tempfile.TemporaryDirectory(prefix="mobius-bench-") as tmp:
        analyser = pipeline_analyser(Path(tmp))
        try:
            result = measure(samples, analyser)
        finally:
            pass

    body = result.as_dict()
    print(json.dumps(body, indent=2) if as_json else _render(body))
    # Non-zero when a benign control was flagged: a regression a CI job should fail on.
    counts = body.get("metrics", {}).get("counts", {})
    return 1 if counts.get("false_positive") else 0


def _render(body: dict[str, Any]) -> str:
    lines = [f"MOBIUS benchmark — measured: {body['measured']}", ""]
    if not body["measured"]:
        lines += [f"  {note}" for note in body["notes"]]
        return "\n".join(lines)

    metrics = body["metrics"]
    counts = metrics["counts"]
    lines += [
        f"  samples          : {body['samples']}",
        f"  flagged          : {metrics['flagged']}",
        f"  precision        : {_pct(metrics['precision'])}",
        f"  recall           : {_pct(metrics['recall'])}",
        f"  benign specificity: {_pct(metrics['benign_specificity'])}",
        "",
        "  outcomes:",
    ]
    for outcome in body["outcomes"]:
        state = "ERROR" if outcome["error"] else ("flagged" if outcome["flagged"] else "clean")
        lines.append(
            f"    {outcome['name']:<28} {outcome['label']:<11} {state:<8} "
            f"confirmed={outcome['confirmed']} manual_review={outcome['manual_review']}"
        )
    lines += [""] + [f"  note: {note}" for note in body["notes"]]
    lines.append(
        f"  counts: tp={counts['true_positive']} fp={counts['false_positive']} "
        f"fn={counts['false_negative']} tn={counts['true_negative']} err={counts['error']}"
    )
    return "\n".join(lines)


def _pct(value: float | None) -> str:
    return "undefined" if value is None else f"{value:.2%}"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main", "pipeline_analyser", "Sample"]
