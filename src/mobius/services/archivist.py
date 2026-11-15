"""ARCHIVIST: turn a closed investigation into a document someone else can read.

A report is the only artefact most readers will ever see, so it is also the easiest place in
the project to lie. Three rules keep it honest:

* **Every sentence comes from a row.** No section is composed from what the analysis "probably"
  found. If there are no confirmed findings, the report says zero rather than describing a
  risk in prose.
* **The "not determined" section is generated, not written.** It lists the findings in manual
  review, the observations whose reachability was never established, and the frontier entries
  that were never run - each with the reason. When there is genuinely nothing undetermined,
  the section says so *and* still states what static analysis cannot see.
* **Rejections are reported as findings of their own.** "Not reachable" and "guarded by a
  caller check" are conclusions the pipeline reached; a report that printed only the positives
  would misrepresent a scan that spent its budget refuting things.

The output is Markdown and is stored as evidence, so the report a reviewer reads is the report
that was produced - content-addressed, not regenerated from a later database state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.events import SqlEventStore, utcnow
from ..adapters.models import (
    ApplicationRow,
    AuthorizationRow,
    EventRow,
    EvidenceRow,
    FindingRow,
    FrontierEntryRow,
    InvestigationRow,
    ObservationRow,
    VerdictRow,
)
from ..core.enums import EvidenceKind, FindingStatus
from .artifacts import ArtifactStore
from .errors import NotFound
from .evidence import EvidenceService

AGENT = "ARCHIVIST"

#: What this build's analysis structurally cannot establish. Printed in every report, because
#: a reader who only sees the positives will over-read them.
_LIMITATIONS = """\
- **Static only.** Nothing was executed. No finding was confirmed by observing the target at
  runtime, and no dynamic-analysis capability exists in this build.
- **No data-flow analysis.** Reachability means a call path exists in the bytecode from an
  entry point to a security-relevant operation. It does **not** establish that
  attacker-controlled data reaches that operation.
- **No control-flow analysis.** A guard anywhere in the same method suppresses the
  "no caller check" clause, whatever order it executes in. This biases toward *not* confirming.
- **Incomplete graphs are reported as such.** A truncated index can neither confirm nor refute
  absence; those candidates are listed under "Not determined", not as clean.
- **No decompilation, no reflection, no multi-dex.** Source-level intent, reflective dispatch
  and secondary dex files are outside what this build can see.
- **Absence of a finding is not evidence of absence.** An empty findings list means this
  pipeline found nothing by these methods, not that the application is safe.
"""


@dataclass(frozen=True, slots=True)
class Report:
    investigation_id: str
    markdown: str
    generated_at: str

    @property
    def bytes(self) -> bytes:
        return self.markdown.encode("utf-8")


class ArchivistService:
    def __init__(self, session: Session, store: ArtifactStore) -> None:
        self._session = session
        self._store = store

    def build(self, investigation_id: str, *, generated_at: str | None = None) -> Report:
        """Compose the report from stored rows. Pure read: writes nothing."""
        row = self._row(investigation_id)
        generated = generated_at or utcnow()
        sections = [
            self._header(row, generated),
            self._scope(row),
            self._outcome(row),
            self._confirmed(row),
            self._rejected(row),
            self._undetermined(row),
            self._method(row),
            self._evidence(row),
            self._events(row),
        ]
        return Report(investigation_id, "\n".join(sections).rstrip() + "\n", generated)

    def write(self, investigation_id: str, *, generated_at: str | None = None) -> dict[str, Any]:
        """Build the report, store it as evidence, and emit the event."""
        report = self.build(investigation_id, generated_at=generated_at)
        sha = ArtifactStore.digest(report.bytes)
        existing = self._session.execute(
            select(EvidenceRow).where(
                EvidenceRow.investigation_id == investigation_id,
                EvidenceRow.kind == EvidenceKind.REPORT.value,
                EvidenceRow.sha256 == sha,
            )
        ).scalar_one_or_none()
        if existing is not None:
            # Same document already written. Re-emitting `report_written` would claim a
            # second write happened, which is the kind of quiet duplication the event log
            # exists to prevent.
            return {
                "investigation_id": investigation_id,
                "evidence_id": existing.id,
                "sha256": existing.sha256,
                "byte_size": existing.byte_size,
                "generated_at": report.generated_at,
                "markdown": report.markdown,
                "duplicate": True,
            }

        evidence = EvidenceService(self._session, self._store).record(
            investigation_id=investigation_id,
            kind=EvidenceKind.REPORT,
            content=report.bytes,
            summary=f"Investigation report ({len(report.bytes)} bytes of Markdown)",
            produced_by=AGENT,
        )
        self._session.flush()
        SqlEventStore(self._session).emit(
            investigation_id,
            "report_written",
            {
                "evidence_id": evidence.id,
                "sha256": evidence.sha256,
                "byte_size": evidence.byte_size,
            },
            actor=AGENT,
        )
        return {
            "investigation_id": investigation_id,
            "evidence_id": evidence.id,
            "sha256": evidence.sha256,
            "byte_size": evidence.byte_size,
            "generated_at": report.generated_at,
            "markdown": report.markdown,
            "duplicate": False,
        }

    def latest(self, investigation_id: str) -> str:
        """The most recent stored report, as text.

        Reads the stored artefact rather than rebuilding, so what a reader downloads is what
        the scan produced even if later observations were added.
        """
        self._row(investigation_id)
        rows = (
            self._session.execute(
                select(EvidenceRow)
                .where(
                    EvidenceRow.investigation_id == investigation_id,
                    EvidenceRow.kind == EvidenceKind.REPORT.value,
                )
                .order_by(EvidenceRow.created_at.desc())
            )
            .scalars()
            .all()
        )
        if not rows:
            raise NotFound(f"no report has been written for investigation {investigation_id}")
        return self._store.get(rows[0].object_key).decode("utf-8")

    # -- sections ------------------------------------------------------------------

    def _row(self, investigation_id: str) -> InvestigationRow:
        row = self._session.get(InvestigationRow, investigation_id)
        if row is None:
            raise NotFound(f"investigation {investigation_id} not found")
        return row

    def _header(self, row: InvestigationRow, generated: str) -> str:
        return (
            f"# MOBIUS investigation report — `{row.id}`\n\n"
            f"Generated {generated} by ARCHIVIST. "
            "Every statement below is derived from stored rows; "
            "the evidence index in §7 gives the hash of each source.\n"
        )

    def _scope(self, row: InvestigationRow) -> str:
        app = self._session.get(ApplicationRow, row.application_id)
        auth = (
            self._session.get(AuthorizationRow, row.authorization_id)
            if row.authorization_id
            else None
        )
        lines = ["## 1. Scope and authorisation", ""]
        if app is not None:
            lines += [
                "| Field | Value |",
                "|---|---|",
                f"| Application | `{app.id}` |",
                f"| SHA-256 | `{app.sha256}` |",
                f"| Package | `{app.package_name or 'unknown'}` |",
                f"| Version | `{app.version_name or 'unknown'}` ({app.version_code or '—'}) |",
                f"| Size | {app.file_size} bytes |",
            ]
        lines += [
            "",
            f"**Objective.** {row.objective}",
            "",
            f"**Intensity granted to the scan:** {row.intensity} "
            f"({'passive — static analysis only' if row.intensity == 0 else 'above passive'}).",
        ]
        if auth is not None:
            lines += [
                "",
                "**Authorisation.**",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Authorisation | `{auth.id}` |",
                f"| Granted by | `{auth.granted_by}` |",
                f"| Target package | `{auth.target_package}` |",
                f"| Max intensity | {auth.max_intensity} |",
                f"| Expires | {auth.expires_at} |",
                f"| Revoked | {auth.revoked_at or 'no'} |",
                "",
                f"> Scope of the grant, verbatim: “{auth.scope_text}”",
            ]
        return "\n".join(lines) + "\n"

    def _outcome(self, row: InvestigationRow) -> str:
        findings = self._findings(row.id)
        counts = self._count(findings)
        return "\n".join(
            [
                "## 2. Outcome",
                "",
                "| | |",
                "|---|---|",
                f"| Final state | `{row.state}` |",
                f"| Stop reason | `{row.stop_reason or 'not recorded'}` |",
                f"| Findings | {len(findings)} |",
                f"| Confirmed | {counts['confirmed']} |",
                f"| Rejected | {counts['rejected']} |",
                f"| Requiring manual review | {counts['manual_review']} |",
                "",
                self._outcome_sentence(counts),
            ]
        ) + "\n"

    @staticmethod
    def _outcome_sentence(counts: dict[str, int]) -> str:
        if counts["confirmed"] == 0 and counts["rejected"] == 0 and counts["manual_review"] == 0:
            return (
                "No hypothesis was evaluated: the scan produced no candidate that reached a "
                "gate. This is a statement about the pipeline's coverage, not about the "
                "application's security."
            )
        if counts["confirmed"] == 0:
            refuted = counts["rejected"]
            return (
                f"No finding was confirmed by this scan. {refuted} "
                f"{'hypothesis was' if refuted == 1 else 'hypotheses were'} refuted on stored "
                f"evidence and {counts['manual_review']} could not be decided."
            )
        return (
            f"{counts['confirmed']} "
            f"{'finding was' if counts['confirmed'] == 1 else 'findings were'} "
            f"confirmed by the gate, "
            f"{counts['rejected']} refuted, {counts['manual_review']} left undecided. "
            "A confirmed finding means the gate's clauses were each established; it does not "
            "mean the weakness was exploited."
        )

    def _confirmed(self, row: InvestigationRow) -> str:
        confirmed = [f for f in self._findings(row.id) if f.status == FindingStatus.CONFIRMED.value]
        lines = ["## 3. Confirmed findings", ""]
        if not confirmed:
            lines.append("None.")
            return "\n".join(lines) + "\n"
        for finding in confirmed:
            verdict = self._verdict(finding.id)
            lines += [
                f"### {finding.title}",
                "",
                f"- **Component:** `{finding.component_ref or 'not recorded'}`",
                f"- **Category:** `{finding.category}`",
                f"- **Severity:** {finding.severity} · **Confidence:** {finding.confidence}",
                f"- **Weakness:** {', '.join(finding.maswe) or '—'} "
                f"({', '.join(finding.masvs) or '—'})",
                f"- **Discovered by** {finding.discovered_by} · "
                f"**validated by** {finding.validated_by}",
                "",
                f"{finding.description}",
                "",
                "**Gate evidence** — every clause had to be established:",
                "",
                "| Clause | Established |",
                "|---|---|",
            ]
            for key, value in sorted((finding.gate_evidence or {}).items()):
                lines.append(f"| `{key}` | {'yes' if value is True else 'no'} |")
            if verdict is not None:
                lines += ["", f"**Validator's rationale.** {verdict.rationale}"]
            lines += ["", f"**Evidence.** {', '.join(finding.evidence_refs) or '—'}", ""]
        return "\n".join(lines) + "\n"

    def _rejected(self, row: InvestigationRow) -> str:
        rejected = [f for f in self._findings(row.id) if f.status == FindingStatus.REJECTED.value]
        lines = ["## 4. Rejected hypotheses", ""]
        if not rejected:
            lines.append("None.")
            return "\n".join(lines) + "\n"
        lines += ["A rejection is a conclusion reached on evidence, not a silence.", ""]
        lines += ["| Finding | Component | Reason |", "|---|---|---|"]
        for finding in rejected:
            verdict = self._verdict(finding.id)
            reason = verdict.rejection_reason if verdict and verdict.rejection_reason else "—"
            lines.append(
                f"| {finding.title} | `{finding.component_ref or '—'}` | `{reason}` |"
            )
        lines += ["", "Why each was refused:", ""]
        for finding in rejected:
            verdict = self._verdict(finding.id)
            rationale = verdict.rationale if verdict is not None else finding.description
            lines.append(f"- **{finding.title}** — {rationale}")
        return "\n".join(lines) + "\n"

    def _undetermined(self, row: InvestigationRow) -> str:
        findings = self._findings(row.id)
        review = [
            f for f in findings if f.status == FindingStatus.MANUAL_REVIEW_REQUIRED.value
        ]
        unknown_obs = [
            o
            for o in self._observations(row.id)
            if (o.attributes or {}).get("reachability") in ("unknown", "truncated", "no-entry-point")
            or (o.attributes or {}).get("index_truncated")
        ]
        open_entries = (
            self._session.execute(
                select(FrontierEntryRow).where(
                    FrontierEntryRow.investigation_id == row.id,
                    FrontierEntryRow.state.in_(("queued", "leased", "failed", "dropped")),
                )
            )
            .scalars()
            .all()
        )

        lines = ["## 5. Not determined", ""]
        if not (review or unknown_obs or open_entries):
            lines += [
                "Nothing in this investigation was left undetermined: every candidate that "
                "reached a gate was decided.",
                "",
                "That is a statement about the candidates, not about the application. "
                "See §6 for what this build cannot see at all.",
            ]
            return "\n".join(lines) + "\n"

        if review:
            lines += ["**Findings requiring a human decision**", ""]
            for finding in review:
                lines.append(f"- `{finding.id}` **{finding.title}** — {finding.description}")
            lines.append("")
        if unknown_obs:
            lines += ["**Observations whose reachability was never established**", ""]
            for observation in unknown_obs:
                attributes = observation.attributes or {}
                lines.append(
                    f"- `{observation.subject_ref}` — reachability "
                    f"`{attributes.get('reachability', 'unknown')}`"
                    f"{' (index truncated)' if attributes.get('index_truncated') else ''}: "
                    f"{observation.statement}"
                )
            lines.append("")
        if open_entries:
            lines += ["**Work that was queued and not completed**", ""]
            for entry in open_entries:
                lines.append(
                    f"- `{entry.action}` on `{(entry.action_args or {}).get('component', '—')}` "
                    f"for {entry.required_agent} — state `{entry.state}`, "
                    f"{entry.attempts} attempt(s)"
                )
            lines.append("")
        return "\n".join(lines) + "\n"

    def _method(self, row: InvestigationRow) -> str:
        return "\n".join(
            [
                "## 6. Method and limitations",
                "",
                "Decisions in this scan were made by deterministic code: manifest decoding "
                "(RECON), a bounded call-graph search over the dex (SPECTRE), a priority-queue "
                "dispatcher (NEXUS) and a fixed gate. **No language model was called**, so this "
                "report is reproducible from the APK bytes and the authorisation alone.",
                "",
                "What that buys: a reviewer can re-run the scan and get the same verdicts. "
                "What it costs is stated below, and it is not small.",
                "",
                _LIMITATIONS,
                f"Investigation intensity was {row.intensity}; with a passive grant nothing in "
                "this build could execute the target even if an execution host existed.",
            ]
        ) + "\n"

    def _evidence(self, row: InvestigationRow) -> str:
        # Reports are excluded: a document that lists itself as evidence for itself is not
        # an evidence index, and including it made two writes of the same investigation
        # produce different bytes - so the content hash could never deduplicate.
        rows = (
            self._session.execute(
                select(EvidenceRow)
                .where(
                    EvidenceRow.investigation_id == row.id,
                    EvidenceRow.kind != EvidenceKind.REPORT.value,
                )
                .order_by(EvidenceRow.created_at.asc())
            )
            .scalars()
            .all()
        )
        lines = ["## 7. Evidence index", ""]
        if not rows:
            lines.append("No evidence was recorded.")
            return "\n".join(lines) + "\n"
        lines += ["| Evidence | Kind | Bytes | SHA-256 | Summary |", "|---|---|---|---|---|"]
        for evidence in rows:
            summary = evidence.summary.replace("|", "\\|")
            lines.append(
                f"| `{evidence.id}` | {evidence.kind} | {evidence.byte_size} | "
                f"`{evidence.sha256[:16]}…` | {summary} |"
            )
        return "\n".join(lines) + "\n"

    def _events(self, row: InvestigationRow) -> str:
        rows = (
            self._session.execute(
                select(EventRow)
                .where(EventRow.investigation_id == row.id)
                .order_by(EventRow.seq.asc())
            )
            .scalars()
            .all()
        )
        # `report_written` is excluded for the same reason the report is not in its own
        # evidence index: counting it would make the summary depend on whether the report
        # had been written before, so a rewrite would never match the original.
        rows = [e for e in rows if not e.type.startswith("report_")]
        counts: dict[str, int] = {}
        for event in rows:
            counts[event.type] = counts.get(event.type, 0) + 1
        lines = ["## 8. Event log", ""]
        if not rows:
            lines.append("No events.")
            return "\n".join(lines) + "\n"
        lines += [f"{len(rows)} events, sequences {rows[0].seq}–{rows[-1].seq}.", ""]
        lines += ["| Event type | Count |", "|---|---|"]
        for name in sorted(counts):
            lines.append(f"| `{name}` | {counts[name]} |")
        lines += [
            "",
            "The full event log is replayable from `GET /api/v1/scans/{id}/stream?after=0`.",
        ]
        return "\n".join(lines) + "\n"

    # -- helpers --------------------------------------------------------------------

    def _findings(self, investigation_id: str) -> list[FindingRow]:
        return list(
            self._session.execute(
                select(FindingRow)
                .where(FindingRow.investigation_id == investigation_id)
                .order_by(FindingRow.created_at.asc(), FindingRow.id.asc())
            )
            .scalars()
            .all()
        )

    def _observations(self, investigation_id: str) -> list[ObservationRow]:
        return list(
            self._session.execute(
                select(ObservationRow)
                .where(ObservationRow.investigation_id == investigation_id)
                .order_by(ObservationRow.created_at.asc(), ObservationRow.id.asc())
            )
            .scalars()
            .all()
        )

    def _verdict(self, finding_id: str) -> VerdictRow | None:
        return self._session.execute(
            select(VerdictRow).where(VerdictRow.finding_id == finding_id)
        ).scalar_one_or_none()

    @staticmethod
    def _count(findings: list[FindingRow]) -> dict[str, int]:
        def count(status: str) -> int:
            return sum(1 for f in findings if f.status == status)

        return {
            "confirmed": count(FindingStatus.CONFIRMED.value),
            "rejected": count(FindingStatus.REJECTED.value),
            "manual_review": count(FindingStatus.MANUAL_REVIEW_REQUIRED.value),
        }


__all__ = ["ArchivistService", "Report"]
