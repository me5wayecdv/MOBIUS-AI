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

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.events import SqlEventStore, utcnow
from ..adapters.models import (
    ApplicationRow,
    AuthorizationRow,
    DecisionRow,
    EventRow,
    EvidenceRow,
    FindingRow,
    FrontierEntryRow,
    InvestigationRow,
    ObservationRow,
    PoCRunRow,
    PoCRunEvidenceRow,
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
- **Bounded, selected-family data flow only.** The current slice tracks a small set of
  incoming Intent/URI source candidates to selected direct sinks within one method; external caller control is not established. It does not model
  exception edges (try/catch methods are marked incomplete), field/array memory, cross-method propagation, reflection, dynamic dispatch, or framework
  internals. Results are `may-flow` evidence, never a confirmed vulnerability; no-flow is
  not proof that no tainted path exists.
- **Bounded CFG and guard evidence.** Basic-block order and dominance are recorded for selected
  methods. Guard invocation before/dominating a sink is not proof that the successful branch
  protects it: branch polarity, permission correctness and semantic guard effectiveness are
  not verified. The existing call-graph gate remains conservative.
- **Incomplete graphs are reported as such.** A truncated index can neither confirm nor refute
  absence; those candidates are listed under "Not determined", not as clean.
- **Native code and resources are inventory-only.** Native libraries, assets and resources are listed where the APK archive can be read; they are not semantically analyzed.
- **Obfuscation is not reversed.** Names remain as exposed by DEX/JADX; no deobfuscation is claimed.
- **Multi-DEX coverage is per-entry.** The coverage manifest lists indexed, failed, skipped and truncated DEX entries; a partial entry set cannot support a clean bill of health.
- **Incomplete semantic coverage.** JADX output is reconstructed code, not original source. Native boundaries, reflection, dynamic dispatch, obfuscation and framework internals remain unsupported or partial; DEX entry coverage is reported separately.
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
            self._native_local_runs(row),
            self._method(row),
            self._evidence(row),
            self._events(row),
            self._coverage_manifest(row),
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

    def _native_local_runs(self, row: InvestigationRow) -> str:
        runs=self._session.execute(select(PoCRunRow).where(
            PoCRunRow.investigation_id==row.id).order_by(PoCRunRow.created_at)).scalars()
        lines=[]
        for run in runs:
            if (run.input_json or {}).get("target_kind")!="native_local_fixture":continue
            if not lines:
                lines=["## Controlled native local fixture runs", "",
                    "These runs use a fixed stdlib loopback client, not the investigation APK. "
                    "APK/package/digest are authorization anchors only. No Android/Allsafe, "
                    "certificate pinning, TLS rejection or general target-traffic claim follows.", ""]
            links=self._session.execute(select(PoCRunEvidenceRow).where(
                PoCRunEvidenceRow.investigation_id==row.id,PoCRunEvidenceRow.run_id==run.id)).scalars()
            refs=", ".join(f"`{link.evidence_id}`" for link in links)
            lines.append(f"- Run `{run.id}`, plan `{run.plan_id}`, status `{run.status}`, "
                f"authorization `{run.authorization_id}`, anchor `{run.target_sha256}`, "
                f"input SHA256 `{run.input_sha256}`, output SHA256 `{run.output_sha256}`. "
                f"Evidence: {refs}.")
        return "\n".join(lines)+"\n" if lines else ""

    def _method(self, row: InvestigationRow) -> str:
        model_rows = self._session.execute(
            select(DecisionRow).where(
                DecisionRow.investigation_id == row.id,
                (DecisionRow.model_id.is_not(None)) | (DecisionRow.provider.is_not(None)),
            )
        ).scalars().all()
        model_statement = (
            f"{len(model_rows)} model-backed decision(s) are recorded in persisted provenance; "
            "provider/model and token totals appear in the coverage manifest."
            if model_rows
            else "No language model was called according to persisted decision rows."
        )
        reproducibility_statement = (
            "Deterministic stages are reproducible from stored evidence; model-backed outputs "
            "are recorded with provenance but are not promised to reproduce byte-for-byte."
            if model_rows
            else "The deterministic path is reproducible from the APK bytes and authorisation."
        )
        has_native=any((r.input_json or {}).get("target_kind")=="native_local_fixture" for r in
            self._session.execute(select(PoCRunRow).where(PoCRunRow.investigation_id==row.id)).scalars())
        limitations=_LIMITATIONS
        if has_native:
            limitations=limitations.replace(
                "- **Static only.** Nothing was executed. No finding was confirmed by observing the target at\n"
                "runtime, and no dynamic-analysis capability exists in this build.",
                "- **APK analysis remains static.** Controlled local native fixture runs are listed separately. "
                "Their traffic is not APK runtime evidence and confirms no target finding.")
        return "\n".join(
            [
                "## 6. Method and limitations",
                "",
                "Manifest decoding (RECON), bounded call-graph search over indexed DEX entries "
                "(SPECTRE), the priority-queue dispatcher (NEXUS) and the fixed gate provide the "
                "deterministic analysis and decision controls. " + model_statement,
                "",
                reproducibility_statement + " What it costs is stated below, and it is not small.",
                "",
                limitations,
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

    def _secrets_analysis_summary(self, row: InvestigationRow) -> list[str]:
        """Render the stored secrets-analysis scan summary, when one exists.

        Reads the latest ``secrets_analysis_completed`` event payload - the
        only place the accounting, transport state, DEX ledger state,
        flow-incomplete count and detector coverage limits persist - so a
        scan whose secrets run transported ZERO candidates still says so in
        the report instead of reading like "nothing found"."""
        event = (
            self._session.execute(
                select(EventRow)
                .where(EventRow.investigation_id == row.id,
                       EventRow.type == "secrets_analysis_completed")
                .order_by(EventRow.seq.desc())
                .limit(1)
            )
            .scalar_one_or_none()
        )
        if event is None:
            return []
        payload = event.payload or {}
        acc = payload.get("accounting") or {}
        lines = ["### Secrets analysis (candidate scan)", ""]
        if acc.get("truncated"):
            transport = ("TRUNCATED by the worker: unreported candidates may "
                         "exist; this is not a no-evidence result")
        elif acc.get("conversion_failed"):
            transport = (f"INCOMPLETE: {acc['conversion_failed']} candidate(s) "
                         "with detector evidence could not be converted; this "
                         "is not a complete scan")
        else:
            transport = "complete (payload transport only - see below)"
        lines.append(f"- **Transport:** {transport}")
        lines.append(
            "- **Accounting:** "
            f"screened {acc.get('screened_total', 0)} · "
            f"evidence-less {acc.get('evidence_less', 0)} · "
            f"conversion-failed {acc.get('conversion_failed', 0)} · "
            f"merged {acc.get('merged', 0)} · "
            f"transported {acc.get('transported', 0)} · "
            f"placeholder-dropped {acc.get('placeholder_dropped', 0)}"
        )
        dex_state = ("complete (consistent ledger)"
                     if payload.get("dex_complete") else "INCOMPLETE or ambiguous")
        lines.append(f"- **DEX ledger (worker-asserted):** {dex_state}")
        for entry in payload.get("dex_coverage") or []:
            if isinstance(entry, dict):
                lines.append(
                    "  - %s: %s, %s bytes, %s method(s), %s duplicate(s)%s" % (
                        entry.get("entry"), entry.get("status"),
                        entry.get("size_bytes"), entry.get("methods"),
                        entry.get("duplicates"),
                        ", AMBIGUOUS" if entry.get("ambiguous") else ""))
            else:
                lines.append(f"  - {entry}")
        lines.append(
            "- **Flow-incomplete candidates:** "
            f"{payload.get('flow_incomplete_candidates', 0)} "
            "(absence of evidence not established)"
        )
        # API-owned constants, rendered from source - never strings read
        # back from a payload: the only unrestricted prose in the event is
        # what this service itself wrote, and the report does not re-trust
        # it. Every other rendered value is an int, a bool, or a
        # schema-bounded enumeration (ledger entry names are
        # ``classes*.dex``-shaped, statuses enumerated).
        from .secrets_analysis import DETECTOR_COVERAGE_LIMITS
        lines.append("- **Detector coverage limits:**")
        lines += [f"  - {limit}" for limit in DETECTOR_COVERAGE_LIMITS]
        if not acc.get("transported"):
            lines += [
                "",
                "No secrets candidates were transported. This is **not** a "
                "no-secrets result: it says nothing about secrets outside the "
                "detector's coverage.",
            ]
        # The transport_complete disclaimer is part of the rendered
        # API-owned coverage limits above; no separate closing line.
        lines.append("")
        return lines

    def _coverage_manifest(self, row: InvestigationRow) -> str:
        """Embed the same structured manifest exposed by the read-only API route."""
        from .coverage_manifest import CoverageManifestBuilder

        manifest = CoverageManifestBuilder(self._session, self._store).build(row.id)
        encoded = json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2)
        # APK-controlled ZIP names are data. Prevent a filename from closing the Markdown
        # fence while preserving the exact JSON string after decoding the escaped backticks.
        encoded = encoded.replace("```", r"\u0060\u0060\u0060")
        limitations = [
            f"| `{item['capability']}` | `{item['status']}` | {item['detail']} |"
            for item in manifest["limitations"]
        ]
        return "\n".join([
            "## 9. Code coverage and limitations manifest",
            "",
            f"**Overall coverage status:** `{manifest['overall_status'].upper()}`"
            + (" · **truncation detected**" if manifest["truncated"] else ""),
            "",
            "| Area | Status / coverage |",
            "|---|---|",
            f"| APK archive inventory | `{manifest['apk_inventory'].get('status', 'unknown')}` |",
            f"| RECON manifest | `{manifest['recon']['status']}` · {manifest['recon']['manifest_evidence_count']} evidence record(s) |",
            f"| DEX index | `{manifest['dex_analysis']['status']}` · {manifest['dex_analysis'].get('indexed_entries', 0)}/{manifest['dex_analysis'].get('dex_entry_count', 0)} indexed entries |",
            f"| JADX | `{manifest['jadx']['status']}` · {manifest['jadx'].get('source_file_count', 0)} source file(s) reported |",
            f"| SPECTRE reachability | {manifest['reachability']['observation_count']} observation(s), {manifest['reachability']['truncated_observations']} truncated |",
            f"| Model-backed decisions | {manifest['model_usage']['model_backed_decision_count']} of {manifest['model_usage']['decision_count']} decisions |",
            f"| Native libraries | {manifest['apk_inventory'].get('native_libraries', {}).get('count', 0)} inventoried; not analyzed |",
            f"| Assets / resources | {manifest['apk_inventory'].get('assets', {}).get('count', 0)} asset(s), {manifest['apk_inventory'].get('resources', {}).get('count', 0)} resource(s); inventory only |",
            "",
            *self._secrets_analysis_summary(row),
            "### Unsupported or inventory-only capabilities",
            "",
            "| Capability | Status | Limitation |",
            "|---|---|---|",
            *limitations,
            "",
            "### Machine-readable manifest",
            "",
            "```json",
            encoded,
            "```",
            "",
            "A missing or truncated entry is not evidence that the corresponding code or behavior is absent.",
        ]) + "\\n"

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
