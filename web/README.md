# MOBIUS — open-source AI SAST, AI DAST and bug chains for Android

A static, dependency-free product site for a fictional open-source Android security
platform: dark technical-sheet layout, a four-view demo console, an agent trace, an
exploit-chain anatomy, and an open-source section.

**This is a design study, not a product.** Every finding, run id and device on the page is
demo data. It is not affiliated with djini.ai, and no text from any site was copied.

## Run it

```bash
python3 -m http.server 8000 --bind 0.0.0.0
```

Open `http://localhost:8000`. Nothing to install, nothing to build.

## Sections

| # | Section | What it argues |
|---|---|---|
| — | Hero + console | SAST finds, DAST proves, agents chain. Four tabs: AI SAST, AI DAST, Chain, Agent |
| 01 | Platform | Six capabilities: SAST, DAST, chain builder, agents, device lab, CI/CD |
| 02 | How agents find bugs | Observe → hypothesise → probe → verify → connect, plus a run trace with a **rejected** hypothesis kept in the log |
| 03 | Anatomy of a chain | Five hops, four CWEs, one impact — and why a single medium finding is not the story |
| 04 | Open source | Apache-2.0, self-host, BYO model, write your own analyser, own the output |
| 05 | Funding | Community / Cloud / Enterprise — support and hosting, never a feature flag |
| 06 | FAQ | Open-core, model keys, what DAST runs, chains vs vuln lists, being wrong |

## Files

```
index.html          all sections
assets/styles.css   design system + v2 components (agent log, chain rail, repo panel)
assets/app.js       tabs (arrow-key), billing toggle, reveals, agent playhead, binary scramble
assets/mark.svg     favicon / logo mark
```

## Design notes

- **One accent.** Acid lime means "state or action". Red/amber/cyan are reserved for
  severity, so colour carries information instead of decoration.
- **Hairlines, not shadows.** Structure comes from 1px rules, a masked 72px grid and
  blueprint numbering (`SHEET 01 · REV. 26.11`).
- **The agent screen is the argument.** It shows a hypothesis, four evidenced clauses, a
  rejected branch and an explicit "0 unsupported claims" counter — the honesty is the
  feature being sold.
- **The chain is drawn, not listed.** A dotted rail, one node per hop, severity encoded in
  the node border and the meta colour.
- **Motion with an off switch.** Everything respects `prefers-reduced-motion`; the console
  autoplay pauses on hover/focus, and the agent playhead only highlights rows — it never
  hides them.
- **Accessibility.** Real `<button>`s with `aria-selected`, arrow-key tab navigation,
  visible focus rings, semantic landmarks, no colour-only meaning.

## Previous contents

The repository previously held a Python/Android analysis engine. Its history is at
commit `d373bba`; the site replaced the working tree on request.
