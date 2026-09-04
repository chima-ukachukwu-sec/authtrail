# AuthTrail Roadmap

AuthTrail v1 is intentionally focused on local OpenSSH authentication-log analysis. Future work should expand investigation depth before expanding into unrelated telemetry sources.

## v1.1: Investigation workflow

- Detection-rule explanations with threshold and evidence breakdowns
- Exportable Markdown and JSON investigation reports
- Session/activity reconstruction for related authentication events

## v1.2: Linux security context

- `sudo` activity analysis
- fail2ban correlation
- broader `journalctl` input support while preserving local-only processing

## v1.3: Comparative analysis

- Analyst-focused timeline view
- Log-to-log comparison for new sources, targeted accounts, activity spikes, and new findings

## v2: Local investigation workspace

- Configurable deterministic rule profiles with reportable configuration metadata
- Multi-log investigations
- Local case workspace
- Windows authentication-event support through a separate parser and normalized event model

## Principles

- Keep log data local by default
- Prefer deterministic, evidence-backed findings
- Preserve original source provenance
- Add a feature only when it improves an investigation workflow
- Keep parser/domain boundaries explicit as new log sources are introduced
