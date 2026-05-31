# Changelog

All notable changes to pgopps are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · Versioning: [Semantic Versioning](https://semver.org/)

---

## [Unreleased]

---

## [0.1.2] - 2026-05-31

### Added

- **Finding IDs** — every finding now carries a stable, referenceable ID derived from its check's fixed position within its group (e.g. `[SEC-003]`, `[DATA-001]`). A gap in the sequence means the check ran and found nothing. IDs appear in both text and JSON output and can be used in tickets, audit notes, and PR descriptions.
- **Severity summary** in the report footer — shows counts for all severities regardless of the active `-p` filter (`CRITICAL N  HIGH N  MEDIUM N  LOW N  INFO N`).
- **`Scanned` timestamp** (UTC) in the header info block.
- **`-f markdown` output** (alias `-f md`) — ANSI-free, table-based report ready for Notion, Confluence, GitHub, or git-tracked audit history. Combined with `-v`, adds a full Details section with `Fix:` blocks per finding.
- **Client audit block** in the header — second section below the server info showing `Scanned`, `Client` (OS user@hostname), and `Platform` (kernel release + architecture). Separates "what was scanned" from "who ran the scan".
- **Verbose layout** — `Detail` and `Fix` labels with column-aligned output; multi-line descriptions (e.g. pg_hba entry lists) indent continuation lines to maintain visual alignment.

### Changed

- Header info block split into two sections: **server info** (Host, Database, PG User, Provider, Started, Storage, Connections) and **audit context** (Scanned, Client, Platform).
- `User` label renamed to `PG User` to distinguish the PostgreSQL role from the OS-level client user.
- Markdown report header restructured into **Target** and **Auditor** sub-sections.

---

## [0.1.1] - 2026-05-30

### Added

- **Opps Score** — a 0–100 instance health score calculated from all findings regardless of the active priority filter. Severity penalties: CRITICAL −15, HIGH −8, MEDIUM −4, LOW −1, INFO 0.
- Score rendered as a UTF-8 block-character bar with colour thresholds: ≥75 green · ≥50 yellow · <50 red. Grade labels: Excellent / Good / Fair / Poor / Critical.
- **README.md** — installation instructions (Arch/Debian), usage guide, minimum privilege table, check groups with SOC-2 Trust Service Criteria mapping, cloud detection signal table, and Opps Score section.

### Fixed

- Long-running queries check incorrectly surfaced WAL sender and replication slot background processes. Fixed by adding `AND backend_type = 'client backend'` to the query filter.

---

## [0.1.0] - 2026-05-29

### Added

- Initial release.
- Read-only libpq connection; `default_transaction_read_only = on` enforced immediately after connect so checks can never write regardless of the user's privileges.
- **9 check groups** covering 41 checks total:

  | Group | Checks | SOC-2 |
  |---|---|---|
  | Performance | 6 | A1.2 |
  | Security | 5 | CC6 |
  | Encryption | 5 | CC6.7, C1 |
  | Audit & Logging | 6 | CC7.2 |
  | Data Integrity | 4 | PI1 |
  | Maintenance | 4 | — |
  | Configuration | 7 | A1.2 |
  | Replication & HA | 4 | A1.3 |
  | Backup & Recovery | 5 | A1.3 |

- **Cloud provider detection** via `pg_roles` fingerprints: AWS RDS/Aurora, Azure Database for PostgreSQL, Google Cloud SQL, Supabase, Neon, Aiven, and an `UNKNOWN` fallback for unrecognised managed platforms.
  - Cloud-aware check suppression: `hba_trust`, `no_standby`, `logging_collector`, `archive_mode` adjust behaviour or are suppressed per provider.
  - Provider-specific remediation hints via `cloud_param_hint()` (e.g. "apply via Parameter Group" for RDS).
- Output formats: `TEXT` (ANSI colour) and `JSON`.
- Priority filter (`-p 1–5`, default 3/MEDIUM).
- Verbose mode (`-v`) showing `description` and `remediation` inline.
- Connection info summary block: host, database, user, server start time + uptime, storage size, active/max connections.
- `--version` flag.
