# pgopps

**PostgreSQL Opportunities** — a read-only DBA health advisor and pre-audit checklist tool.

pgopps connects to a PostgreSQL instance with a read-only user, runs a curated set of checks across 9 concern areas, and presents prioritised, grouped findings with actionable remediation steps. It is designed for DBA daily operations, pre-production reviews, and audit preparation (including SOC-2 alignment).

---

## Installation

### Download pre-built binary (Linux x86-64)

```bash
curl -Lo pgopps https://github.com/deepcraftdata/pgopps/releases/latest/download/pgopps-linux-amd64
chmod +x pgopps
sudo mv pgopps /usr/local/bin/
```

### Build from source

#### Prerequisites

| Package | Arch Linux | Debian/Ubuntu |
|---|---|---|
| libpq (client library) | `postgresql-libs` | `libpq-dev` |
| cmake ≥ 3.16 | `cmake` | `cmake` |
| gcc | `gcc` | `gcc` |

#### Build

```bash
git clone https://github.com/deepcraftdata/pgopps.git
cd pgopps
cmake -S . -B build
cmake --build build
```

Binary: `build/pgopps`

**Development symlink** (rebuild once, always current):

```bash
ln -sf $(pwd)/build/pgopps ~/.local/bin/pgopps
```

**System install:**

```bash
sudo cmake --install build   # installs to /usr/local/bin
```

---

## Usage

```
pgopps [OPTIONS] CONNSTR
```

`CONNSTR` accepts both URL and key=value formats — identical to `psql`:

```bash
pgopps "postgresql://readonly:pass@db.example.com:5432/mydb"
pgopps "host=db.example.com dbname=mydb user=readonly"
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-f`, `--format TEXT\|JSON\|MARKDOWN` | `TEXT` | Output format |
| `-p`, `--priority 1-5` | `3` (MEDIUM) | Show findings at this priority and above |
| `-v`, `--verbose` | off | Show description and remediation for each finding |
| `--version` | | Print version and exit |
| `-h`, `--help` | | Show usage |

### Priority filter examples

```bash
# Default: CRITICAL, HIGH, MEDIUM
pgopps "postgresql://..."

# Also show LOW findings
pgopps -p 4 "postgresql://..."

# Show everything including INFO
pgopps -p 5 "postgresql://..."

# JSON output, all findings
pgopps -f json -p 5 "postgresql://..." | jq .

# Markdown report saved to file (for Notion, Confluence, GitHub, git history)
pgopps -f markdown -v "postgresql://..." > reports/$(date +%F).md
```

---

## Output

```
  pgopps v0.1.1 — connected to PostgreSQL 16.3
  ────────────────────────────────────────────
  Host           db.example.com:5432
  Database       mydb
  User           readonly
  Scanned        2026-05-31 14:32:01 UTC
  Started        2024-03-01 08:00:00+00  (up 14d 06h 22m)
  Storage        5 databases, 42 GB total
  Connections    28 / 100 connections active
  ────────────────────────────────────────────

  Findings

[ Security ]
  [SEC-003]    CRITICAL  pg_hba.conf allows network connections without authentication (trust)
  [SEC-002]    MEDIUM    PUBLIC can CREATE objects in the public schema

[ Encryption ]
  [ENC-001]    HIGH      SSL is disabled — all connections are unencrypted

[ Configuration ]
  [CONF-001]   MEDIUM    shared_buffers at default (128MB)

─────────────────────────────────────────────
  CRITICAL 1   HIGH 1   MEDIUM 2   LOW 3   INFO 2
4 finding(s) shown (priority ≤ MEDIUM)

  ─────────────────────────────────────────────
  Opps Score  (9 findings across all checks)

  ████████████░░░░░░░░░░░░░░░░░░  47 / 100

  Fair       Several issues need attention.
  ─────────────────────────────────────────────
```

Finding IDs (e.g. `SEC-003`, `CONF-001`) are stable across runs — they are derived from the check's fixed position within its group. A gap in the sequence means that check ran and found nothing.

Use `-v` to see descriptions and remediation steps inline.

---

## Minimum required privileges

pgopps is designed to run as a **read-only** user. The connection is immediately placed in `default_transaction_read_only = on`.

The following system views are accessed; most are available to any login role:

| View / Function | Required privilege |
|---|---|
| `pg_stat_activity`, `pg_stat_database`, `pg_stat_user_tables`, `pg_stat_user_indexes`, `pg_stat_ssl`, `pg_stat_replication`, `pg_stat_archiver` | Any login role |
| `pg_settings`, `pg_roles`, `pg_class`, `pg_index`, `pg_constraint` | Any login role |
| `pg_hba_file_rules` | Superuser (PG < 15), any login role (PG ≥ 15) |
| `pg_authid` (MD5 password check) | Superuser only — skipped silently if not accessible |

Recommended setup:

```sql
CREATE ROLE pgopps_ro LOGIN PASSWORD '...';
GRANT pg_monitor TO pgopps_ro;       -- covers most stat views
GRANT pg_read_all_data TO pgopps_ro; -- optional, for schema-level checks
```

---

## Check groups

| Group | What it covers | SOC-2 relevance |
|---|---|---|
| **Performance** | Cache hit ratio, seq scans, unused indexes, long-running queries, idle-in-transaction, connection utilization | A1.2 Capacity |
| **Security** | Superuser count, PUBLIC schema privileges, pg_hba trust/plaintext, password expiry, CREATEDB/CREATEROLE/BYPASSRLS | CC6 Access Control |
| **Encryption** | SSL on/off, TLS protocol version, password_encryption, MD5 hashed passwords, non-SSL active connections | CC6.7, C1 Confidentiality |
| **Audit & Logging** | log_connections, slow query log, log_statement (DDL), log_line_prefix fields, logging_collector, pgaudit | CC7.2 Monitoring |
| **Data Integrity** | data_checksums, tables without PK, FK without index, Row-Level Security coverage | PI1 Processing Integrity |
| **Maintenance** | Dead tuple ratio, XID wraparound risk, never-analyzed tables, per-table autovacuum disabled | — |
| **Configuration** | shared_buffers, wal_level, max_connections, work_mem, checkpoint_completion_target, autovacuum, random_page_cost | A1.2 Capacity |
| **Replication & HA** | Stale replication slots, standby lag, no standbys (SPOF), synchronous_commit | A1.3 Recovery |
| **Backup & Recovery** | archive_mode, archive failures, archive stall, wal_keep_size, PITR advisory | A1.3 Recovery |

---

## Cloud provider detection

pgopps automatically detects whether it is connected to a managed cloud instance by inspecting `pg_roles` and `pg_settings` fingerprints:

| Provider | Detection signal |
|---|---|
| AWS RDS / Aurora | `rdsadmin` role |
| Azure Database for PostgreSQL | `azure_superuser` role |
| Google Cloud SQL | `cloudsqlsuperuser` role |
| Supabase | `supabase_admin` role |
| Neon | `neon_superuser` role |
| Aiven | `avnadmin` role |

When a cloud provider is detected, the **Provider** line appears in the info block and several checks adjust their behaviour:

- `hba_trust` — suppressed (pg_hba is managed by the provider)
- `no_standby` — suppressed (HA is handled at infrastructure level)
- `logging_collector` — suppressed (stderr is captured by the cloud log pipeline)
- `archive_mode` — replaced with a cloud-specific backup advisory
- Configuration remediations — include provider-specific parameter group instructions

---

## Opps Score

After every run, pgopps calculates an **Opps Score** — a single number from 0 to 100 that reflects the overall health of the instance based on the severity of all findings detected.

| Score | Colour | Grade |
|---|---|---|
| 75 – 100 | 🟢 Green | Good / Excellent |
| 50 – 74 | 🟡 Yellow | Fair |
| 0 – 49 | 🔴 Red | Poor / Critical |

The score is calculated from **all checks**, regardless of the priority filter (`-p`). Fixing CRITICAL and HIGH findings has the biggest impact on the score.

---

## Priority levels

| Value | Label | Meaning |
|---|---|---|
| 1 | `CRITICAL` | Immediate risk: data loss, security breach, cluster crash |
| 2 | `HIGH` | Significant risk, should be addressed within days |
| 3 | `MEDIUM` | Sub-optimal configuration, address within weeks |
| 4 | `LOW` | Minor improvement opportunity |
| 5 | `INFO` | Advisory — requires manual verification |

Default output shows CRITICAL, HIGH, and MEDIUM (`-p 3`).

---

## Adding a new check

1. Write `static Finding *check_foo(PGconn *conn, const Options *opts)` in `src/checks/<group>.c`.
2. Add an entry to that file's `const Check checks_<group>[]` array.
3. Rebuild — `registry.c` picks it up automatically via the count variable.

See `CLAUDE.md` for the full architectural guide.

---

## License

MIT
