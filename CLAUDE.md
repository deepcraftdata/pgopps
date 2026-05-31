# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

```bash
cmake -S . -B build
cmake --build build
```

Binary lands at `build/pgopps`. For a release build:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

**Required system packages** (Arch Linux): `cmake`, `postgresql-libs` (libpq), and `gcc` are installed. No other external dependencies.

## Architecture

pgopps connects read-only to a PostgreSQL instance and emits prioritized, grouped findings. The flow is:

```
main() → db_connect() → registry_init() → registry_run_all() → report_print()
```

### Core types (`include/pgopps.h`)

Everything flows through three types:

- **`Finding`** — a single observation: `title`, `description`, `remediation`, `Priority` (1=CRITICAL…5=INFO), `CheckGroup`, and a `next` pointer (singly-linked list per check).
- **`Check`** — a check descriptor: `name`, `description`, `group`, and a `run(PGconn*)` function pointer that returns a `Finding*` list (NULL = nothing found).
- **`Options`** — parsed CLI state passed to `report_print()`.

### Check groups (`CheckGroup` enum, ordered)

| Value | Group | SOC-II relevance |
|---|---|---|
| 0 | `GROUP_PERFORMANCE` | A1.2 Capacity |
| 1 | `GROUP_SECURITY` | CC6 Access Control |
| 2 | `GROUP_ENCRYPTION` | CC6.7, C1 |
| 3 | `GROUP_AUDIT_AND_LOGGING` | CC7.2 Monitoring |
| 4 | `GROUP_DATA_INTEGRITY` | PI1 |
| 5 | `GROUP_MAINTENANCE` | — |
| 6 | `GROUP_CONFIGURATION` | A1.2 |
| 7 | `GROUP_REPLICATION_HA` | A1.3 |
| 8 | `GROUP_BACKUP_RECOVERY` | A1.3 |

The `GROUP__COUNT` sentinel must stay last in the enum.

### Cloud provider detection (`src/cloud.c`)

`db_detect_cloud(PGconn *)` runs at startup and stores the result in `Options.cloud`. Detection uses `pg_roles` fingerprints (`rdsadmin`, `azure_superuser`, `cloudsqlsuperuser`, `supabase_admin`, `neon_superuser`, `avnadmin`) and `pg_settings` fallbacks.

`cloud_param_hint(CloudProvider)` returns a provider-specific parameter-change instruction appended to remediation strings. `cloud_provider_name(CloudProvider)` returns the display name shown in the info block (NULL for self-hosted → line is omitted).

**Cloud-aware check behaviour:**
- `security/hba_trust` — suppressed on any cloud (pg_hba is provider-managed)
- `configuration/*` — remediation text switches to "resize instance" or "use parameter group" instead of "edit postgresql.conf"

### Adding a new check

1. Write a `static Finding *check_foo(PGconn *conn, const Options *opts)` function in the appropriate `src/checks/<group>.c`. Add `(void)opts;` if the function doesn't use cloud context.
2. Add an entry to that file's `const Check checks_<group>[]` array.
3. No registration needed elsewhere — `registry.c` picks it up via the `checks_<group>_count` variable.

To add an entirely new group: add a value to `CheckGroup`, add `group_name()` case in `utils.c`, declare the extern array in `registry.h`, wire it in `registry_init()`, create the `.c` file, and add it to the gcc command / `CMakeLists.txt`.

### Opps Score (`src/score.c`)

`score_calculate(findings, count)` computes a 0–100 score by applying severity penalties to **all** findings regardless of the user's `-p` filter:

| Severity | Penalty |
|---|---|
| CRITICAL | −15 |
| HIGH | −8 |
| MEDIUM | −4 |
| LOW | −1 |
| INFO | 0 |

`score_print(score, total, opts)` renders the bar + grade after the findings list. Color thresholds: ≥75 green · ≥50 yellow · <50 red. Suppressed in JSON mode.

### Report output (`src/report.c`)

Findings are sorted by `(group, priority)` before printing. Text output uses ANSI colours keyed on `Priority`. JSON output is hand-formatted (no external JSON library). The `-v` flag adds `description` and `remediation` to text output.

### Connection (`src/connection.c`)

`db_connect()` sets `default_transaction_read_only = on` immediately after connecting, so checks can never accidentally write regardless of the user's privileges.
