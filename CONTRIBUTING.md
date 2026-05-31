# Contributing to pgopps

Thank you for your interest in contributing. This document covers how to build the project, how it is structured internally, and how to add new checks.

---

## Build

```bash
cmake -S . -B build
cmake --build build
```

Binary lands at `build/pgopps`. Release build:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

**Required packages** (Arch Linux: `cmake postgresql-libs gcc` · Debian/Ubuntu: `cmake libpq-dev gcc`)

No other external dependencies.

---

## Architecture

pgopps connects read-only to a PostgreSQL instance and emits prioritised, grouped findings:

```
main() → db_connect() → registry_init() → registry_run_all() → report_print()
```

### Core types (`include/pgopps.h`)

| Type | Purpose |
|---|---|
| `Finding` | A single observation: `title`, `description`, `remediation`, `fix_sql`, `Priority` (1=CRITICAL…5=INFO), `CheckGroup`, `FixType`, finding `id`, and a `next` pointer (singly-linked list). |
| `Check` | A check descriptor: `name`, `description`, `group`, and a `run(PGconn*, const Options*)` function pointer that returns a `Finding*` chain (NULL = nothing found). |
| `Options` | Parsed CLI state (`connstr`, `format`, `min_priority`, `verbose`, `fix_script`, `exit_code`, `cloud`) passed to every check function. |

### Check groups (`CheckGroup` enum)

| Value | Group | SOC-2 |
|---|---|---|
| 0 | `GROUP_PERFORMANCE` | A1.2 |
| 1 | `GROUP_SECURITY` | CC6 |
| 2 | `GROUP_ENCRYPTION` | CC6.7, C1 |
| 3 | `GROUP_AUDIT_AND_LOGGING` | CC7.2 |
| 4 | `GROUP_DATA_INTEGRITY` | PI1 |
| 5 | `GROUP_MAINTENANCE` | — |
| 6 | `GROUP_CONFIGURATION` | A1.2 |
| 7 | `GROUP_REPLICATION_HA` | A1.3 |
| 8 | `GROUP_BACKUP_RECOVERY` | A1.3 |

`GROUP__COUNT` must remain the last value in the enum.

### Output pipeline

| Source | Description |
|---|---|
| `src/info.c` | Prints the connection info block (target + auditor sections) |
| `src/report.c` | Sorts findings by `(group, priority)`, renders TEXT / JSON / Markdown |
| `src/score.c` | Calculates and renders the Opps Score (0–100) |
| `src/fixscript.c` | `--fix-script`: emits a ready-to-run SQL fix script |
| `src/htmlreport.c` | `-f html`: emits a self-contained HTML report |

### Cloud provider detection (`src/cloud.c`)

`db_detect_cloud(PGconn *)` fingerprints `pg_roles` at startup (`rdsadmin`, `azure_superuser`, `cloudsqlsuperuser`, `supabase_admin`, `neon_superuser`, `avnadmin`) and stores the result in `Options.cloud`.

Cloud-aware check behaviour:
- `hba_trust` — suppressed on cloud (pg_hba is provider-managed)
- `no_standby` — suppressed on cloud (HA handled at infrastructure level)
- `logging_collector` — suppressed on cloud
- `configuration/*` remediations — switch to "resize instance" / "use parameter group"

### Opps Score (`src/score.c`)

Penalties applied to **all** findings regardless of the `-p` filter:

| Severity | Penalty |
|---|---|
| CRITICAL | −15 |
| HIGH | −8 |
| MEDIUM | −4 |
| LOW | −1 |
| INFO | 0 |

Score = max(0, 100 − total penalty). Colour thresholds: ≥75 green · ≥50 yellow · <50 red.

### Fix types (`FixType` enum)

Checks that have an automatable fix populate `Finding.fix_sql` and set `Finding.fix_type`:

| Value | Meaning |
|---|---|
| `FIX_NONE` | Manual action required — no SQL generated |
| `FIX_RELOAD` | `ALTER SYSTEM SET` / `GRANT` — `pg_reload_conf()` sufficient |
| `FIX_RESTART` | `ALTER SYSTEM SET` — PostgreSQL restart required |

---

## Adding a new check

1. Write a function in the appropriate `src/checks/<group>.c`:
   ```c
   static Finding *check_foo(PGconn *conn, const Options *opts)
   ```
   Return a `Finding *` (or `NULL` if nothing found). Add `(void)opts;` if the function does not use cloud context.

2. Optionally populate `fix_sql` and `fix_type` on the returned finding for `--fix-script` support:
   ```c
   Finding *f = finding_new(...);
   f->fix_type = FIX_RELOAD;
   strncpy(f->fix_sql, "ALTER SYSTEM SET foo = bar;\nSELECT pg_reload_conf();",
           sizeof(f->fix_sql) - 1);
   return f;
   ```

3. Add an entry to the file's `const Check checks_<group>[]` array. No registration needed elsewhere — `registry.c` picks it up automatically via the `checks_<group>_count` variable.

### Adding a new group

Add a value to `CheckGroup` → add a `group_name()` case in `utils.c` and a `group_abbrev()` case → declare the extern array in `registry.h` → wire it in `registry_init()` → create the `.c` source file → add it to `CMakeLists.txt`.

---

## Commit workflow

Before every commit:

1. Bump `PGOPPS_VERSION` in `include/pgopps.h`
2. Bump `project(pgopps VERSION ...)` in `CMakeLists.txt`
3. Add an entry to `CHANGELOG.md`

Pushing a `v*.*.*` tag triggers the GitHub Actions workflow which builds a stripped release binary and publishes a GitHub Release automatically.
