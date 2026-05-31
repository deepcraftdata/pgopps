#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pgopps.h"
#include "checks/registry.h"

static PGresult *query(PGconn *conn, const char *sql)
{
    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }
    return res;
}

/* ---------------------------------------------------------------- */

static Finding *check_archive_mode(PGconn *conn, const Options *opts)
{
    /* Cloud providers handle PITR at the infrastructure level */
    if (opts->cloud != CLOUD_NONE) {
        return finding_new(PRIORITY_INFO, GROUP_BACKUP_RECOVERY,
            "Backup managed by cloud provider — verify retention settings",
            "This is a managed cloud PostgreSQL instance. "
            "Point-in-time recovery (PITR) and base backups are handled by the "
            "cloud provider, not by archive_mode/archive_command. "
            "Ensure the backup retention period meets your RPO requirements "
            "and that restore procedures are documented and tested.",
            "Review your cloud provider's backup retention settings and "
            "run a test restore to a separate instance at least quarterly.");
    }

    PGresult *res = query(conn,
        "SELECT current_setting('archive_mode'),"
        "       current_setting('archive_command')");
    if (!res) return NULL;

    char mode[16] = {0}, cmd[256] = {0};
    strncpy(mode, PQgetvalue(res, 0, 0), sizeof(mode) - 1);
    strncpy(cmd,  PQgetvalue(res, 0, 1), sizeof(cmd)  - 1);
    PQclear(res);

    if (strcmp(mode, "off") == 0) {
        Finding *f = finding_new(PRIORITY_HIGH, GROUP_BACKUP_RECOVERY,
            "archive_mode = off — WAL archiving disabled, no PITR possible",
            "archive_mode = off means WAL segments are not archived. "
            "Point-in-time recovery (PITR) is impossible: you can only restore "
            "from a base backup to the exact moment it was taken. "
            "Any committed transactions after the last base backup are unrecoverable "
            "if the primary is lost.",
            "Set archive_mode = on and configure archive_command (or archive_library) "
            "in postgresql.conf. Requires a PostgreSQL restart.");
        if (f) {
            f->fix_type = FIX_RESTART;
            strncpy(f->fix_sql,
                "ALTER SYSTEM SET archive_mode = on;\n"
                "-- Also set archive_command before restarting, e.g.:\n"
                "-- ALTER SYSTEM SET archive_command = 'cp %p /mnt/wal_archive/%f';\n"
                "-- Restart PostgreSQL to apply.",
                sizeof(f->fix_sql) - 1);
        }
        return f;
    }

    /* archive_mode is on but command is empty or disabled */
    if (cmd[0] == '\0' || strcmp(cmd, "(disabled)") == 0) {
        return finding_new(PRIORITY_HIGH, GROUP_BACKUP_RECOVERY,
            "archive_mode = on but archive_command is empty",
            "archive_mode is enabled but archive_command is not configured. "
            "WAL archiving is silently failing — PostgreSQL will accumulate "
            "WAL in pg_wal indefinitely until archive_command is set and works.",
            "Set archive_command to a working copy command, e.g.: "
            "archive_command = 'cp %p /mnt/wal_archive/%f' "
            "or use pgBackRest / Barman for managed archiving.");
    }

    return NULL;
}

static Finding *check_archive_failures(PGconn *conn, const Options *opts)
{
    (void)opts;

    /* Only meaningful when archiving is configured */
    PGresult *mode_res = query(conn, "SELECT current_setting('archive_mode')");
    if (!mode_res) return NULL;
    char mode[16] = {0};
    strncpy(mode, PQgetvalue(mode_res, 0, 0), sizeof(mode) - 1);
    PQclear(mode_res);
    if (strcmp(mode, "off") == 0) return NULL;

    PGresult *res = query(conn,
        "SELECT failed_count,"
        "       COALESCE(last_failed_wal, 'unknown')                AS wal,"
        "       COALESCE(last_failed_time::text, 'unknown')         AS failed_at,"
        "       EXTRACT(epoch FROM now()-last_failed_time)::int     AS secs_ago"
        "  FROM pg_stat_archiver"
        " WHERE last_failed_time IS NOT NULL"
        "   AND now() - last_failed_time < interval '24 hours'");
    if (!res) return NULL;

    int  failed_count = atoi(PQgetvalue(res, 0, 0));
    char wal[128]     = {0};
    char failed_at[64]= {0};
    int  secs_ago     = atoi(PQgetvalue(res, 0, 3));
    strncpy(wal,       PQgetvalue(res, 0, 1), sizeof(wal)       - 1);
    strncpy(failed_at, PQgetvalue(res, 0, 2), sizeof(failed_at) - 1);
    PQclear(res);

    char title[128], desc[512];
    snprintf(title, sizeof(title),
        "WAL archive failures in the last 24 hours (%d total)", failed_count);
    snprintf(desc, sizeof(desc),
        "pg_stat_archiver shows %d archive failure(s). "
        "Last failed WAL: %s at %s (%d seconds ago). "
        "While archive is failing, WAL segments accumulate in pg_wal. "
        "If pg_wal fills the disk, PostgreSQL will halt all writes.",
        failed_count, wal, failed_at, secs_ago);

    return finding_new(PRIORITY_CRITICAL, GROUP_BACKUP_RECOVERY, title, desc,
        "Check the archive_command: run it manually against the last failed WAL. "
        "Verify target directory exists, has write permission, and has disk space. "
        "Monitor: SELECT * FROM pg_stat_archiver;");
}

static Finding *check_archive_stalled(PGconn *conn, const Options *opts)
{
    (void)opts;

    PGresult *mode_res = query(conn, "SELECT current_setting('archive_mode')");
    if (!mode_res) return NULL;
    char mode[16] = {0};
    strncpy(mode, PQgetvalue(mode_res, 0, 0), sizeof(mode) - 1);
    PQclear(mode_res);
    if (strcmp(mode, "off") == 0) return NULL;

    /* If last_archived_time is NULL, archiving has never succeeded */
    PGresult *res = query(conn,
        "SELECT archived_count,"
        "       COALESCE(last_archived_time::text, 'never')          AS last_ok,"
        "       COALESCE("
        "           EXTRACT(epoch FROM now()-last_archived_time)::int,"
        "           -1)                                               AS secs_ago"
        "  FROM pg_stat_archiver");
    if (!res) return NULL;

    int  archived  = atoi(PQgetvalue(res, 0, 0));
    char last_ok[64] = {0};
    int  secs_ago  = atoi(PQgetvalue(res, 0, 2));
    strncpy(last_ok, PQgetvalue(res, 0, 1), sizeof(last_ok) - 1);
    PQclear(res);

    /* Stalled = archive_mode on, but nothing archived recently (or ever) */
    int stalled = (archived == 0) || (secs_ago > 3600);   /* > 1 hour */
    if (!stalled) return NULL;

    char desc[512];
    if (archived == 0) {
        snprintf(desc, sizeof(desc),
            "archive_mode is on but no WAL segments have ever been successfully archived "
            "(archived_count = 0). The archive_command may be misconfigured or the "
            "target is unreachable. WAL is accumulating in pg_wal.");
    } else {
        snprintf(desc, sizeof(desc),
            "archive_mode is on but the last successful archive was %s "
            "(%d seconds ago). For an active primary, this suggests the "
            "archive pipeline has stalled. WAL is accumulating in pg_wal.",
            last_ok, secs_ago);
    }

    return finding_new(PRIORITY_HIGH, GROUP_BACKUP_RECOVERY,
        "WAL archiving appears stalled",
        desc,
        "Test archive_command manually. Check disk space at archive destination. "
        "Review PostgreSQL logs for archive errors. "
        "Query: SELECT * FROM pg_stat_archiver;");
}

static Finding *check_wal_keep_size(PGconn *conn, const Options *opts)
{
    (void)opts;

    /* wal_keep_size (PG13+); silently skip on older versions */
    PGresult *res = query(conn,
        "SELECT current_setting('wal_keep_size', true),"
        "       current_setting('archive_mode')");
    if (!res) return NULL;

    if (PQgetisnull(res, 0, 0)) { PQclear(res); return NULL; }   /* PG < 13 */

    long long keep_mb    = atoll(PQgetvalue(res, 0, 0));
    char      arch[16]   = {0};
    strncpy(arch, PQgetvalue(res, 0, 1), sizeof(arch) - 1);
    PQclear(res);

    /* Only flag when both archiving AND keep_size are zero — no WAL retention at all */
    if (keep_mb > 0 || strcmp(arch, "off") != 0) return NULL;

    /* Also skip if replication slots exist (they retain WAL themselves) */
    PGresult *slot_res = PQexec(conn,
        "SELECT count(*) FROM pg_replication_slots");
    if (PQresultStatus(slot_res) == PGRES_TUPLES_OK) {
        int slots = atoi(PQgetvalue(slot_res, 0, 0));
        PQclear(slot_res);
        if (slots > 0) return NULL;
    } else {
        PQclear(slot_res);
    }

    Finding *f = finding_new(PRIORITY_MEDIUM, GROUP_BACKUP_RECOVERY,
        "No WAL retention configured (wal_keep_size = 0, archive_mode = off)",
        "wal_keep_size = 0 and archive_mode = off means no WAL segments are "
        "retained beyond what is immediately needed. "
        "If a standby falls behind or a restore scenario requires older WAL, "
        "those segments will already be recycled and unavailable.",
        "Set wal_keep_size to retain enough WAL to cover your longest expected "
        "standby lag (e.g. wal_keep_size = 1024 for 1 GB). "
        "Or enable archiving for unlimited WAL history.");
    if (f) {
        f->fix_type = FIX_RELOAD;
        strncpy(f->fix_sql,
            "ALTER SYSTEM SET wal_keep_size = 1024; -- 1 GB; adjust for your standby lag\n"
            "SELECT pg_reload_conf();",
            sizeof(f->fix_sql) - 1);
    }
    return f;
}

static Finding *check_pitr_verify(PGconn *conn, const Options *opts)
{
    /* Emit an INFO advisory about verifying backup recency */
    char desc[512], rem[512];

    if (opts->cloud != CLOUD_NONE) {
        snprintf(desc, sizeof(desc),
            "pgopps cannot verify cloud backup recency from SQL. "
            "Ensure your backup retention period covers your RPO and that "
            "a test restore has been performed recently.");
        snprintf(rem, sizeof(rem),
            "Review backup retention in your cloud console. "
            "Perform a test restore to a separate instance at least quarterly. "
            "%s",
            cloud_param_hint(opts->cloud) ? cloud_param_hint(opts->cloud) : "");
    } else {
        /* Check if archive_mode is off — base backup is the only option */
        PGresult *res = query(conn, "SELECT current_setting('archive_mode')");
        char mode[16] = "off";
        if (res) {
            strncpy(mode, PQgetvalue(res, 0, 0), sizeof(mode) - 1);
            PQclear(res);
        }

        if (strcmp(mode, "off") == 0) {
            snprintf(desc, sizeof(desc),
                "archive_mode = off. The only recovery option is a full base backup. "
                "pgopps cannot verify whether a recent base backup exists or "
                "how old it is (filesystem-level check required).");
            snprintf(rem, sizeof(rem),
                "Schedule regular base backups with pg_basebackup or pgBackRest. "
                "Verify the last backup timestamp and test restore periodically.");
        } else {
            snprintf(desc, sizeof(desc),
                "pgopps cannot verify the age or completeness of your base backup "
                "from SQL alone (filesystem-level check required). "
                "A working archive_command does not guarantee a usable base backup exists.");
            snprintf(rem, sizeof(rem),
                "Use pgBackRest (pgbackrest info) or Barman (barman check) to verify "
                "backup catalog and recency. Run a restore test to a separate server.");
        }
    }

    return finding_new(PRIORITY_INFO, GROUP_BACKUP_RECOVERY,
        "Verify base backup recency and restore procedure (manual check required)",
        desc, rem);
}

/* ---------------------------------------------------------------- */

const Check checks_backup_recovery[] = {
    { "archive_mode",    "archive_mode off or misconfigured — no PITR",             GROUP_BACKUP_RECOVERY, check_archive_mode    },
    { "archive_failures","Recent WAL archive failures in pg_stat_archiver",         GROUP_BACKUP_RECOVERY, check_archive_failures },
    { "archive_stalled", "WAL archiving stalled — nothing archived recently",       GROUP_BACKUP_RECOVERY, check_archive_stalled  },
    { "wal_keep_size",   "No WAL retention — wal_keep_size=0 and no archiving",     GROUP_BACKUP_RECOVERY, check_wal_keep_size    },
    { "pitr_verify",     "Manual verification: base backup recency and restore test",GROUP_BACKUP_RECOVERY, check_pitr_verify     },
};

const int checks_backup_recovery_count =
    sizeof(checks_backup_recovery) / sizeof(checks_backup_recovery[0]);
