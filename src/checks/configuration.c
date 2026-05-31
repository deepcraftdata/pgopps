#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pgopps.h"
#include "checks/registry.h"

/* Append the cloud provider's parameter-change instructions to buf. */
static void append_cloud_hint(char *buf, size_t size, CloudProvider cp)
{
    const char *hint = cloud_param_hint(cp);
    if (!hint) return;
    size_t used = strlen(buf);
    if (used + 2 < size) {
        buf[used] = ' ';
        strncpy(buf + used + 1, hint, size - used - 2);
        buf[size - 1] = '\0';
    }
}

/* Run a single-row SELECT; returns NULL and clears result on any error. */
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

static Finding *check_shared_buffers(PGconn *conn, const Options *opts)
{
    PGresult *res = query(conn,
        "SELECT pg_size_bytes(current_setting('shared_buffers')),"
        "       current_setting('shared_buffers')");
    if (!res) return NULL;

    long long bytes = atoll(PQgetvalue(res, 0, 0));
    char      value[32] = {0};
    strncpy(value, PQgetvalue(res, 0, 1), sizeof(value) - 1);
    PQclear(res);

    /* 128 MB is the out-of-the-box default; above that we assume intentional */
    if (bytes > 128LL * 1024 * 1024)
        return NULL;

    char desc[512];
    snprintf(desc, sizeof(desc),
        "shared_buffers = %s is the PostgreSQL out-of-the-box default. "
        "For production systems it should be ~25%% of total RAM. "
        "This setting controls the size of PostgreSQL's shared memory buffer "
        "pool; too small a value forces heavy reliance on the OS page cache.",
        value);

    char rem[512];
    if (opts->cloud != CLOUD_NONE)
        snprintf(rem, sizeof(rem),
            "Resize your database instance to a larger tier to increase "
            "shared_buffers (typically auto-configured as ~25%% of instance RAM).");
    else
        snprintf(rem, sizeof(rem),
            "Set shared_buffers = '<25%% of RAM>' in postgresql.conf and restart. "
            "e.g. for a 16 GB server: shared_buffers = '4GB'");
    append_cloud_hint(rem, sizeof(rem), opts->cloud);

    return finding_new(PRIORITY_MEDIUM, GROUP_CONFIGURATION,
        "shared_buffers at default (128MB)", desc, rem);
}

static Finding *check_wal_level(PGconn *conn, const Options *opts)
{
    PGresult *res = query(conn, "SELECT current_setting('wal_level')");
    if (!res) return NULL;

    char level[32] = {0};
    strncpy(level, PQgetvalue(res, 0, 0), sizeof(level) - 1);
    PQclear(res);

    if (strcmp(level, "minimal") != 0)
        return NULL;

    char rem[512];
    snprintf(rem, sizeof(rem),
        "Set wal_level = replica (or logical) in postgresql.conf and restart PostgreSQL.");
    append_cloud_hint(rem, sizeof(rem), opts->cloud);

    return finding_new(PRIORITY_HIGH, GROUP_CONFIGURATION,
        "wal_level = minimal",
        "wal_level = minimal disables WAL archiving, streaming replication, "
        "and logical decoding. Point-in-time recovery (PITR) is impossible "
        "and no standby server can be attached.",
        rem);
}

static Finding *check_max_connections(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT current_setting('max_connections')::int,"
        "       current_setting('work_mem'),"
        "       pg_size_pretty("
        "           current_setting('max_connections')::bigint"
        "           * pg_size_bytes(current_setting('work_mem')))");
    if (!res) return NULL;

    int  max_conn       = atoi(PQgetvalue(res, 0, 0));
    char work_mem[32]   = {0};
    char worst_case[32] = {0};
    strncpy(work_mem,   PQgetvalue(res, 0, 1), sizeof(work_mem)   - 1);
    strncpy(worst_case, PQgetvalue(res, 0, 2), sizeof(worst_case) - 1);
    PQclear(res);

    if (max_conn <= 200)
        return NULL;

    char title[128], desc[512];
    snprintf(title, sizeof(title),
        "max_connections = %d without a connection pooler", max_conn);
    snprintf(desc, sizeof(desc),
        "max_connections = %d. With work_mem = %s, worst-case memory for sort "
        "operations alone is %s (max_connections × work_mem). High connection "
        "counts without a pooler waste memory on idle backends and increase "
        "context-switch overhead under load.",
        max_conn, work_mem, worst_case);

    return finding_new(PRIORITY_MEDIUM, GROUP_CONFIGURATION,
        title, desc,
        "Lower max_connections and place PgBouncer (transaction mode) in front "
        "of PostgreSQL. Typical production target: max_connections = 100-200.");
}

static Finding *check_work_mem(PGconn *conn, const Options *opts)
{
    PGresult *res = query(conn,
        "SELECT pg_size_bytes(current_setting('work_mem')),"
        "       current_setting('work_mem')");
    if (!res) return NULL;

    long long bytes = atoll(PQgetvalue(res, 0, 0));
    char      value[32] = {0};
    strncpy(value, PQgetvalue(res, 0, 1), sizeof(value) - 1);
    PQclear(res);

    /* 4 MB is the default; above 64 MB is a different concern (memory pressure) */
    if (bytes > 4LL * 1024 * 1024)
        return NULL;

    char desc[512];
    snprintf(desc, sizeof(desc),
        "work_mem = %s is the PostgreSQL default. Each sort operation or hash "
        "join node in a query plan can use up to work_mem of RAM before spilling "
        "to disk. With complex queries this can significantly slow down execution.",
        value);

    char rem[512];
    snprintf(rem, sizeof(rem),
        "Increase work_mem (e.g. 64MB for OLTP, 256MB+ for analytics). "
        "Note: each query node can allocate work_mem independently — "
        "account for max_connections × work_mem in your RAM budget.");
    append_cloud_hint(rem, sizeof(rem), opts->cloud);

    return finding_new(PRIORITY_LOW, GROUP_CONFIGURATION,
        "work_mem at default (4MB)", desc, rem);
}

static Finding *check_checkpoint_completion_target(PGconn *conn, const Options *opts)
{
    PGresult *res = query(conn,
        "SELECT current_setting('checkpoint_completion_target')::float,"
        "       current_setting('server_version_num')::int");
    if (!res) return NULL;

    double cct     = atof(PQgetvalue(res, 0, 0));
    int    ver_num = atoi(PQgetvalue(res, 0, 1));
    PQclear(res);

    if (cct >= 0.9)
        return NULL;

    char desc[512];
    if (ver_num < 140000 && cct == 0.5) {
        snprintf(desc, sizeof(desc),
            "checkpoint_completion_target = %.1f is the pre-PG14 default. "
            "PostgreSQL 14+ changed this default to 0.9. Spreading checkpoint "
            "I/O over 90%% of the interval prevents write spikes that cause "
            "query latency spikes.", cct);
    } else {
        snprintf(desc, sizeof(desc),
            "checkpoint_completion_target = %.1f concentrates checkpoint I/O "
            "into a shorter burst at the end of each checkpoint interval, "
            "causing periodic write spikes visible as latency outliers.", cct);
    }

    char rem[512];
    snprintf(rem, sizeof(rem),
        "Set checkpoint_completion_target = 0.9. "
        "Reload without restart: SELECT pg_reload_conf();");
    append_cloud_hint(rem, sizeof(rem), opts->cloud);

    return finding_new(PRIORITY_MEDIUM, GROUP_CONFIGURATION,
        "checkpoint_completion_target < 0.9", desc, rem);
}

static Finding *check_autovacuum(PGconn *conn, const Options *opts)
{
    PGresult *res = query(conn, "SELECT current_setting('autovacuum')");
    if (!res) return NULL;

    char val[8] = {0};
    strncpy(val, PQgetvalue(res, 0, 0), sizeof(val) - 1);
    PQclear(res);

    if (strcmp(val, "off") != 0)
        return NULL;

    char rem[512];
    snprintf(rem, sizeof(rem),
        "Set autovacuum = on. If disabled for performance, tune "
        "autovacuum_vacuum_cost_delay and autovacuum_vacuum_scale_factor instead.");
    append_cloud_hint(rem, sizeof(rem), opts->cloud);

    return finding_new(PRIORITY_CRITICAL, GROUP_CONFIGURATION,
        "autovacuum is disabled globally",
        "autovacuum = off means dead tuples accumulate indefinitely, leading to "
        "table and index bloat. Eventually transaction ID wraparound will force "
        "PostgreSQL into read-only emergency mode to protect data integrity.",
        rem);
}

static Finding *check_random_page_cost(PGconn *conn, const Options *opts)
{
    PGresult *res = query(conn,
        "SELECT current_setting('random_page_cost')::float");
    if (!res) return NULL;

    double rpc = atof(PQgetvalue(res, 0, 0));
    PQclear(res);

    if (rpc < 2.0)
        return NULL;

    char desc[512];
    snprintf(desc, sizeof(desc),
        "random_page_cost = %.1f is the default tuned for spinning hard disks. "
        "If this server uses SSD or NVMe storage, the query planner overestimates "
        "the cost of index scans and may incorrectly choose sequential scans "
        "over more efficient index access paths.", rpc);

    char rem[512];
    snprintf(rem, sizeof(rem),
        "If running on SSD/NVMe, set random_page_cost = 1.1. "
        "Reload without restart: SELECT pg_reload_conf();");
    append_cloud_hint(rem, sizeof(rem), opts->cloud);

    return finding_new(PRIORITY_LOW, GROUP_CONFIGURATION,
        "random_page_cost suggests spinning-disk tuning", desc, rem);
}

/* ---------------------------------------------------------------- */

const Check checks_configuration[] = {
    { "shared_buffers",               "shared_buffers at PostgreSQL default",                           GROUP_CONFIGURATION, check_shared_buffers               },
    { "wal_level",                    "wal_level = minimal blocks replication and PITR",                GROUP_CONFIGURATION, check_wal_level                    },
    { "max_connections",              "High max_connections without a pooler wastes memory",            GROUP_CONFIGURATION, check_max_connections              },
    { "work_mem",                     "work_mem at default may cause disk-based sorts",                 GROUP_CONFIGURATION, check_work_mem                     },
    { "checkpoint_completion_target", "checkpoint_completion_target < 0.9 causes write spikes",        GROUP_CONFIGURATION, check_checkpoint_completion_target },
    { "autovacuum",                   "autovacuum = off is a critical risk",                            GROUP_CONFIGURATION, check_autovacuum                   },
    { "random_page_cost",             "random_page_cost = 4.0 is tuned for spinning disks, not SSDs",  GROUP_CONFIGURATION, check_random_page_cost             },
};

const int checks_configuration_count =
    sizeof(checks_configuration) / sizeof(checks_configuration[0]);
