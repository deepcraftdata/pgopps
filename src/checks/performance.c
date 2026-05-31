#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pgopps.h"
#include "checks/registry.h"

static PGresult *query(PGconn *conn, const char *sql)
{
    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return NULL;
    }
    return res;
}

/* ---------------------------------------------------------------- */

static Finding *check_cache_hit_ratio(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT round("
        "    blks_hit::numeric / NULLIF(blks_hit + blks_read, 0) * 100, 2"
        ") AS ratio"
        " FROM pg_stat_database"
        " WHERE datname = current_database()");
    if (!res) return NULL;

    if (PQgetisnull(res, 0, 0)) {   /* no I/O yet — skip */
        PQclear(res);
        return NULL;
    }

    double ratio = atof(PQgetvalue(res, 0, 0));
    PQclear(res);

    if (ratio >= 99.0)
        return NULL;

    char title[128], desc[512];
    Priority p = (ratio < 90.0) ? PRIORITY_HIGH : PRIORITY_MEDIUM;

    snprintf(title, sizeof(title),
        "Buffer cache hit ratio is %.2f%% (target: >99%%)", ratio);
    snprintf(desc, sizeof(desc),
        "The shared buffer cache hit ratio for database \"%s\" is %.2f%%. "
        "A ratio below 99%% means PostgreSQL is reading a significant portion "
        "of blocks from disk rather than from RAM. "
        "%s",
        PQdb(conn), ratio,
        (ratio < 90.0)
            ? "A ratio below 90% indicates a serious memory shortage or cold cache."
            : "Consider increasing shared_buffers or pg_prewarm for hot relations.");

    return finding_new(p, GROUP_PERFORMANCE, title, desc,
        "Increase shared_buffers (~25% of RAM) and restart PostgreSQL. "
        "Use pg_prewarm to warm the cache after restart. "
        "Verify no runaway queries are evicting the cache with large sequential scans.");
}

static Finding *check_seq_scans(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT schemaname, relname, seq_scan, n_live_tup, COALESCE(idx_scan, 0)"
        "  FROM pg_stat_user_tables"
        " WHERE n_live_tup  > 10000"
        "   AND seq_scan    > 50"
        "   AND COALESCE(idx_scan, 0) < seq_scan"
        " ORDER BY seq_scan * n_live_tup DESC"
        " LIMIT 5");
    if (!res) return NULL;

    int n = PQntuples(res);
    if (n == 0) { PQclear(res); return NULL; }

    char desc[1024] = {0};
    char *p = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(p, rem,
        "%d table(s) with frequent sequential scans and no index utilization:\n", n);
    p += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(p, rem, "  %s.%s  (seq_scan: %s, rows: ~%s)\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2), PQgetvalue(res, i, 3));
        p += w; rem -= w;
    }
    PQclear(res);

    return finding_new(PRIORITY_MEDIUM, GROUP_PERFORMANCE,
        "Tables with high sequential scan rate",
        desc,
        "Run EXPLAIN (ANALYZE, BUFFERS) on queries accessing these tables. "
        "Add indexes on frequently filtered or joined columns. "
        "Check pg_stat_statements for the responsible queries.");
}

static Finding *check_unused_indexes(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT s.schemaname, s.relname, s.indexrelname,"
        "       pg_size_pretty(pg_relation_size(s.indexrelid)) AS idx_size,"
        "       pg_relation_size(s.indexrelid)"
        "  FROM pg_stat_user_indexes s"
        "  JOIN pg_index i ON i.indexrelid = s.indexrelid"
        " WHERE s.idx_scan   = 0"
        "   AND NOT i.indisprimary"
        "   AND NOT i.indisunique"
        "   AND pg_relation_size(s.indexrelid) > 1024 * 1024"
        " ORDER BY pg_relation_size(s.indexrelid) DESC"
        " LIMIT 10");
    if (!res) return NULL;

    int n = PQntuples(res);
    if (n == 0) { PQclear(res); return NULL; }

    /* Total wasted size */
    long long total_bytes = 0;
    for (int i = 0; i < n; i++)
        total_bytes += atoll(PQgetvalue(res, i, 4));

    char total_pretty[32] = {0};
    /* Format manually to avoid another query round-trip */
    if      (total_bytes >= 1024LL*1024*1024) snprintf(total_pretty, sizeof(total_pretty), "%.1f GB", total_bytes / (1024.0*1024*1024));
    else if (total_bytes >= 1024*1024)        snprintf(total_pretty, sizeof(total_pretty), "%.0f MB", total_bytes / (1024.0*1024));
    else                                      snprintf(total_pretty, sizeof(total_pretty), "%.0f kB", total_bytes / 1024.0);

    char desc[1024] = {0};
    char *dp = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(dp, rem,
        "%d index(es) have never been scanned (total: %s). "
        "Each write to these tables pays the index maintenance cost for no read benefit:\n",
        n, total_pretty);
    dp += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(dp, rem, "  %s.%s on %s (%s)\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 2),
            PQgetvalue(res, i, 1), PQgetvalue(res, i, 3));
        dp += w; rem -= w;
    }
    PQclear(res);

    return finding_new(PRIORITY_LOW, GROUP_PERFORMANCE,
        "Unused indexes wasting write I/O and storage",
        desc,
        "Verify with pg_stat_reset() date and normal load before dropping. "
        "Drop with: DROP INDEX CONCURRENTLY <schema>.<indexname>;");
}

static Finding *check_long_running_queries(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT pid, usename, state,"
        "       round(extract(epoch FROM now()-query_start)/60)::int AS minutes,"
        "       left(query, 80) AS preview"
        "  FROM pg_stat_activity"
        " WHERE state NOT IN ('idle', 'idle in transaction (aborted)')"
        "   AND query_start IS NOT NULL"
        "   AND now() - query_start > interval '5 minutes'"
        "   AND pid != pg_backend_pid()"
        "   AND backend_type = 'client backend'"
        " ORDER BY query_start ASC"
        " LIMIT 5");
    if (!res) return NULL;

    int n = PQntuples(res);
    if (n == 0) { PQclear(res); return NULL; }

    int max_minutes = 0;
    for (int i = 0; i < n; i++) {
        int m = atoi(PQgetvalue(res, i, 3));
        if (m > max_minutes) max_minutes = m;
    }

    Priority p = (max_minutes >= 30) ? PRIORITY_HIGH : PRIORITY_MEDIUM;

    char desc[1024] = {0};
    char *dp = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(dp, rem, "%d long-running query/queries (longest: %d min):\n",
        n, max_minutes);
    dp += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(dp, rem, "  [pid %s, %s min, %s] %s\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 3),
            PQgetvalue(res, i, 2), PQgetvalue(res, i, 4));
        dp += w; rem -= w;
    }
    PQclear(res);

    return finding_new(p, GROUP_PERFORMANCE,
        "Long-running queries detected",
        desc,
        "Investigate with: SELECT * FROM pg_stat_activity WHERE pid = <pid>; "
        "Cancel with: SELECT pg_cancel_backend(<pid>); "
        "or terminate: SELECT pg_terminate_backend(<pid>);");
}

static Finding *check_idle_in_transaction(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT count(*),"
        "       COALESCE(max(round("
        "           extract(epoch FROM now()-state_change)/60))::int, 0)"
        "  FROM pg_stat_activity"
        " WHERE state = 'idle in transaction'"
        "   AND pid != pg_backend_pid()");
    if (!res) return NULL;

    int cnt         = atoi(PQgetvalue(res, 0, 0));
    int max_minutes = atoi(PQgetvalue(res, 0, 1));
    PQclear(res);

    if (cnt == 0) return NULL;

    Priority p = (max_minutes >= 15) ? PRIORITY_HIGH : PRIORITY_MEDIUM;

    char title[128], desc[512];
    snprintf(title, sizeof(title),
        "%d connection(s) idle in transaction (longest: %d min)", cnt, max_minutes);
    snprintf(desc, sizeof(desc),
        "%d backend(s) are in 'idle in transaction' state, with the longest open "
        "for %d minutes. These sessions hold row locks and prevent VACUUM from "
        "reclaiming dead tuples, causing table bloat over time.",
        cnt, max_minutes);

    return finding_new(p, GROUP_PERFORMANCE, title, desc,
        "Identify the application leaving transactions open. "
        "Set idle_in_transaction_session_timeout (e.g. 30min) in postgresql.conf "
        "to auto-terminate these sessions. Reload: SELECT pg_reload_conf();");
}

static Finding *check_connection_utilization(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT count(*),"
        "       (SELECT setting::int FROM pg_settings"
        "         WHERE name = 'max_connections')"
        "  FROM pg_stat_activity"
        " WHERE pid != pg_backend_pid()");
    if (!res) return NULL;

    int active   = atoi(PQgetvalue(res, 0, 0));
    int max_conn = atoi(PQgetvalue(res, 0, 1));
    PQclear(res);

    if (max_conn == 0) return NULL;

    int pct = (active * 100) / max_conn;
    if (pct < 60) return NULL;

    Priority p = (pct >= 80) ? PRIORITY_HIGH : PRIORITY_MEDIUM;

    char title[128], desc[512];
    snprintf(title, sizeof(title),
        "Connection utilization at %d%% (%d / %d)", pct, active, max_conn);
    snprintf(desc, sizeof(desc),
        "%d of %d max_connections are in use (%d%%). "
        "Approaching the connection limit causes new connection attempts to fail "
        "with 'FATAL: sorry, too many clients already'. "
        "Superuser connections (%s reserved) are the last line of defence for DBA access.",
        active, max_conn, pct,
        "3 slots are");

    return finding_new(p, GROUP_PERFORMANCE, title, desc,
        "Deploy a connection pooler (PgBouncer in transaction mode) to multiplex "
        "application connections. Consider lowering max_connections and reserving "
        "superuser_reserved_connections = 5.");
}

/* ---------------------------------------------------------------- */

const Check checks_performance[] = {
    { "cache_hit_ratio",        "Shared buffer cache hit ratio below target",               GROUP_PERFORMANCE, check_cache_hit_ratio        },
    { "seq_scans",              "Tables with high sequential scan rate (missing indexes)",  GROUP_PERFORMANCE, check_seq_scans              },
    { "unused_indexes",         "Indexes never scanned since last statistics reset",        GROUP_PERFORMANCE, check_unused_indexes         },
    { "long_running_queries",   "Queries running longer than 5 minutes",                    GROUP_PERFORMANCE, check_long_running_queries   },
    { "idle_in_transaction",    "Sessions open in idle-in-transaction state",               GROUP_PERFORMANCE, check_idle_in_transaction    },
    { "connection_utilization", "Connection count near max_connections limit",              GROUP_PERFORMANCE, check_connection_utilization },
};

const int checks_performance_count =
    sizeof(checks_performance) / sizeof(checks_performance[0]);
