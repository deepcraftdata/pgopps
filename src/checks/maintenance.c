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

static Finding *check_dead_tuples(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT schemaname, relname,"
        "       n_dead_tup,"
        "       n_live_tup,"
        "       round(n_dead_tup::numeric"
        "           / NULLIF(n_live_tup + n_dead_tup, 0) * 100, 1) AS dead_pct,"
        "       pg_size_pretty(pg_total_relation_size(relid))        AS size,"
        "       COALESCE(last_autovacuum::text, last_vacuum::text, 'never') AS last_vac"
        "  FROM pg_stat_user_tables"
        " WHERE n_live_tup > 1000"
        "   AND n_dead_tup::numeric"
        "       / NULLIF(n_live_tup + n_dead_tup, 0) > 0.1"   /* > 10% dead */
        " ORDER BY n_dead_tup DESC"
        " LIMIT 10");
    if (!res) return NULL;

    int n = PQntuples(res);

    double max_pct = atof(PQgetvalue(res, 0, 4));
    Priority p = (max_pct >= 50.0) ? PRIORITY_HIGH : PRIORITY_MEDIUM;

    char desc[1024] = {0};
    char *dp  = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(dp, rem,
        "%d table(s) with dead tuple ratio above 10%% — VACUUM needed:\n", n);
    dp += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(dp, rem,
            "  %s.%s  dead: %s%% (%s dead / %s live, size: %s, last vacuum: %s)\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 4),
            PQgetvalue(res, i, 2), PQgetvalue(res, i, 3),
            PQgetvalue(res, i, 5), PQgetvalue(res, i, 6));
        dp += w; rem -= w;
    }
    PQclear(res);

    return finding_new(p, GROUP_MAINTENANCE,
        "Tables with high dead tuple ratio",
        desc,
        "Run: VACUUM ANALYZE <schema>.<table>; "
        "For autovacuum to keep up, verify autovacuum_vacuum_scale_factor "
        "and autovacuum_vacuum_cost_delay are not too conservative.");
}

static Finding *check_xid_wraparound(PGconn *conn, const Options *opts)
{
    (void)opts;
    /*
     * PostgreSQL freezes tuples before the XID age reaches 2^31 ≈ 2.1B.
     * Autovacuum triggers aggressive freezing at autovacuum_freeze_max_age (200M default).
     * We warn at 500M (approaching the autovacuum threshold) and escalate at 1.5B.
     */
    PGresult *res = query(conn,
        "SELECT n.nspname, c.relname,"
        "       age(c.relfrozenxid)                                AS xid_age,"
        "       round(age(c.relfrozenxid)::numeric"
        "           / 2100000000 * 100, 1)                         AS pct,"
        "       pg_size_pretty(pg_total_relation_size(c.oid))      AS size"
        "  FROM pg_class c"
        "  JOIN pg_namespace n ON n.oid = c.relnamespace"
        " WHERE c.relkind IN ('r', 't')"
        "   AND n.nspname NOT IN ('pg_catalog','information_schema')"
        "   AND age(c.relfrozenxid) > 500000000"
        " ORDER BY age(c.relfrozenxid) DESC"
        " LIMIT 10");
    if (!res) return NULL;

    int n = PQntuples(res);

    long long max_age = atoll(PQgetvalue(res, 0, 2));
    double    max_pct = atof(PQgetvalue(res, 0, 3));
    Priority  p;

    if      (max_age >= 1500000000LL) p = PRIORITY_CRITICAL;
    else if (max_age >= 1000000000LL) p = PRIORITY_HIGH;
    else                              p = PRIORITY_MEDIUM;

    char desc[1024] = {0};
    char *dp  = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(dp, rem,
        "%d table(s) approaching transaction ID wraparound "
        "(highest: %.1f%% of 2.1B limit):\n", n, max_pct);
    dp += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(dp, rem, "  %s.%s  age: %s XIDs (%.1f%%, size: %s)\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2), atof(PQgetvalue(res, i, 3)),
            PQgetvalue(res, i, 4));
        dp += w; rem -= w;
    }

    if (rem > 0 && p == PRIORITY_CRITICAL)
        strncat(dp,
            "CRITICAL: PostgreSQL will refuse all writes when XID age reaches 2.1B "
            "to prevent data corruption.",
            rem - 1);
    PQclear(res);

    return finding_new(p, GROUP_MAINTENANCE,
        "Tables approaching transaction ID wraparound",
        desc,
        "Run: VACUUM FREEZE <schema>.<table>; "
        "For database-wide freeze: VACUUM FREEZE; (holds AccessShareLock only). "
        "Investigate why autovacuum has not frozen these tables: "
        "check autovacuum_freeze_max_age and per-table storage parameters.");
}

static Finding *check_never_analyzed(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT schemaname, relname,"
        "       n_live_tup,"
        "       pg_size_pretty(pg_total_relation_size(relid)) AS size"
        "  FROM pg_stat_user_tables"
        " WHERE last_analyze      IS NULL"
        "   AND last_autoanalyze  IS NULL"
        "   AND n_live_tup > 1000"
        " ORDER BY pg_total_relation_size(relid) DESC"
        " LIMIT 10");
    if (!res) return NULL;

    int n = PQntuples(res);

    char desc[1024] = {0};
    char *dp  = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(dp, rem,
        "%d table(s) with no statistics — never analyzed since last stats reset:\n", n);
    dp += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(dp, rem, "  %s.%s  (%s live rows, %s)\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2), PQgetvalue(res, i, 3));
        dp += w; rem -= w;
    }

    if (rem > 0)
        strncat(dp,
            "Without statistics the query planner uses default estimates, "
            "often choosing poor plans (wrong join order, seq scan instead of index).",
            rem - 1);
    PQclear(res);

    return finding_new(PRIORITY_MEDIUM, GROUP_MAINTENANCE,
        "Tables with no planner statistics (never analyzed)",
        desc,
        "Run: ANALYZE <schema>.<table>; "
        "Or database-wide: ANALYZE; "
        "Check that autovacuum is running and not blocked on these tables.");
}

static Finding *check_autovacuum_disabled(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT n.nspname, c.relname,"
        "       pg_size_pretty(pg_total_relation_size(c.oid)) AS size"
        "  FROM pg_class c"
        "  JOIN pg_namespace n ON n.oid = c.relnamespace"
        " WHERE c.relkind = 'r'"
        "   AND n.nspname NOT IN ('pg_catalog','information_schema')"
        "   AND EXISTS ("
        "       SELECT 1 FROM unnest(c.reloptions) opt"
        "        WHERE opt LIKE 'autovacuum_enabled=false%')"
        " ORDER BY pg_total_relation_size(c.oid) DESC");
    if (!res) return NULL;

    int n = PQntuples(res);

    char desc[1024] = {0};
    char *dp  = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(dp, rem,
        "%d table(s) with autovacuum explicitly disabled via storage parameter:\n", n);
    dp += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(dp, rem, "  %s.%s (%s)\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2));
        dp += w; rem -= w;
    }

    if (rem > 0)
        strncat(dp,
            "These tables will accumulate dead tuples and are at risk of XID "
            "wraparound unless manually vacuumed on a schedule.",
            rem - 1);
    PQclear(res);

    return finding_new(PRIORITY_HIGH, GROUP_MAINTENANCE,
        "Tables with autovacuum explicitly disabled",
        desc,
        "Re-enable autovacuum: ALTER TABLE <schema>.<table> "
        "RESET (autovacuum_enabled); "
        "If disabled for performance, tune autovacuum_vacuum_cost_delay "
        "and autovacuum_vacuum_scale_factor per-table instead of disabling entirely.");
}

/* ---------------------------------------------------------------- */

const Check checks_maintenance[] = {
    { "dead_tuples",          "Tables with high dead tuple ratio needing VACUUM",    GROUP_MAINTENANCE, check_dead_tuples          },
    { "xid_wraparound",       "Tables approaching transaction ID wraparound",        GROUP_MAINTENANCE, check_xid_wraparound       },
    { "never_analyzed",       "Tables with no planner statistics",                   GROUP_MAINTENANCE, check_never_analyzed       },
    { "autovacuum_disabled",  "Tables with autovacuum disabled per-table",           GROUP_MAINTENANCE, check_autovacuum_disabled  },
};

const int checks_maintenance_count =
    sizeof(checks_maintenance) / sizeof(checks_maintenance[0]);
