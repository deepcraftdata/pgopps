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

static Finding *check_data_checksums(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn, "SHOW data_checksums");
    if (!res) return NULL;

    char val[8] = {0};
    strncpy(val, PQgetvalue(res, 0, 0), sizeof(val) - 1);
    PQclear(res);

    if (strcmp(val, "on") == 0) return NULL;

    return finding_new(PRIORITY_CRITICAL, GROUP_DATA_INTEGRITY,
        "data_checksums is disabled — silent data corruption undetectable",
        "data_checksums = off means PostgreSQL does not verify page checksums on "
        "every read from disk. Hardware errors, storage bugs, or filesystem "
        "corruption can silently produce wrong query results or corrupt indexes "
        "without any error being raised. This cannot be enabled without a "
        "full cluster rebuild (pg_checksums --enable requires downtime).",
        "Enable checksums on a new cluster or use: pg_checksums --enable --pgdata "
        "<PGDATA> (requires server shutdown). "
        "For cloud deployments, checksums are typically enabled by default.");
}

static Finding *check_tables_without_pk(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT n.nspname, c.relname,"
        "       pg_size_pretty(pg_total_relation_size(c.oid)) AS size,"
        "       pg_total_relation_size(c.oid)"
        "  FROM pg_class c"
        "  JOIN pg_namespace n ON n.oid = c.relnamespace"
        " WHERE c.relkind = 'r'"
        "   AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')"
        "   AND NOT EXISTS ("
        "       SELECT 1 FROM pg_constraint k"
        "        WHERE k.conrelid = c.oid AND k.contype = 'p')"
        " ORDER BY pg_total_relation_size(c.oid) DESC"
        " LIMIT 10");
    if (!res) return NULL;

    int n = PQntuples(res);

    /* Only flag if at least one table is meaningfully sized (> 1 MB) */
    long long max_bytes = atoll(PQgetvalue(res, 0, 3));
    if (max_bytes < 1024 * 1024) { PQclear(res); return NULL; }

    char desc[1024] = {0};
    char *dp  = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(dp, rem,
        "%d table(s) without a primary key (showing largest first):\n", n);
    dp += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(dp, rem, "  %s.%s (%s)\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2));
        dp += w; rem -= w;
    }

    if (rem > 0)
        strncat(dp,
            "Tables without a PK cannot use logical replication, "
            "are harder to UPDATE/DELETE safely, and cause issues with most ORMs.",
            rem - 1);
    PQclear(res);

    Priority p = (max_bytes > 100LL * 1024 * 1024) ? PRIORITY_MEDIUM : PRIORITY_LOW;

    return finding_new(p, GROUP_DATA_INTEGRITY,
        "Tables without a primary key",
        desc,
        "Add a primary key: ALTER TABLE <schema>.<table> ADD PRIMARY KEY (<col>); "
        "For append-only tables with no natural key, add a surrogate: "
        "ALTER TABLE ... ADD COLUMN id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY;");
}

static Finding *check_fk_without_index(PGconn *conn, const Options *opts)
{
    (void)opts;
    /*
     * Detect FK columns whose leading column has no matching index.
     * Unindexed FK columns cause full table scans when the parent row is
     * updated or deleted, and hold ShareLock on the child table during
     * the scan.
     * Note: checks only the first column of composite FKs.
     */
    PGresult *res = query(conn,
        "SELECT n.nspname, c.relname, a.attname, c2.relname AS ref_table"
        "  FROM pg_constraint k"
        "  JOIN pg_class c     ON c.oid   = k.conrelid"
        "  JOIN pg_namespace n ON n.oid   = c.relnamespace"
        "  JOIN pg_class c2    ON c2.oid  = k.confrelid"
        "  JOIN pg_attribute a ON a.attrelid = c.oid"
        "                     AND a.attnum   = k.conkey[1]"
        " WHERE k.contype = 'f'"
        "   AND n.nspname NOT IN ('pg_catalog','information_schema')"
        "   AND NOT EXISTS ("
        "       SELECT 1 FROM pg_index i"
        "        WHERE i.indrelid = k.conrelid"
        "          AND (i.indkey::int[])[0] = k.conkey[1])"
        " ORDER BY n.nspname, c.relname"
        " LIMIT 10");
    if (!res) return NULL;

    int n = PQntuples(res);

    char desc[1024] = {0};
    char *dp  = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(dp, rem,
        "%d foreign key(s) with no supporting index on the referencing column:\n", n);
    dp += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(dp, rem, "  %s.%s(%s) → %s\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2), PQgetvalue(res, i, 3));
        dp += w; rem -= w;
    }

    if (rem > 0)
        strncat(dp,
            "Each DELETE or UPDATE on the referenced table triggers a full scan "
            "of the unindexed child table to enforce referential integrity.",
            rem - 1);
    PQclear(res);

    return finding_new(PRIORITY_MEDIUM, GROUP_DATA_INTEGRITY,
        "Foreign keys with no supporting index",
        desc,
        "Create an index on each unindexed FK column: "
        "CREATE INDEX CONCURRENTLY ON <schema>.<table>(<fk_column>);");
}

static Finding *check_rls_coverage(PGconn *conn, const Options *opts)
{
    (void)opts;

    /* Only flag if there are non-superuser login roles (application users) */
    PGresult *role_res = query(conn,
        "SELECT count(*) FROM pg_roles"
        " WHERE rolcanlogin AND NOT rolsuper");
    if (!role_res) return NULL;
    int login_roles = atoi(PQgetvalue(role_res, 0, 0));
    PQclear(role_res);

    if (login_roles == 0) return NULL;

    /* Check if any policies exist at all */
    PGresult *pol_res = PQexec(conn,
        "SELECT count(*) FROM pg_policy");
    if (PQresultStatus(pol_res) != PGRES_TUPLES_OK) {
        PQclear(pol_res);
        return NULL;
    }
    int policies = atoi(PQgetvalue(pol_res, 0, 0));
    PQclear(pol_res);

    if (policies > 0) return NULL;

    char desc[512];
    snprintf(desc, sizeof(desc),
        "No Row-Level Security (RLS) policies are defined anywhere in this database, "
        "yet there are %d non-superuser login role(s). "
        "Without RLS, any authenticated user granted SELECT on a table sees all rows. "
        "For multi-tenant applications or strict data separation (SOC-2 CC6.3), "
        "RLS policies ensure users access only their own data.",
        login_roles);

    return finding_new(PRIORITY_INFO, GROUP_DATA_INTEGRITY,
        "No Row-Level Security policies defined",
        desc,
        "If data isolation between application users is required, enable RLS: "
        "ALTER TABLE <table> ENABLE ROW LEVEL SECURITY; "
        "CREATE POLICY <name> ON <table> USING (<condition>);");
}

/* ---------------------------------------------------------------- */

const Check checks_data_integrity[] = {
    { "data_checksums",     "data_checksums off — silent corruption undetectable", GROUP_DATA_INTEGRITY, check_data_checksums     },
    { "tables_without_pk",  "Tables without a primary key",                        GROUP_DATA_INTEGRITY, check_tables_without_pk  },
    { "fk_without_index",   "Foreign keys with no supporting index",               GROUP_DATA_INTEGRITY, check_fk_without_index   },
    { "rls_coverage",       "No Row-Level Security policies defined",               GROUP_DATA_INTEGRITY, check_rls_coverage       },
};

const int checks_data_integrity_count =
    sizeof(checks_data_integrity) / sizeof(checks_data_integrity[0]);
