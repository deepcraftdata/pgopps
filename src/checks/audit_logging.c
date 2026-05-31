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

static Finding *check_log_connections(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT current_setting('log_connections'),"
        "       current_setting('log_disconnections')");
    if (!res) return NULL;

    char log_conn[8] = {0}, log_disc[8] = {0};
    strncpy(log_conn, PQgetvalue(res, 0, 0), sizeof(log_conn) - 1);
    strncpy(log_disc, PQgetvalue(res, 0, 1), sizeof(log_disc) - 1);
    PQclear(res);

    int conn_off = (strcmp(log_conn, "off") == 0);
    int disc_off = (strcmp(log_disc, "off") == 0);

    if (!conn_off && !disc_off) return NULL;

    char title[128], desc[512];
    if (conn_off && disc_off) {
        snprintf(title, sizeof(title),
            "log_connections and log_disconnections are both off");
        snprintf(desc, sizeof(desc),
            "Neither login events nor session terminations are logged. "
            "Without this information it is impossible to audit who connected, "
            "when, and from where — a baseline requirement for SOC-2 CC7.2 "
            "(monitoring of system activity).");
    } else {
        snprintf(title, sizeof(title),
            "log_%s is off — incomplete session audit trail",
            conn_off ? "connections" : "disconnections");
        snprintf(desc, sizeof(desc),
            "log_%s = off means %s are not recorded in the log. "
            "A complete session audit trail requires both settings to be on.",
            conn_off ? "connections" : "disconnections",
            conn_off ? "login events" : "session terminations");
    }

    return finding_new(PRIORITY_MEDIUM, GROUP_AUDIT_AND_LOGGING, title, desc,
        "Set log_connections = on and log_disconnections = on in postgresql.conf. "
        "Reload: SELECT pg_reload_conf();");
}

static Finding *check_slow_query_log(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT current_setting('log_min_duration_statement')::int");
    if (!res) return NULL;

    int ms = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);

    if (ms >= 0) return NULL;   /* -1 means disabled */

    return finding_new(PRIORITY_MEDIUM, GROUP_AUDIT_AND_LOGGING,
        "Slow query logging is disabled (log_min_duration_statement = -1)",
        "log_min_duration_statement = -1 means no queries are ever logged by duration. "
        "Slow queries are invisible: there is no way to identify performance regressions, "
        "runaway queries, or anomalous access patterns after the fact.",
        "Set log_min_duration_statement to a reasonable threshold in postgresql.conf "
        "(e.g. 1000 for 1 second). Reload: SELECT pg_reload_conf();");
}

static Finding *check_log_statement(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT current_setting('log_statement')");
    if (!res) return NULL;

    char val[16] = {0};
    strncpy(val, PQgetvalue(res, 0, 0), sizeof(val) - 1);
    PQclear(res);

    /* 'none' means no DDL/DML is ever logged */
    if (strcmp(val, "none") != 0) return NULL;

    return finding_new(PRIORITY_MEDIUM, GROUP_AUDIT_AND_LOGGING,
        "log_statement = none — DDL changes are not logged",
        "log_statement = none means schema changes (CREATE, ALTER, DROP), "
        "permission grants, and other DDL statements leave no trace in the logs. "
        "Auditing 'who changed what schema' becomes impossible after the fact, "
        "violating SOC-2 CC8.1 (change management logging).",
        "Set log_statement = 'ddl' to capture all schema changes. "
        "Use 'mod' to also capture INSERT/UPDATE/DELETE. "
        "Reload: SELECT pg_reload_conf();");
}

static Finding *check_log_line_prefix(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT current_setting('log_line_prefix')");
    if (!res) return NULL;

    char prefix[256] = {0};
    strncpy(prefix, PQgetvalue(res, 0, 0), sizeof(prefix) - 1);
    PQclear(res);

    /* Required tokens for a meaningful audit log entry */
    int has_user  = (strstr(prefix, "%u") != NULL);
    int has_db    = (strstr(prefix, "%d") != NULL);
    int has_host  = (strstr(prefix, "%r") != NULL || strstr(prefix, "%h") != NULL);
    int has_time  = (strstr(prefix, "%t") != NULL || strstr(prefix, "%m") != NULL);

    if (has_user && has_db && has_host && has_time) return NULL;

    char missing[128] = {0};
    char *mp = missing;
    if (!has_time)  mp += snprintf(mp, sizeof(missing) - (mp - missing), "%%m (timestamp) ");
    if (!has_user)  mp += snprintf(mp, sizeof(missing) - (mp - missing), "%%u (user) ");
    if (!has_db)    mp += snprintf(mp, sizeof(missing) - (mp - missing), "%%d (database) ");
    if (!has_host)  mp += snprintf(mp, sizeof(missing) - (mp - missing), "%%r (remote host) ");
    (void)mp;

    char desc[1024];
    snprintf(desc, sizeof(desc),
        "Current log_line_prefix = '%s'. "
        "Missing tokens: %s"
        "Without these, log entries cannot be correlated to specific users, "
        "databases, or client hosts — a baseline audit trail requirement.",
        prefix, missing);

    return finding_new(PRIORITY_MEDIUM, GROUP_AUDIT_AND_LOGGING,
        "log_line_prefix missing required audit fields", desc,
        "Set log_line_prefix = '%%m [%%p] %%u@%%d %%r ' in postgresql.conf. "
        "Reload: SELECT pg_reload_conf().");
}

static Finding *check_logging_collector(PGconn *conn, const Options *opts)
{
    /* Cloud providers capture stderr via their own log pipeline — skip */
    if (opts->cloud != CLOUD_NONE) return NULL;

    PGresult *res = query(conn,
        "SELECT current_setting('logging_collector')");
    if (!res) return NULL;

    char val[8] = {0};
    strncpy(val, PQgetvalue(res, 0, 0), sizeof(val) - 1);
    PQclear(res);

    if (strcmp(val, "on") == 0) return NULL;

    return finding_new(PRIORITY_LOW, GROUP_AUDIT_AND_LOGGING,
        "logging_collector is off — logs written to stderr only",
        "logging_collector = off means PostgreSQL writes log output to stderr. "
        "In non-containerised deployments this output may not be captured or "
        "rotated, risking log loss. Without persistent log files, audit "
        "reconstruction after an incident is not possible.",
        "Set logging_collector = on, log_directory, and log_filename in "
        "postgresql.conf. Requires a PostgreSQL restart.");
}

static Finding *check_pgaudit(PGconn *conn, const Options *opts)
{
    PGresult *res = query(conn,
        "SELECT extversion FROM pg_extension WHERE extname = 'pgaudit'");
    if (!res) {
        /* query() returns NULL when 0 rows — extension not installed */
        char rem[512];
        if (opts->cloud == CLOUD_AWS_RDS)
            snprintf(rem, sizeof(rem),
                "Add pgaudit to shared_preload_libraries via RDS Parameter Group, "
                "reboot, then: CREATE EXTENSION pgaudit;");
        else if (opts->cloud == CLOUD_AZURE)
            snprintf(rem, sizeof(rem),
                "Enable pgaudit via Azure Portal → Server parameters "
                "(shared_preload_libraries), restart, then: CREATE EXTENSION pgaudit;");
        else
            snprintf(rem, sizeof(rem),
                "Install the pgaudit package (e.g. postgresql-17-pgaudit on Debian), "
                "add 'pgaudit' to shared_preload_libraries in postgresql.conf, "
                "restart PostgreSQL, then: CREATE EXTENSION pgaudit;");

        return finding_new(PRIORITY_MEDIUM, GROUP_AUDIT_AND_LOGGING,
            "pgaudit extension is not installed",
            "pgaudit provides object-level and statement-level audit logging beyond "
            "what standard PostgreSQL log settings offer. It is the standard mechanism "
            "for achieving SOC-2 CC7.2 and PCI-DSS audit log requirements in PostgreSQL. "
            "Without it, there is no record of which objects were READ (SELECT), "
            "only writes if log_statement is set.",
            rem);
    }

    PQclear(res);   /* extension is installed — no finding */
    return NULL;
}

/* ---------------------------------------------------------------- */

const Check checks_audit_logging[] = {
    { "log_connections",    "log_connections/disconnections off — no session audit trail",  GROUP_AUDIT_AND_LOGGING, check_log_connections    },
    { "slow_query_log",     "log_min_duration_statement disabled — slow queries invisible", GROUP_AUDIT_AND_LOGGING, check_slow_query_log     },
    { "log_statement",      "log_statement = none — DDL changes not logged",               GROUP_AUDIT_AND_LOGGING, check_log_statement      },
    { "log_line_prefix",    "log_line_prefix missing user/db/host audit fields",           GROUP_AUDIT_AND_LOGGING, check_log_line_prefix    },
    { "logging_collector",  "logging_collector off — logs not persisted to files",         GROUP_AUDIT_AND_LOGGING, check_logging_collector  },
    { "pgaudit",            "pgaudit extension not installed",                             GROUP_AUDIT_AND_LOGGING, check_pgaudit            },
};

const int checks_audit_logging_count =
    sizeof(checks_audit_logging) / sizeof(checks_audit_logging[0]);
