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

static Finding *check_superuser_count(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT count(*),"
        "       string_agg(rolname, ', ' ORDER BY rolname)"
        "  FROM pg_roles"
        " WHERE rolsuper AND rolcanlogin");
    if (!res) return NULL;

    int  cnt   = atoi(PQgetvalue(res, 0, 0));
    char names[256] = {0};
    if (!PQgetisnull(res, 0, 1))
        strncpy(names, PQgetvalue(res, 0, 1), sizeof(names) - 1);
    PQclear(res);

    if (cnt <= 1) return NULL;

    char title[128], desc[512];
    snprintf(title, sizeof(title),
        "%d superuser accounts with LOGIN privilege", cnt);
    snprintf(desc, sizeof(desc),
        "%d roles have both SUPERUSER and LOGIN: %s. "
        "Each additional superuser account is a potential full-compromise vector. "
        "Superusers bypass all access controls including Row-Level Security and "
        "can read, modify, or delete any data.",
        cnt, names);

    return finding_new(PRIORITY_MEDIUM, GROUP_SECURITY, title, desc,
        "Reduce to one operational superuser. Replace superuser access with "
        "least-privilege roles (pg_read_all_data, pg_monitor, etc.) for "
        "specific use cases.");
}

static Finding *check_public_schema_create(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT has_schema_privilege('public', 'public', 'CREATE')");
    if (!res) return NULL;

    char val[8] = {0};
    strncpy(val, PQgetvalue(res, 0, 0), sizeof(val) - 1);
    PQclear(res);

    if (strcmp(val, "t") != 0) return NULL;

    /* Determine PG version — PG15+ revoked this by default */
    int ver = PQserverVersion(conn);
    char desc[512];
    snprintf(desc, sizeof(desc),
        "The PUBLIC role has CREATE privilege on the public schema%s. "
        "Any authenticated user can create tables, functions, or triggers there, "
        "enabling privilege escalation attacks (e.g. trojan functions that execute "
        "as a higher-privileged caller).",
        (ver < 150000) ? " (pre-PG15 default, but still a risk)" : "");

    return finding_new(PRIORITY_MEDIUM, GROUP_SECURITY,
        "PUBLIC can CREATE objects in the public schema",
        desc,
        "Revoke the privilege: REVOKE CREATE ON SCHEMA public FROM PUBLIC; "
        "Grant explicit CREATE to roles that legitimately need it.");
}

static Finding *check_hba_trust(PGconn *conn, const Options *opts)
{
    /* Cloud providers manage pg_hba internally; entries are not user-editable */
    if (opts->cloud != CLOUD_NONE)
        return NULL;

    /* pg_hba_file_rules accessible to all in PG15+; superuser-only before that */
    PGresult *res = query(conn,
        "SELECT type, database::text, user_name::text, auth_method"
        "  FROM pg_hba_file_rules"
        " WHERE auth_method IN ('trust', 'password')"
        " ORDER BY line_number");
    if (!res) return NULL;   /* permission denied or not available — skip */

    int n = PQntuples(res);
    if (n == 0) { PQclear(res); return NULL; }

    /* Severity: trust on network type is worse than on local socket */
    int has_network_trust = 0;
    for (int i = 0; i < n; i++) {
        const char *type   = PQgetvalue(res, i, 0);
        const char *method = PQgetvalue(res, i, 3);
        if (strcmp(method, "trust") == 0 &&
            (strcmp(type, "host")     == 0 ||
             strcmp(type, "hostssl")  == 0 ||
             strcmp(type, "hostnossl")== 0))
            has_network_trust = 1;
    }

    char desc[1024] = {0};
    char *dp  = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(dp, rem,
        "%d pg_hba.conf entry/entries use 'trust' or plaintext 'password' "
        "authentication:\n", n);
    dp += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(dp, rem, "  type=%-10s db=%-14s user=%-14s method=%s\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2), PQgetvalue(res, i, 3));
        dp += w; rem -= w;
    }
    PQclear(res);

    Priority p = has_network_trust ? PRIORITY_CRITICAL : PRIORITY_HIGH;

    return finding_new(p, GROUP_SECURITY,
        has_network_trust
            ? "pg_hba.conf allows network connections without authentication (trust)"
            : "pg_hba.conf uses weak or no-password authentication",
        desc,
        "Replace 'trust' with 'scram-sha-256' in pg_hba.conf. "
        "Replace 'password' (plaintext) with 'scram-sha-256'. "
        "Reload: SELECT pg_reload_conf(); — no restart needed.");
}

static Finding *check_no_password_expiry(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT count(*),"
        "       string_agg(rolname, ', ' ORDER BY rolname)"
        "  FROM pg_roles"
        " WHERE rolcanlogin"
        "   AND NOT rolsuper"
        "   AND rolvaliduntil IS NULL");
    if (!res) return NULL;

    int cnt = atoi(PQgetvalue(res, 0, 0));
    if (cnt == 0) { PQclear(res); return NULL; }

    char names[256] = {0};
    if (!PQgetisnull(res, 0, 1))
        strncpy(names, PQgetvalue(res, 0, 1), sizeof(names) - 1);
    PQclear(res);

    char title[128], desc[512];
    snprintf(title, sizeof(title),
        "%d login role(s) with no password expiry", cnt);
    snprintf(desc, sizeof(desc),
        "%d non-superuser login role(s) have no password expiry date "
        "(rolvaliduntil IS NULL): %s. "
        "Permanent credentials increase the window of exposure if a password "
        "is ever leaked or compromised.",
        cnt, names);

    return finding_new(PRIORITY_LOW, GROUP_SECURITY, title, desc,
        "Set a password rotation policy: "
        "ALTER ROLE <name> VALID UNTIL '<date>'; "
        "Or enforce rotation via an external PAM/LDAP identity provider.");
}

static Finding *check_excessive_privileges(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT rolname,"
        "       CASE WHEN rolcreatedb  THEN 'CREATEDB '  ELSE '' END ||"
        "       CASE WHEN rolcreaterole THEN 'CREATEROLE ' ELSE '' END ||"
        "       CASE WHEN rolbypassrls  THEN 'BYPASSRLS'  ELSE '' END AS privs"
        "  FROM pg_roles"
        " WHERE rolcanlogin AND NOT rolsuper"
        "   AND (rolcreatedb OR rolcreaterole OR rolbypassrls)"
        " ORDER BY rolname");
    if (!res) return NULL;

    int n = PQntuples(res);
    if (n == 0) { PQclear(res); return NULL; }

    char desc[1024] = {0};
    char *dp  = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(dp, rem,
        "%d non-superuser login role(s) hold elevated privileges:\n", n);
    dp += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(dp, rem, "  %-32s %s\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1));
        dp += w; rem -= w;
    }

    if (rem > 0)
        strncat(dp,
            "BYPASSRLS allows the role to bypass all Row-Level Security policies.",
            rem - 1);
    PQclear(res);

    return finding_new(PRIORITY_MEDIUM, GROUP_SECURITY,
        "Roles with elevated privileges (CREATEDB / CREATEROLE / BYPASSRLS)",
        desc,
        "Apply principle of least privilege. Revoke unneeded attributes: "
        "ALTER ROLE <name> NOCREATEDB NOCREATEROLE; "
        "BYPASSRLS should only be held by application superuser equivalents.");
}

/* ---------------------------------------------------------------- */

const Check checks_security[] = {
    { "superuser_count",        "Multiple superuser accounts with LOGIN",              GROUP_SECURITY, check_superuser_count        },
    { "public_schema_create",   "PUBLIC role has CREATE on the public schema",         GROUP_SECURITY, check_public_schema_create   },
    { "hba_trust",              "pg_hba.conf trust or plaintext-password auth",        GROUP_SECURITY, check_hba_trust              },
    { "no_password_expiry",     "Login roles with no password expiration date",        GROUP_SECURITY, check_no_password_expiry     },
    { "excessive_privileges",   "Non-superuser roles with CREATEDB/CREATEROLE/BYPASSRLS", GROUP_SECURITY, check_excessive_privileges},
};

const int checks_security_count =
    sizeof(checks_security) / sizeof(checks_security[0]);
