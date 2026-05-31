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

static Finding *check_ssl_enabled(PGconn *conn, const Options *opts)
{
    PGresult *res = query(conn, "SELECT current_setting('ssl')");
    if (!res) return NULL;

    char val[8] = {0};
    strncpy(val, PQgetvalue(res, 0, 0), sizeof(val) - 1);
    PQclear(res);

    if (strcmp(val, "on") == 0) return NULL;

    char rem[512];
    if (opts->cloud != CLOUD_NONE)
        snprintf(rem, sizeof(rem),
            "Enable SSL enforcement in your cloud provider's console. "
            "%s",
            cloud_param_hint(opts->cloud) ? cloud_param_hint(opts->cloud) : "");
    else
        snprintf(rem, sizeof(rem),
            "Set ssl = on in postgresql.conf and restart PostgreSQL. "
            "Provide ssl_cert_file and ssl_key_file. "
            "Then enforce SSL for clients in pg_hba.conf using hostssl entries.");

    Finding *f = finding_new(PRIORITY_HIGH, GROUP_ENCRYPTION,
        "SSL is disabled — all connections are unencrypted",
        "ssl = off means all data transmitted between clients and the server "
        "is in cleartext. Credentials, query results, and sensitive data are "
        "visible to anyone with network access between client and server.",
        rem);
    if (f) {
        f->fix_type = FIX_RESTART;
        strncpy(f->fix_sql,
            "-- Ensure ssl_cert_file and ssl_key_file are configured first.\n"
            "ALTER SYSTEM SET ssl = on;\n"
            "-- Restart PostgreSQL to apply.",
            sizeof(f->fix_sql) - 1);
    }
    return f;
}

static Finding *check_ssl_protocol(PGconn *conn, const Options *opts)
{
    (void)opts;
    /* ssl_min_protocol_version added in PG12; query returns NULL on older versions */
    PGresult *res = query(conn,
        "SELECT current_setting('ssl_min_protocol_version', true)");
    if (!res) return NULL;

    if (PQgetisnull(res, 0, 0)) { PQclear(res); return NULL; }

    char ver[16] = {0};
    strncpy(ver, PQgetvalue(res, 0, 0), sizeof(ver) - 1);
    PQclear(res);

    /* Also skip if SSL itself is off — covered by check_ssl_enabled */
    PGresult *ssl_res = query(conn, "SELECT current_setting('ssl')");
    if (!ssl_res) return NULL;
    char ssl_val[8] = {0};
    strncpy(ssl_val, PQgetvalue(ssl_res, 0, 0), sizeof(ssl_val) - 1);
    PQclear(ssl_res);
    if (strcmp(ssl_val, "off") == 0) return NULL;

    Priority p;
    if      (strcmp(ver, "TLSv1")   == 0) p = PRIORITY_CRITICAL;
    else if (strcmp(ver, "TLSv1.1") == 0) p = PRIORITY_HIGH;
    else    return NULL;   /* TLSv1.2 and above are acceptable */

    char title[128], desc[512];
    snprintf(title, sizeof(title),
        "ssl_min_protocol_version = %s is obsolete and vulnerable", ver);
    snprintf(desc, sizeof(desc),
        "ssl_min_protocol_version = %s allows clients to negotiate an obsolete "
        "TLS version with known cryptographic weaknesses. "
        "TLS 1.0 and 1.1 are deprecated by RFC 8996 and fail PCI-DSS / SOC-2 audits.",
        ver);

    Finding *f = finding_new(p, GROUP_ENCRYPTION, title, desc,
        "Set ssl_min_protocol_version = 'TLSv1.2' (minimum) or 'TLSv1.3' in "
        "postgresql.conf. Reload: SELECT pg_reload_conf();");
    if (f) {
        f->fix_type = FIX_RELOAD;
        strncpy(f->fix_sql,
            "ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.2';\n"
            "SELECT pg_reload_conf();",
            sizeof(f->fix_sql) - 1);
    }
    return f;
}

static Finding *check_password_encryption(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT current_setting('password_encryption')");
    if (!res) return NULL;

    char val[32] = {0};
    strncpy(val, PQgetvalue(res, 0, 0), sizeof(val) - 1);
    PQclear(res);

    if (strcmp(val, "scram-sha-256") == 0) return NULL;

    char title[128], desc[512];
    snprintf(title, sizeof(title),
        "password_encryption = %s (should be scram-sha-256)", val);

    if (strcmp(val, "md5") == 0) {
        snprintf(desc, sizeof(desc),
            "password_encryption = md5 stores new passwords as MD5 hashes. "
            "MD5 is cryptographically broken: rainbow tables and GPU cracking "
            "can recover passwords from leaked hashes. "
            "Existing md5-hashed passwords in pg_authid remain vulnerable until "
            "roles set a new password.");
    } else {
        snprintf(desc, sizeof(desc),
            "password_encryption = %s is not the recommended scram-sha-256. "
            "scram-sha-256 provides mutual authentication and is resistant "
            "to offline dictionary attacks.", val);
    }

    Finding *f = finding_new(PRIORITY_MEDIUM, GROUP_ENCRYPTION, title, desc,
        "Set password_encryption = 'scram-sha-256' in postgresql.conf, "
        "reload (SELECT pg_reload_conf()), then have all login roles reset "
        "their passwords: ALTER ROLE <name> PASSWORD '<new_password>';");
    if (f) {
        f->fix_type = FIX_RELOAD;
        strncpy(f->fix_sql,
            "ALTER SYSTEM SET password_encryption = 'scram-sha-256';\n"
            "SELECT pg_reload_conf();\n"
            "-- Existing roles must reset their passwords to upgrade from MD5:\n"
            "-- ALTER ROLE <name> PASSWORD '<new_password>';",
            sizeof(f->fix_sql) - 1);
    }
    return f;
}

static Finding *check_md5_passwords(PGconn *conn, const Options *opts)
{
    (void)opts;
    /* pg_authid requires superuser; silently skipped for non-superuser connections */
    PGresult *res = query(conn,
        "SELECT count(*),"
        "       string_agg(rolname, ', ' ORDER BY rolname)"
        "  FROM pg_authid"
        " WHERE rolcanlogin"
        "   AND rolpassword LIKE 'md5%'");
    if (!res) return NULL;

    int cnt = atoi(PQgetvalue(res, 0, 0));
    if (cnt == 0) { PQclear(res); return NULL; }

    char names[256] = {0};
    if (!PQgetisnull(res, 0, 1))
        strncpy(names, PQgetvalue(res, 0, 1), sizeof(names) - 1);
    PQclear(res);

    char title[128], desc[512];
    snprintf(title, sizeof(title),
        "%d login role(s) still use MD5-hashed passwords", cnt);
    snprintf(desc, sizeof(desc),
        "%d role(s) have passwords stored as MD5 hashes: %s. "
        "Even if password_encryption is set to scram-sha-256, existing password "
        "hashes remain MD5 until the role sets a new password. "
        "MD5 hashes are vulnerable to offline cracking if pg_authid is compromised.",
        cnt, names);

    return finding_new(PRIORITY_MEDIUM, GROUP_ENCRYPTION, title, desc,
        "Have each affected role reset its password: "
        "ALTER ROLE <name> PASSWORD '<new_password>'; "
        "The new hash will use the current password_encryption setting.");
}

static Finding *check_ssl_connections(PGconn *conn, const Options *opts)
{
    /* If SSL is globally off, check_ssl_enabled already covers this */
    PGresult *ssl_res = query(conn, "SELECT current_setting('ssl')");
    if (!ssl_res) return NULL;
    char ssl_val[8] = {0};
    strncpy(ssl_val, PQgetvalue(ssl_res, 0, 0), sizeof(ssl_val) - 1);
    PQclear(ssl_res);
    if (strcmp(ssl_val, "off") == 0) return NULL;

    /* Count non-SSL connections from remote clients (exclude unix socket) */
    PGresult *res = query(conn,
        "SELECT count(*)"
        "  FROM pg_stat_ssl s"
        "  JOIN pg_stat_activity a ON a.pid = s.pid"
        " WHERE s.ssl = false"
        "   AND s.pid != pg_backend_pid()"
        "   AND a.client_addr IS NOT NULL");
    if (!res) return NULL;

    int cnt = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);

    if (cnt == 0) return NULL;

    char title[128], desc[512], rem[512];
    snprintf(title, sizeof(title),
        "%d active remote connection(s) not using SSL", cnt);
    snprintf(desc, sizeof(desc),
        "%d remote client connection(s) are currently connected without SSL "
        "despite SSL being available on this server. "
        "These connections transmit queries and results in cleartext.",
        cnt);

    if (opts->cloud != CLOUD_NONE)
        snprintf(rem, sizeof(rem),
            "Enforce SSL-only connections in your cloud provider's network settings "
            "or set require_ssl = on where available. %s",
            cloud_param_hint(opts->cloud) ? cloud_param_hint(opts->cloud) : "");
    else
        snprintf(rem, sizeof(rem),
            "Replace 'host' entries in pg_hba.conf with 'hostssl' to require SSL. "
            "Reload: SELECT pg_reload_conf();");

    return finding_new(PRIORITY_MEDIUM, GROUP_ENCRYPTION, title, desc, rem);
}

/* ---------------------------------------------------------------- */

const Check checks_encryption[] = {
    { "ssl_enabled",          "SSL disabled — all connections unencrypted",                GROUP_ENCRYPTION, check_ssl_enabled          },
    { "ssl_protocol",         "ssl_min_protocol_version allows obsolete TLS versions",     GROUP_ENCRYPTION, check_ssl_protocol         },
    { "password_encryption",  "password_encryption is not scram-sha-256",                 GROUP_ENCRYPTION, check_password_encryption  },
    { "md5_passwords",        "Login roles with MD5-hashed passwords in pg_authid",        GROUP_ENCRYPTION, check_md5_passwords        },
    { "ssl_connections",      "Remote connections established without SSL",                GROUP_ENCRYPTION, check_ssl_connections      },
};

const int checks_encryption_count =
    sizeof(checks_encryption) / sizeof(checks_encryption[0]);
