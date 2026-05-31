#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/utsname.h>

#include "pgopps.h"

static void print_header(PGconn *conn, const Options *opts,
                         int auto_count, int restart_count, int manual_count,
                         int score, int total_findings)
{
    /* Scan timestamp */
    char scan_ts[32];
    time_t now = time(NULL);
    strftime(scan_ts, sizeof(scan_ts), "%Y-%m-%d %H:%M:%S UTC", gmtime(&now));

    /* Client identity */
    char client_host[128] = "unknown";
    gethostname(client_host, sizeof(client_host) - 1);
    char client_user[64] = "unknown";
    struct passwd *pw = getpwuid(getuid());
    if (pw) strncpy(client_user, pw->pw_name, sizeof(client_user) - 1);
    else if (getenv("USER")) strncpy(client_user, getenv("USER"), sizeof(client_user) - 1);

    /* Platform */
    char platform[256] = "unknown";
    struct utsname uts;
    if (uname(&uts) == 0)
        snprintf(platform, sizeof(platform), "%s %s %s",
                 uts.sysname, uts.release, uts.machine);

    /* Server info */
    char db[128] = "", host[160] = "", pguser[64] = "", ver[16] = "";
    PGresult *res = PQexec(conn,
        "SELECT current_database(), current_user,"
        "  COALESCE(host(inet_server_addr())||':'||inet_server_port()::text,'local'),"
        "  current_setting('server_version')");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        strncpy(db,     PQgetvalue(res, 0, 0), sizeof(db)     - 1);
        strncpy(pguser, PQgetvalue(res, 0, 1), sizeof(pguser) - 1);
        strncpy(host,   PQgetvalue(res, 0, 2), sizeof(host)   - 1);
        strncpy(ver,    PQgetvalue(res, 0, 3), sizeof(ver)     - 1);
    }
    PQclear(res);

    const char *provider = cloud_provider_name(opts->cloud);

    printf("-- ================================================================\n");
    printf("-- pgopps Fix Script\n");
    printf("-- ================================================================\n");
    printf("-- Generated : %s\n", scan_ts);
    printf("-- Auditor   : %s@%s\n", client_user, client_host);
    printf("-- Platform  : %s\n", platform);
    printf("-- pgopps    : v%s\n", PGOPPS_VERSION);
    printf("-- ----------------------------------------------------------------\n");
    printf("-- Target    : %s\n", host);
    printf("-- Database  : %s\n", db);
    printf("-- PG User   : %s\n", pguser);
    printf("-- PostgreSQL: %s\n", ver);
    if (provider)
        printf("-- Provider  : %s\n", provider);
    printf("-- ----------------------------------------------------------------\n");
    printf("-- Opps Score: %d / 100  (%d finding%s across all checks)\n",
           score, total_findings, total_findings == 1 ? "" : "s");
    printf("-- ----------------------------------------------------------------\n");
    printf("-- Summary   : %d auto-fixable (reload)  |  %d require restart"
           "  |  %d manual\n",
           auto_count, restart_count, manual_count);
    printf("-- ================================================================\n");

    if (opts->cloud != CLOUD_NONE) {
        printf("--\n");
        printf("-- NOTE: Connected to a managed cloud instance (%s).\n", provider);
        printf("-- ALTER SYSTEM SET commands do not apply directly.\n");
        printf("-- Apply settings via your provider's parameter group or config UI.\n");
    }

    printf("--\n");
    printf("-- REVIEW ALL COMMANDS BEFORE RUNNING.\n");
    printf("-- Run as a PostgreSQL superuser or equivalent.\n");
    printf("-- Test in a non-production environment first.\n");
    printf("-- ================================================================\n\n");

    printf("\\set ON_ERROR_STOP on\n\n");
}

void fixscript_print(Finding **findings, int count, int score,
                     const Options *opts, PGconn *conn)
{
    /* Count findings by fix type */
    int auto_count    = 0;
    int restart_count = 0;
    int manual_count  = 0;
    int total         = 0;

    for (int i = 0; i < count; i++) {
        for (Finding *f = findings[i]; f; f = f->next) {
            total++;
            switch (f->fix_type) {
            case FIX_RELOAD:  auto_count++;    break;
            case FIX_RESTART: restart_count++; break;
            default:          manual_count++;  break;
            }
        }
    }

    print_header(conn, opts, auto_count, restart_count, manual_count,
                 score, total);

    /* ---- Section 1: auto-fixable (reload) -------------------------------- */
    if (auto_count > 0) {
        printf("-- ================================================================\n");
        printf("-- AUTOMATIC — apply with pg_reload_conf() (%d finding%s)\n",
               auto_count, auto_count == 1 ? "" : "s");
        printf("-- ================================================================\n\n");

        for (int i = 0; i < count; i++) {
            for (Finding *f = findings[i]; f; f = f->next) {
                if (f->fix_type != FIX_RELOAD) continue;
                printf("-- [%s-%03d] %s — %s\n",
                       group_abbrev(f->group), f->id,
                       priority_name(f->priority), f->title);
                printf("%s\n\n", f->fix_sql);
            }
        }
    }

    /* ---- Section 2: restart-required ------------------------------------- */
    if (restart_count > 0) {
        printf("-- ================================================================\n");
        printf("-- RESTART REQUIRED — apply, then restart PostgreSQL (%d finding%s)\n",
               restart_count, restart_count == 1 ? "" : "s");
        printf("-- ================================================================\n\n");

        for (int i = 0; i < count; i++) {
            for (Finding *f = findings[i]; f; f = f->next) {
                if (f->fix_type != FIX_RESTART) continue;
                printf("-- [%s-%03d] %s — %s\n",
                       group_abbrev(f->group), f->id,
                       priority_name(f->priority), f->title);
                printf("%s\n\n", f->fix_sql);
            }
        }
    }

    /* ---- Section 3: manual ----------------------------------------------- */
    if (manual_count > 0) {
        printf("-- ================================================================\n");
        printf("-- MANUAL ACTION REQUIRED (%d finding%s)\n",
               manual_count, manual_count == 1 ? "" : "s");
        printf("-- These findings cannot be fixed automatically.\n");
        printf("-- ================================================================\n\n");

        for (int i = 0; i < count; i++) {
            for (Finding *f = findings[i]; f; f = f->next) {
                if (f->fix_type != FIX_NONE) continue;
                printf("-- [%s-%03d] %s — %s\n",
                       group_abbrev(f->group), f->id,
                       priority_name(f->priority), f->title);
                /* Print remediation as commented-out guidance */
                printf("--   Remediation: ");
                const char *p = f->remediation;
                while (*p) {
                    if (*p == '\n')
                        printf("\n--   ");
                    else
                        putchar(*p);
                    p++;
                }
                printf("\n\n");
            }
        }
    }

    printf("-- ================================================================\n");
    printf("-- End of pgopps fix script\n");
    printf("-- ================================================================\n");
}
