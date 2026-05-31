#include <stdio.h>
#include <string.h>

#include "pgopps.h"

static void print_header(PGconn *conn, const Options *opts,
                         int auto_count, int restart_count, int manual_count,
                         int score, int total_findings)
{
    ServerInfo si;
    server_info_gather(conn, &si);

    const char *provider = cloud_provider_name(opts->cloud);

    printf("-- ================================================================\n");
    printf("-- pgopps Fix Script\n");
    printf("-- ================================================================\n");
    printf("-- Generated : %s\n", si.scan_ts);
    printf("-- Auditor   : %s@%s\n", si.client_user, si.client_host);
    printf("-- Platform  : %s\n", si.platform);
    printf("-- pgopps    : v%s\n", PGOPPS_VERSION);
    printf("-- ----------------------------------------------------------------\n");
    printf("-- Target    : %s\n", si.host);
    printf("-- Database  : %s\n", si.database);
    printf("-- PG User   : %s\n", si.pguser);
    printf("-- PostgreSQL: %s\n", si.pg_version);
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
