#ifndef PGOPPS_H
#define PGOPPS_H

#include <libpq-fe.h>

#define PGOPPS_VERSION "0.2.0"
#define MAX_FINDINGS    256

/* ----------------------------------------------------------------
 * Priority levels — findings are sorted by this value ascending
 * ---------------------------------------------------------------- */
typedef enum {
    PRIORITY_CRITICAL = 1,
    PRIORITY_HIGH     = 2,
    PRIORITY_MEDIUM   = 3,
    PRIORITY_LOW      = 4,
    PRIORITY_INFO     = 5,
} Priority;

/* ----------------------------------------------------------------
 * Logical groups shown as sections in the report
 * ---------------------------------------------------------------- */
typedef enum {
    GROUP_PERFORMANCE       = 0,
    GROUP_SECURITY          = 1,
    GROUP_ENCRYPTION        = 2,
    GROUP_AUDIT_AND_LOGGING = 3,
    GROUP_DATA_INTEGRITY    = 4,
    GROUP_MAINTENANCE       = 5,
    GROUP_CONFIGURATION     = 6,
    GROUP_REPLICATION_HA    = 7,
    GROUP_BACKUP_RECOVERY   = 8,
    GROUP__COUNT,               /* sentinel — keep last */
} CheckGroup;

/* ----------------------------------------------------------------
 * Cloud provider detected at connection time
 * ---------------------------------------------------------------- */
typedef enum {
    CLOUD_NONE,       /* self-hosted */
    CLOUD_AWS_RDS,    /* AWS RDS or Aurora */
    CLOUD_AZURE,      /* Azure Database for PostgreSQL */
    CLOUD_GCP,        /* Google Cloud SQL */
    CLOUD_SUPABASE,
    CLOUD_NEON,
    CLOUD_AIVEN,
    CLOUD_UNKNOWN,    /* cloud-like but unrecognised */
} CloudProvider;

/* ----------------------------------------------------------------
 * Fix type — how to apply the fix for a finding
 * ---------------------------------------------------------------- */
typedef enum {
    FIX_NONE    = 0,  /* manual action required */
    FIX_RELOAD,       /* ALTER SYSTEM SET / GRANT — pg_reload_conf() sufficient */
    FIX_RESTART,      /* ALTER SYSTEM SET — PostgreSQL restart required */
} FixType;

/* ----------------------------------------------------------------
 * A single finding returned by a check function
 * ---------------------------------------------------------------- */
typedef struct Finding {
    char            title[256];
    char            description[1024];
    char            remediation[512];
    char            fix_sql[1024];   /* ready-to-run SQL; empty if manual-only */
    Priority        priority;
    CheckGroup      group;
    int             id;          /* 1-based check index within group — forms the stable finding ID */
    FixType         fix_type;
    struct Finding *next;
} Finding;

/* ----------------------------------------------------------------
 * Output formats
 * ---------------------------------------------------------------- */
typedef enum {
    OUTPUT_TEXT,
    OUTPUT_JSON,
    OUTPUT_MARKDOWN,
    OUTPUT_HTML,
} OutputFormat;

/* ----------------------------------------------------------------
 * Runtime options parsed from CLI — passed to every check function
 * ---------------------------------------------------------------- */
typedef struct {
    const char   *connstr;
    OutputFormat  format;
    int           min_priority;   /* filter: only show >= this priority */
    int           verbose;
    int           fix_script;     /* --fix-script: emit SQL fix script instead of report */
    int           exit_code;      /* --exit-code: exit 1 if CRITICAL or HIGH findings exist */
    CloudProvider cloud;
} Options;

/* ----------------------------------------------------------------
 * Check descriptor — each check module registers one of these
 * ---------------------------------------------------------------- */
typedef struct {
    const char  *name;
    const char  *description;
    CheckGroup   group;
    /* Returns a singly-linked list of Finding*; NULL means nothing found */
    Finding    *(*run)(PGconn *conn, const Options *opts);
} Check;

/* ----------------------------------------------------------------
 * Check registry (src/checks/registry.c)
 * ---------------------------------------------------------------- */
void    registry_init(void);
void    registry_run_all(PGconn *conn, const Options *opts,
                         Finding **out, int *count);

/* ----------------------------------------------------------------
 * Report (src/report.c)
 * ---------------------------------------------------------------- */
void    report_print(Finding **findings, int count, const Options *opts);

/* ----------------------------------------------------------------
 * Fix script (src/fixscript.c)
 * ---------------------------------------------------------------- */
void    fixscript_print(Finding **findings, int count, int score,
                        const Options *opts, PGconn *conn);

/* ----------------------------------------------------------------
 * HTML report (src/htmlreport.c)
 * ---------------------------------------------------------------- */
void    htmlreport_print(Finding **findings, int count, int score,
                         const Options *opts, PGconn *conn);

/* ----------------------------------------------------------------
 * Connection helpers (src/connection.c)
 * ---------------------------------------------------------------- */
PGconn *db_connect(const char *connstr);
void    db_disconnect(PGconn *conn);
int     db_server_version(PGconn *conn);

/* ----------------------------------------------------------------
 * Cloud detection (src/cloud.c)
 * ---------------------------------------------------------------- */
CloudProvider  db_detect_cloud(PGconn *conn);
const char    *cloud_provider_name(CloudProvider cp);
const char    *cloud_param_hint(CloudProvider cp);

/* ----------------------------------------------------------------
 * Server info summary (src/info.c)
 * ---------------------------------------------------------------- */
void    db_print_info(PGconn *conn, const Options *opts);

/* ----------------------------------------------------------------
 * Opps Score (src/score.c)
 * ---------------------------------------------------------------- */
int     score_calculate(Finding **findings, int count);
void    score_print(int score, int total_findings, const Options *opts);

/* ----------------------------------------------------------------
 * Utility helpers (src/utils.c)
 * ---------------------------------------------------------------- */
Finding    *finding_new(Priority priority, CheckGroup group,
                        const char *title, const char *description,
                        const char *remediation);
void        finding_free_list(Finding *head);
const char *priority_name(Priority p);
const char *group_name(CheckGroup g);
const char *group_abbrev(CheckGroup g);

#endif /* PGOPPS_H */
