#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/utsname.h>

#include "pgopps.h"

#define COL_RESET  "\033[0m"
#define COL_BOLD   "\033[1m"
#define COL_GREEN  "\033[32m"
#define COL_DIM    "\033[2m"

/*
 * Parse PQserverVersion() integer (e.g. 160003) into "16.3"
 */
static void format_pg_version(int v, char *buf, size_t len)
{
    if (v >= 100000)
        snprintf(buf, len, "%d.%d", v / 10000, v % 10000);
    else
        snprintf(buf, len, "%d.%d.%d", v / 10000, (v % 10000) / 100, v % 100);
}

/*
 * Strip trailing whitespace from PQgetvalue results (char fields are
 * space-padded in some PG output formats).
 */
static void rtrim(char *s)
{
    int i = (int)strlen(s) - 1;
    while (i >= 0 && (s[i] == ' ' || s[i] == '\n')) s[i--] = '\0';
}

void server_info_gather(PGconn *conn, ServerInfo *out)
{
    memset(out, 0, sizeof(*out));

    time_t now = time(NULL);
    strftime(out->scan_ts, sizeof(out->scan_ts),
             "%Y-%m-%d %H:%M:%S UTC", gmtime(&now));

    gethostname(out->client_host, sizeof(out->client_host) - 1);

    struct passwd *pw = getpwuid(getuid());
    if (pw)
        strncpy(out->client_user, pw->pw_name, sizeof(out->client_user) - 1);
    else if (getenv("USER"))
        strncpy(out->client_user, getenv("USER"), sizeof(out->client_user) - 1);
    else
        strncpy(out->client_user, "unknown", sizeof(out->client_user) - 1);

    struct utsname uts;
    if (uname(&uts) == 0)
        snprintf(out->platform, sizeof(out->platform), "%s %s %s",
                 uts.sysname, uts.release, uts.machine);
    else
        strncpy(out->platform, "unknown", sizeof(out->platform) - 1);

    PGresult *res = PQexec(conn,
        "SELECT current_database(), current_user,"
        "  COALESCE(host(inet_server_addr())||':'||inet_server_port()::text,'local'),"
        "  current_setting('server_version')");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        strncpy(out->database,   PQgetvalue(res,0,0), sizeof(out->database)   - 1);
        strncpy(out->pguser,     PQgetvalue(res,0,1), sizeof(out->pguser)     - 1);
        strncpy(out->host,       PQgetvalue(res,0,2), sizeof(out->host)       - 1);
        strncpy(out->pg_version, PQgetvalue(res,0,3), sizeof(out->pg_version) - 1);
    }
    PQclear(res);
}

void db_print_info(PGconn *conn, const Options *opts)
{
    const char *sql =
        "SELECT"
        "  COALESCE(host(inet_server_addr()), 'local')      AS host,"
        "  COALESCE(inet_server_port()::text, '')           AS port,"
        "  current_database()                               AS database,"
        "  current_user                                     AS usr,"
        "  pg_postmaster_start_time()::timestamptz(0)       AS started,"
        "  to_char(now() - pg_postmaster_start_time(),"
        "          'DD\"d\" HH24\"h\" MI\"m\"')             AS uptime,"
        "  (SELECT count(*)::int"
        "     FROM pg_database WHERE datallowconn)          AS db_count,"
        "  pg_size_pretty("
        "    (SELECT sum(pg_database_size(datname))"
        "       FROM pg_database WHERE datallowconn))       AS total_size,"
        "  (SELECT count(*)::int FROM pg_stat_activity)     AS conn_active,"
        "  (SELECT setting::int FROM pg_settings"
        "    WHERE name = 'max_connections')                AS conn_max,"
        "  (SELECT setting FROM pg_settings"
        "    WHERE name = 'server_version_num')             AS ver_num";

    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Info query failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return;
    }

    /* --- parse result fields ------------------------------------------ */
    char host[128], port[16], database[128], user[128];
    char started[64], uptime[32], total_size[32];
    char ver_buf[16];
    int  db_count, conn_active, conn_max;

    strncpy(host,       PQgetvalue(res, 0,  0), sizeof(host)       - 1);
    strncpy(port,       PQgetvalue(res, 0,  1), sizeof(port)       - 1);
    strncpy(database,   PQgetvalue(res, 0,  2), sizeof(database)   - 1);
    strncpy(user,       PQgetvalue(res, 0,  3), sizeof(user)       - 1);
    strncpy(started,    PQgetvalue(res, 0,  4), sizeof(started)    - 1);
    strncpy(uptime,     PQgetvalue(res, 0,  5), sizeof(uptime)     - 1);
    db_count    = atoi(PQgetvalue(res, 0,  6));
    strncpy(total_size, PQgetvalue(res, 0,  7), sizeof(total_size) - 1);
    conn_active = atoi(PQgetvalue(res, 0,  8));
    conn_max    = atoi(PQgetvalue(res, 0,  9));

    rtrim(host); rtrim(uptime); rtrim(total_size);
    PQclear(res);

    /* Build "host:port" or just "host" for unix sockets */
    char hostport[160];
    if (port[0] && strcmp(port, "0") != 0)
        snprintf(hostport, sizeof(hostport), "%s:%s", host, port);
    else
        strncpy(hostport, host, sizeof(hostport) - 1);

    format_pg_version(db_server_version(conn), ver_buf, sizeof(ver_buf));

    char scan_ts[32];
    time_t now = time(NULL);
    strftime(scan_ts, sizeof(scan_ts), "%Y-%m-%d %H:%M:%S UTC", gmtime(&now));

    /* Client identity */
    char client_host[128] = "unknown";
    gethostname(client_host, sizeof(client_host) - 1);

    char client_user[64] = "unknown";
    struct passwd *pw = getpwuid(getuid());
    if (pw)
        strncpy(client_user, pw->pw_name, sizeof(client_user) - 1);
    else if (getenv("USER"))
        strncpy(client_user, getenv("USER"), sizeof(client_user) - 1);

    char client[200];
    snprintf(client, sizeof(client), "%s@%s", client_user, client_host);

    /* Platform */
    char platform[256] = "unknown";
    struct utsname uts;
    if (uname(&uts) == 0)
        snprintf(platform, sizeof(platform), "%s %s %s",
                 uts.sysname, uts.release, uts.machine);

    const char *provider = cloud_provider_name(opts->cloud);

    /* --- print --------------------------------------------------------- */
    if (opts->format == OUTPUT_MARKDOWN) {
        printf("# pgopps Report\n\n");
        printf("## Target\n\n");
        printf("| | |\n|---|---|\n");
        printf("| **pgopps** | v%s |\n",       PGOPPS_VERSION);
        printf("| **PostgreSQL** | %s |\n",    ver_buf);
        printf("| **Host** | %s |\n",          hostport);
        printf("| **Database** | %s |\n",      database);
        printf("| **PG User** | %s |\n",       user);
        if (provider)
            printf("| **Provider** | %s |\n",  provider);
        printf("| **Started** | %s (up %s) |\n", started, uptime);
        printf("| **Storage** | %d databases, %s total |\n", db_count, total_size);
        printf("| **Connections** | %d / %d active |\n", conn_active, conn_max);
        printf("\n## Auditor\n\n");
        printf("| | |\n|---|---|\n");
        printf("| **Scanned** | %s |\n",   scan_ts);
        printf("| **Client** | %s |\n",    client);
        printf("| **Platform** | %s |\n",  platform);
        printf("\n---\n\n");
        return;
    }

    printf("\n" COL_BOLD COL_GREEN
           "  pgopps v%s" COL_RESET
           " — connected to " COL_BOLD "PostgreSQL %s" COL_RESET "\n",
           PGOPPS_VERSION, ver_buf);
    printf("  ────────────────────────────────────────────\n");
    printf("  %-14s %s\n", "Host",     hostport);
    printf("  %-14s %s\n", "Database", database);
    printf("  %-14s %s\n", "PG User",  user);

    if (provider)
        printf("  %-14s %s\n", "Provider", provider);

    printf("  %-14s %s" COL_DIM " (up %s)" COL_RESET "\n",
           "Started", started, uptime);
    printf("  %-14s %d databases, %s total\n",
           "Storage", db_count, total_size);
    printf("  %-14s %d / %d connections active\n",
           "Connections", conn_active, conn_max);
    printf("  ────────────────────────────────────────────\n");
    printf("  %-14s %s\n", "Scanned",  scan_ts);
    printf("  %-14s %s\n", "Client",   client);
    printf("  %-14s %s\n", "Platform", platform);
    printf("  ────────────────────────────────────────────\n\n");
}
