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

static Finding *check_stale_replication_slots(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT slot_name, slot_type,"
        "       COALESCE(active_pid::text, 'none')                           AS pid,"
        "       pg_size_pretty("
        "           pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn))     AS retained,"
        "       pg_wal_lsn_diff(pg_current_wal_sn(), restart_lsn)          AS retained_bytes"
        " FROM pg_replication_slots"
        " WHERE active = false"
        " ORDER BY retained_bytes DESC");

    /* Fix: pg_current_wal_lsn not pg_current_wal_sn */
    if (!res) {
        res = query(conn,
            "SELECT slot_name, slot_type,"
            "       COALESCE(active_pid::text, 'none')                           AS pid,"
            "       pg_size_pretty("
            "           pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn))     AS retained,"
            "       pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)          AS retained_bytes"
            "  FROM pg_replication_slots"
            " WHERE active = false"
            " ORDER BY retained_bytes DESC");
    }
    if (!res) return NULL;

    int n = PQntuples(res);

    long long max_bytes = atoll(PQgetvalue(res, 0, 4));
    Priority p;
    if      (max_bytes >= 10LL * 1024 * 1024 * 1024) p = PRIORITY_CRITICAL;
    else if (max_bytes >= 1LL  * 1024 * 1024 * 1024) p = PRIORITY_HIGH;
    else                                              p = PRIORITY_MEDIUM;

    char desc[1024] = {0};
    char *dp  = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(dp, rem,
        "%d inactive replication slot(s) preventing WAL cleanup:\n", n);
    dp += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(dp, rem, "  %-32s  type: %-10s  retained WAL: %s\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 3));
        dp += w; rem -= w;
    }

    if (rem > 0)
        strncat(dp,
            "Inactive slots hold WAL segments on disk indefinitely. "
            "If the consumer never reconnects, disk can fill completely.",
            rem - 1);
    PQclear(res);

    return finding_new(p, GROUP_REPLICATION_HA,
        "Inactive replication slots retaining WAL",
        desc,
        "If the slot consumer is permanently gone: "
        "SELECT pg_drop_replication_slot('<slot_name>'); "
        "If temporary: set wal_keep_size as a safety net while the consumer recovers.");
}

static Finding *check_replication_lag(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT COALESCE(client_addr::text, 'socket') AS addr,"
        "       state,"
        "       sync_state,"
        "       COALESCE(EXTRACT(epoch FROM replay_lag)::int, 0) AS lag_secs,"
        "       pg_size_pretty("
        "           pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)) AS lag_size,"
        "       pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)      AS lag_bytes"
        "  FROM pg_stat_replication"
        " WHERE pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) > 0"
        " ORDER BY lag_bytes DESC");
    if (!res) return NULL;

    int n = PQntuples(res);

    long long max_bytes = atoll(PQgetvalue(res, 0, 5));
    int       max_secs  = atoi(PQgetvalue(res, 0, 3));
    Priority  p;

    if      (max_bytes >= 1LL * 1024 * 1024 * 1024 || max_secs >= 300) p = PRIORITY_HIGH;
    else if (max_bytes >= 100LL * 1024 * 1024       || max_secs >= 60)  p = PRIORITY_MEDIUM;
    else                                                                  p = PRIORITY_LOW;

    char desc[1024] = {0};
    char *dp  = desc;
    int   rem = (int)sizeof(desc);
    int   w;

    w = snprintf(dp, rem,
        "%d standby/subscriber(s) with replication lag:\n", n);
    dp += w; rem -= w;

    for (int i = 0; i < n && rem > 0; i++) {
        w = snprintf(dp, rem,
            "  %-20s  state: %-12s  sync: %-12s  lag: %s (%ss)\n",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2), PQgetvalue(res, i, 4),
            PQgetvalue(res, i, 3));
        dp += w; rem -= w;
    }

    if (rem > 0)
        strncat(dp,
            "High lag means the standby is behind the primary. "
            "On failover, the promoted standby may be missing recent committed transactions.",
            rem - 1);
    PQclear(res);

    return finding_new(p, GROUP_REPLICATION_HA,
        "Standbys with significant replication lag",
        desc,
        "Investigate: network bandwidth, standby disk I/O, or long-running queries "
        "on the standby blocking apply. "
        "Monitor pg_stat_replication.replay_lag over time.");
}

static Finding *check_no_standby(PGconn *conn, const Options *opts)
{
    /* Cloud providers handle HA at the infrastructure level */
    if (opts->cloud != CLOUD_NONE) return NULL;

    /* Skip if we're already on a standby */
    PGresult *recovery = query(conn, "SELECT pg_is_in_recovery()");
    if (!recovery) return NULL;
    char is_standby[8] = {0};
    strncpy(is_standby, PQgetvalue(recovery, 0, 0), sizeof(is_standby) - 1);
    PQclear(recovery);
    if (strcmp(is_standby, "t") == 0) return NULL;

    /* Check for connected standbys */
    PGresult *rep = PQexec(conn, "SELECT count(*) FROM pg_stat_replication");
    if (PQresultStatus(rep) != PGRES_TUPLES_OK) { PQclear(rep); return NULL; }
    int standbys = atoi(PQgetvalue(rep, 0, 0));
    PQclear(rep);

    if (standbys > 0) return NULL;

    return finding_new(PRIORITY_LOW, GROUP_REPLICATION_HA,
        "No standbys connected — single point of failure",
        "This server has no streaming replication standbys. "
        "A hardware failure, OS crash, or storage failure will cause downtime "
        "and potential data loss (no failover target available). "
        "RPO and RTO are unbounded without a standby.",
        "Set up at least one streaming standby with pg_basebackup. "
        "Configure wal_level = replica and max_wal_senders >= 3. "
        "Consider Patroni or repmgr for automated failover.");
}

static Finding *check_synchronous_commit(PGconn *conn, const Options *opts)
{
    (void)opts;
    PGresult *res = query(conn,
        "SELECT current_setting('synchronous_commit')");
    if (!res) return NULL;

    char val[32] = {0};
    strncpy(val, PQgetvalue(res, 0, 0), sizeof(val) - 1);
    PQclear(res);

    if (strcmp(val, "off") != 0) return NULL;

    return finding_new(PRIORITY_MEDIUM, GROUP_REPLICATION_HA,
        "synchronous_commit = off — risk of data loss on crash",
        "synchronous_commit = off allows PostgreSQL to report a transaction as "
        "committed before its WAL record is flushed to disk. "
        "If the server crashes within the wal_writer_delay window (~200ms), "
        "the last few committed transactions may be silently lost on recovery. "
        "This is a deliberate durability tradeoff, not a replication setting.",
        "Set synchronous_commit = on for full durability. "
        "If the performance benefit is needed, use synchronous_commit = local "
        "to at least guarantee local WAL durability while still sending async to standbys.");
}

/* ---------------------------------------------------------------- */

const Check checks_replication_ha[] = {
    { "stale_replication_slots", "Inactive replication slots retaining WAL",          GROUP_REPLICATION_HA, check_stale_replication_slots },
    { "replication_lag",         "Standbys with significant replication lag",         GROUP_REPLICATION_HA, check_replication_lag         },
    { "no_standby",              "No standbys connected — single point of failure",   GROUP_REPLICATION_HA, check_no_standby              },
    { "synchronous_commit",      "synchronous_commit = off risks data loss on crash", GROUP_REPLICATION_HA, check_synchronous_commit       },
};

const int checks_replication_ha_count =
    sizeof(checks_replication_ha) / sizeof(checks_replication_ha[0]);
