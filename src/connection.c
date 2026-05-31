#include <stdio.h>
#include <stdlib.h>

#include "pgopps.h"

PGconn *db_connect(const char *connstr)
{
    PGconn *conn = PQconnectdb(connstr);

    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        return NULL;
    }

    /* Enforce read-only: refuse connections that could accidentally write */
    PGresult *res = PQexec(conn, "SET default_transaction_read_only = on");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Could not set read-only mode: %s\n", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return NULL;
    }
    PQclear(res);

    return conn;
}

void db_disconnect(PGconn *conn)
{
    if (conn)
        PQfinish(conn);
}

int db_server_version(PGconn *conn)
{
    return PQserverVersion(conn);
}
