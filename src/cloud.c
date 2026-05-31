#include <string.h>
#include "pgopps.h"

CloudProvider db_detect_cloud(PGconn *conn)
{
    const char *sql =
        "SELECT"
        "  EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'rdsadmin')                            AS aws_rds,"
        "  EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('azure_superuser','azure_pg_admin')) AS azure,"
        "  EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'cloudsqlsuperuser')                   AS gcp,"
        "  EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'supabase_admin')                      AS supabase,"
        "  EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'neon_superuser')                      AS neon,"
        "  EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'avnadmin')                            AS aiven,"
        /* Settings-based fallback for providers that might rename roles */
        "  EXISTS(SELECT 1 FROM pg_settings WHERE name = 'rds.log_retention_period')           AS aws_rds_cfg,"
        "  EXISTS(SELECT 1 FROM pg_settings WHERE name = 'azure.extensions')                    AS azure_cfg,"
        "  EXISTS(SELECT 1 FROM pg_settings WHERE name = 'cloudsql.enable_pgaudit')             AS gcp_cfg";

    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return CLOUD_NONE;
    }

    CloudProvider cp = CLOUD_NONE;

    if (strcmp(PQgetvalue(res, 0, 0), "t") == 0 ||
        strcmp(PQgetvalue(res, 0, 6), "t") == 0)   cp = CLOUD_AWS_RDS;
    else if (strcmp(PQgetvalue(res, 0, 1), "t") == 0 ||
             strcmp(PQgetvalue(res, 0, 7), "t") == 0) cp = CLOUD_AZURE;
    else if (strcmp(PQgetvalue(res, 0, 2), "t") == 0 ||
             strcmp(PQgetvalue(res, 0, 8), "t") == 0) cp = CLOUD_GCP;
    else if (strcmp(PQgetvalue(res, 0, 3), "t") == 0) cp = CLOUD_SUPABASE;
    else if (strcmp(PQgetvalue(res, 0, 4), "t") == 0) cp = CLOUD_NEON;
    else if (strcmp(PQgetvalue(res, 0, 5), "t") == 0) cp = CLOUD_AIVEN;

    PQclear(res);
    return cp;
}

const char *cloud_provider_name(CloudProvider cp)
{
    switch (cp) {
    case CLOUD_AWS_RDS:  return "AWS RDS / Aurora";
    case CLOUD_AZURE:    return "Azure Database for PostgreSQL";
    case CLOUD_GCP:      return "Google Cloud SQL";
    case CLOUD_SUPABASE: return "Supabase";
    case CLOUD_NEON:     return "Neon";
    case CLOUD_AIVEN:    return "Aiven";
    case CLOUD_UNKNOWN:  return "Managed (provider unknown)";
    default:             return NULL;   /* CLOUD_NONE → don't display */
    }
}

/*
 * Short hint appended to remediation text when a setting cannot be changed
 * directly in postgresql.conf on a managed cloud instance.
 */
const char *cloud_param_hint(CloudProvider cp)
{
    switch (cp) {
    case CLOUD_AWS_RDS:  return "On RDS: apply via Parameter Group; reboot may be required.";
    case CLOUD_AZURE:    return "On Azure: apply via Portal → Server parameters.";
    case CLOUD_GCP:      return "On Cloud SQL: apply via Edit instance → Database flags.";
    case CLOUD_SUPABASE: return "On Supabase: apply via Dashboard → Database → Configuration.";
    default:             return NULL;
    }
}
