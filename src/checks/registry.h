#ifndef PGOPPS_REGISTRY_H
#define PGOPPS_REGISTRY_H

#include "pgopps.h"

extern const Check checks_performance[];
extern const int   checks_performance_count;

extern const Check checks_security[];
extern const int   checks_security_count;

extern const Check checks_encryption[];
extern const int   checks_encryption_count;

extern const Check checks_audit_logging[];
extern const int   checks_audit_logging_count;

extern const Check checks_data_integrity[];
extern const int   checks_data_integrity_count;

extern const Check checks_maintenance[];
extern const int   checks_maintenance_count;

extern const Check checks_configuration[];
extern const int   checks_configuration_count;

extern const Check checks_replication_ha[];
extern const int   checks_replication_ha_count;

extern const Check checks_backup_recovery[];
extern const int   checks_backup_recovery_count;

#endif /* PGOPPS_REGISTRY_H */
