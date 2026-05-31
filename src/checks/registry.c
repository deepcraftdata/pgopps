#include <stdio.h>

#include "pgopps.h"
#include "checks/registry.h"

typedef struct {
    const Check *checks;
    int          count;
} CheckGroup_entry;

static CheckGroup_entry all_groups[GROUP__COUNT];

void registry_init(void)
{
    all_groups[GROUP_PERFORMANCE      ] = (CheckGroup_entry){ checks_performance,    checks_performance_count    };
    all_groups[GROUP_SECURITY         ] = (CheckGroup_entry){ checks_security,       checks_security_count       };
    all_groups[GROUP_ENCRYPTION       ] = (CheckGroup_entry){ checks_encryption,     checks_encryption_count     };
    all_groups[GROUP_AUDIT_AND_LOGGING] = (CheckGroup_entry){ checks_audit_logging,  checks_audit_logging_count  };
    all_groups[GROUP_DATA_INTEGRITY   ] = (CheckGroup_entry){ checks_data_integrity, checks_data_integrity_count };
    all_groups[GROUP_MAINTENANCE      ] = (CheckGroup_entry){ checks_maintenance,    checks_maintenance_count    };
    all_groups[GROUP_CONFIGURATION    ] = (CheckGroup_entry){ checks_configuration,  checks_configuration_count  };
    all_groups[GROUP_REPLICATION_HA   ] = (CheckGroup_entry){ checks_replication_ha, checks_replication_ha_count };
    all_groups[GROUP_BACKUP_RECOVERY  ] = (CheckGroup_entry){ checks_backup_recovery,checks_backup_recovery_count};
}

void registry_run_all(PGconn *conn, const Options *opts,
                      Finding **out, int *count)
{
    *count = 0;

    for (int g = 0; g < GROUP__COUNT; g++) {
        const CheckGroup_entry *grp = &all_groups[g];
        for (int i = 0; i < grp->count; i++) {
            const Check *chk = &grp->checks[i];
            Finding *head = chk->run(conn, opts);
            if (head && *count < MAX_FINDINGS) {
                /* Stamp every finding in the chain with the check's 1-based index */
                for (Finding *f = head; f; f = f->next)
                    f->id = i + 1;
                out[(*count)++] = head;
            }
        }
    }
}
