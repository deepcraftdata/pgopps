#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pgopps.h"

Finding *finding_new(Priority priority, CheckGroup group,
                     const char *title, const char *description,
                     const char *remediation)
{
    Finding *f = calloc(1, sizeof(Finding));
    if (!f) return NULL;

    f->priority = priority;
    f->group    = group;
    f->next     = NULL;

    strncpy(f->title,       title       ? title       : "",       sizeof(f->title)       - 1);
    strncpy(f->description, description ? description : "",       sizeof(f->description) - 1);
    strncpy(f->remediation, remediation ? remediation : "",       sizeof(f->remediation) - 1);

    return f;
}

void finding_free_list(Finding *head)
{
    while (head) {
        Finding *next = head->next;
        free(head);
        head = next;
    }
}

const char *priority_name(Priority p)
{
    switch (p) {
    case PRIORITY_CRITICAL: return "CRITICAL";
    case PRIORITY_HIGH:     return "HIGH";
    case PRIORITY_MEDIUM:   return "MEDIUM";
    case PRIORITY_LOW:      return "LOW";
    case PRIORITY_INFO:     return "INFO";
    default:                return "UNKNOWN";
    }
}

const char *group_name(CheckGroup g)
{
    switch (g) {
    case GROUP_PERFORMANCE:       return "Performance";
    case GROUP_SECURITY:          return "Security";
    case GROUP_ENCRYPTION:        return "Encryption";
    case GROUP_AUDIT_AND_LOGGING: return "Audit & Logging";
    case GROUP_DATA_INTEGRITY:    return "Data Integrity";
    case GROUP_MAINTENANCE:       return "Maintenance";
    case GROUP_CONFIGURATION:     return "Configuration";
    case GROUP_REPLICATION_HA:    return "Replication & HA";
    case GROUP_BACKUP_RECOVERY:   return "Backup & Recovery";
    default:                      return "Other";
    }
}

const char *group_abbrev(CheckGroup g)
{
    switch (g) {
    case GROUP_PERFORMANCE:       return "PERF";
    case GROUP_SECURITY:          return "SEC";
    case GROUP_ENCRYPTION:        return "ENC";
    case GROUP_AUDIT_AND_LOGGING: return "LOG";
    case GROUP_DATA_INTEGRITY:    return "DATA";
    case GROUP_MAINTENANCE:       return "MAINT";
    case GROUP_CONFIGURATION:     return "CONF";
    case GROUP_REPLICATION_HA:    return "REPL";
    case GROUP_BACKUP_RECOVERY:   return "BACK";
    default:                      return "UNK";
    }
}
