#include <stdio.h>
#include <stdlib.h>    /* qsort */
#include <string.h>

#include "pgopps.h"

/* ----------------------------------------------------------------
 * Simple comparison for qsort: sort by group, then priority
 * ---------------------------------------------------------------- */
static int cmp_findings(const void *a, const void *b)
{
    const Finding *fa = *(const Finding **)a;
    const Finding *fb = *(const Finding **)b;

    if (fa->group != fb->group)
        return (int)fa->group - (int)fb->group;
    return (int)fa->priority - (int)fb->priority;
}

/* ----------------------------------------------------------------
 * ANSI colours for text output
 * ---------------------------------------------------------------- */
#define COL_RESET   "\033[0m"
#define COL_RED     "\033[31m"
#define COL_YELLOW  "\033[33m"
#define COL_CYAN    "\033[36m"
#define COL_BOLD    "\033[1m"
#define COL_DIM     "\033[2m"

static const char *priority_color(Priority p)
{
    switch (p) {
    case PRIORITY_CRITICAL: return COL_RED COL_BOLD;
    case PRIORITY_HIGH:     return COL_RED;
    case PRIORITY_MEDIUM:   return COL_YELLOW;
    case PRIORITY_LOW:      return COL_CYAN;
    default:                return COL_DIM;
    }
}

static void print_text(Finding **findings, int count, const Options *opts)
{
    printf(COL_BOLD "  Findings\n" COL_RESET);

    CheckGroup current_group = -1;
    int shown = 0;

    for (int i = 0; i < count; i++) {
        Finding *f = findings[i];
        if (!f) continue;
        if ((int)f->priority > opts->min_priority) continue;

        if (f->group != current_group) {
            current_group = f->group;
            printf(COL_BOLD "[ %s ]\n" COL_RESET, group_name(current_group));
        }

        char fid[16];
        snprintf(fid, sizeof(fid), "[%s-%03d]", group_abbrev(f->group), f->id);
        printf("  %-11s  %s%-8s" COL_RESET "  %s\n",
               fid,
               priority_color(f->priority),
               priority_name(f->priority),
               f->title);

        if (opts->verbose) {
            /* 15 spaces aligns label under the priority column;
               label %-8s + 2 spaces puts content at col 25 (= title start) */
            if (f->description[0]) {
                char buf[sizeof(f->description)];
                strncpy(buf, f->description, sizeof(buf) - 1);
                buf[sizeof(buf) - 1] = '\0';
                char *saveptr = NULL;
                char *line = strtok_r(buf, "\n", &saveptr);
                int first = 1;
                while (line) {
                    if (first)
                        printf("               " COL_DIM "%-8s" COL_RESET "  %s\n",
                               "Detail", line);
                    else
                        printf("                         %s\n", line);
                    first = 0;
                    line = strtok_r(NULL, "\n", &saveptr);
                }
            }
            if (f->remediation[0])
                printf("               " COL_DIM "%-8s" COL_RESET "  %s\n",
                       "Fix", f->remediation);
            printf("\n");
        }
        shown++;
    }

    if (shown == 0)
        printf("  No findings at priority level %d or above.\n", opts->min_priority);

    /* Severity breakdown — count all findings regardless of filter */
    int cnt[6] = {0};
    for (int i = 0; i < count; i++) {
        Finding *f = findings[i];
        while (f) {
            if (f->priority >= 1 && f->priority <= 5)
                cnt[(int)f->priority]++;
            f = f->next;
        }
    }

    printf("\n─────────────────────────────────────────────\n ");
    if (cnt[1]) printf("  " COL_RED COL_BOLD "CRITICAL %d" COL_RESET, cnt[1]);
    if (cnt[2]) printf("  " COL_RED            "HIGH %d" COL_RESET, cnt[2]);
    if (cnt[3]) printf("  " COL_YELLOW        "MEDIUM %d" COL_RESET, cnt[3]);
    if (cnt[4]) printf("  " COL_CYAN             "LOW %d" COL_RESET, cnt[4]);
    if (cnt[5]) printf("  " COL_DIM             "INFO %d" COL_RESET, cnt[5]);
    printf("\n");
    printf("%d finding(s) shown (priority ≤ %s)\n\n",
           shown, priority_name(opts->min_priority));
}

static void print_json(Finding **findings, int count, const Options *opts)
{
    printf("[\n");
    int first = 1;
    for (int i = 0; i < count; i++) {
        Finding *f = findings[i];
        if (!f) continue;
        if ((int)f->priority > opts->min_priority) continue;

        if (!first) printf(",\n");
        first = 0;

        char fid[16];
        snprintf(fid, sizeof(fid), "%s-%03d", group_abbrev(f->group), f->id);
        printf("  {\"id\":\"%s\",\"priority\":%d,\"priority_name\":\"%s\","
               "\"group\":\"%s\",\"title\":\"%s\","
               "\"description\":\"%s\",\"remediation\":\"%s\"}",
               fid, f->priority, priority_name(f->priority),
               group_name(f->group), f->title,
               f->description, f->remediation);
    }
    printf("\n]\n");
}

static void print_markdown(Finding **findings, int count, const Options *opts)
{
    printf("## Findings\n\n");

    CheckGroup current_group = (CheckGroup)-1;
    int shown = 0;

    for (int i = 0; i < count; i++) {
        Finding *f = findings[i];
        if (!f) continue;
        if ((int)f->priority > opts->min_priority) continue;

        if (f->group != current_group) {
            current_group = f->group;
            if (shown > 0) printf("\n");
            printf("### %s\n\n", group_name(current_group));
            printf("| ID | Priority | Finding |\n");
            printf("|---|---|---|\n");
        }
        printf("| %s-%03d | %s | %s |\n",
               group_abbrev(f->group), f->id,
               priority_name(f->priority),
               f->title);
        shown++;
    }

    if (shown == 0)
        printf("No findings at priority level %d or above.\n", opts->min_priority);

    if (opts->verbose && shown > 0) {
        printf("\n---\n\n## Details\n\n");
        current_group = (CheckGroup)-1;
        for (int i = 0; i < count; i++) {
            Finding *f = findings[i];
            if (!f) continue;
            if ((int)f->priority > opts->min_priority) continue;

            if (f->group != current_group) {
                current_group = f->group;
                printf("### %s\n\n", group_name(current_group));
            }
            printf("#### `%s-%03d` — %s — %s\n\n",
                   group_abbrev(f->group), f->id,
                   priority_name(f->priority),
                   f->title);
            if (f->description[0])
                printf("%s\n\n", f->description);
            if (f->remediation[0])
                printf("**Fix:** %s\n\n", f->remediation);
        }
    }

    int cnt[6] = {0};
    for (int i = 0; i < count; i++) {
        Finding *f = findings[i];
        while (f) {
            if (f->priority >= 1 && f->priority <= 5)
                cnt[(int)f->priority]++;
            f = f->next;
        }
    }

    printf("\n---\n\n## Summary\n\n");
    printf("| Severity | Count |\n|---|---|\n");
    if (cnt[1]) printf("| CRITICAL | %d |\n", cnt[1]);
    if (cnt[2]) printf("| HIGH | %d |\n", cnt[2]);
    if (cnt[3]) printf("| MEDIUM | %d |\n", cnt[3]);
    if (cnt[4]) printf("| LOW | %d |\n", cnt[4]);
    if (cnt[5]) printf("| INFO | %d |\n", cnt[5]);
    printf("\n%d finding(s) shown (priority ≤ %s)\n\n",
           shown, priority_name(opts->min_priority));
}

void report_print(Finding **findings, int count, const Options *opts)
{
    /* Sort in-place before printing */
    qsort(findings, count, sizeof(Finding *), cmp_findings);

    if (opts->format == OUTPUT_JSON)
        print_json(findings, count, opts);
    else if (opts->format == OUTPUT_MARKDOWN)
        print_markdown(findings, count, opts);
    else
        print_text(findings, count, opts);
}
