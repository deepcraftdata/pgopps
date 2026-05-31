#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp */
#include <getopt.h>

#include "pgopps.h"

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] CONNSTR\n"
        "\n"
        "  CONNSTR   PostgreSQL connection string\n"
        "            e.g. \"postgresql://user:pass@host:5432/dbname\"\n"
        "                 \"host=localhost dbname=mydb user=readonly\"\n"
        "\n"
        "Options:\n"
        "  -f, --format  TEXT|JSON|MARKDOWN|HTML  output format (default: TEXT)\n"
        "  -p, --priority 1-5         minimum priority to show (default: 3)\n"
        "  -v, --verbose              show extra detail\n"
        "      --fix-script           emit a ready-to-run SQL fix script\n"
        "  -h, --help                 show this help\n"
        "      --version              show version\n"
        "\n"
        "pgopps v%s — PostgreSQL Opportunities\n",
        prog, PGOPPS_VERSION);
}

int main(int argc, char *argv[])
{
    Options opts = {
        .connstr      = NULL,
        .format       = OUTPUT_TEXT,
        .min_priority = PRIORITY_MEDIUM,
        .verbose      = 0,
        .cloud        = CLOUD_NONE,
    };

    static struct option long_opts[] = {
        { "format",     required_argument, NULL, 'f' },
        { "priority",   required_argument, NULL, 'p' },
        { "verbose",    no_argument,       NULL, 'v' },
        { "fix-script", no_argument,       NULL, 'F' },
        { "help",       no_argument,       NULL, 'h' },
        { "version",    no_argument,       NULL, 'V' },
        { NULL, 0, NULL, 0 }
    };

    int c;
    while ((c = getopt_long(argc, argv, "f:p:vhF", long_opts, NULL)) != -1) {
        switch (c) {
        case 'f':
            if (strcasecmp(optarg, "json") == 0)
                opts.format = OUTPUT_JSON;
            else if (strcasecmp(optarg, "markdown") == 0 || strcasecmp(optarg, "md") == 0)
                opts.format = OUTPUT_MARKDOWN;
            else if (strcasecmp(optarg, "html") == 0)
                opts.format = OUTPUT_HTML;
            else if (strcasecmp(optarg, "text") != 0) {
                fprintf(stderr, "Unknown format: %s\n", optarg);
                return 1;
            }
            break;
        case 'p':
            opts.min_priority = atoi(optarg);
            if (opts.min_priority < 1 || opts.min_priority > 5) {
                fprintf(stderr, "Priority must be 1-5\n");
                return 1;
            }
            break;
        case 'v':
            opts.verbose = 1;
            break;
        case 'F':
            opts.fix_script = 1;
            break;
        case 'V':
            printf("pgopps %s\n", PGOPPS_VERSION);
            return 0;
        case 'h':
        default:
            usage(argv[0]);
            return c == 'h' ? 0 : 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: connection string required\n\n");
        usage(argv[0]);
        return 1;
    }
    opts.connstr = argv[optind];

    PGconn *conn = db_connect(opts.connstr);
    if (!conn)
        return 1;

    opts.cloud = db_detect_cloud(conn);

    registry_init();

    Finding *findings[MAX_FINDINGS];
    int      count = 0;
    registry_run_all(conn, &opts, findings, &count);

    int score = score_calculate(findings, count);

    if (opts.fix_script) {
        fixscript_print(findings, count, score, &opts, conn);
    } else if (opts.format == OUTPUT_HTML) {
        htmlreport_print(findings, count, score, &opts, conn);
    } else {
        db_print_info(conn, &opts);
        report_print(findings, count, &opts);
        score_print(score, count, &opts);
    }

    for (int i = 0; i < count; i++)
        finding_free_list(findings[i]);

    db_disconnect(conn);
    return 0;
}
