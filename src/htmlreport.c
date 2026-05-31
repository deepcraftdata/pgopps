#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/utsname.h>

#include "pgopps.h"

static int cmp_findings(const void *a, const void *b)
{
    const Finding *fa = *(const Finding **)a;
    const Finding *fb = *(const Finding **)b;
    if (fa->group != fb->group) return (int)fa->group - (int)fb->group;
    return (int)fa->priority - (int)fb->priority;
}

static const char *pri_color(Priority p)
{
    switch (p) {
    case PRIORITY_CRITICAL: return "#dc2626";
    case PRIORITY_HIGH:     return "#ea580c";
    case PRIORITY_MEDIUM:   return "#d97706";
    case PRIORITY_LOW:      return "#0284c7";
    default:                return "#6b7280";
    }
}
static const char *pri_bg(Priority p)
{
    switch (p) {
    case PRIORITY_CRITICAL: return "#fef2f2";
    case PRIORITY_HIGH:     return "#fff7ed";
    case PRIORITY_MEDIUM:   return "#fffbeb";
    case PRIORITY_LOW:      return "#f0f9ff";
    default:                return "#f9fafb";
    }
}
static const char *score_color(int s) { return s>=75?"#16a34a":s>=50?"#d97706":"#dc2626"; }
static const char *score_grade(int s) {
    if (s>=90) return "Excellent";
    if (s>=75) return "Good";
    if (s>=50) return "Fair";
    if (s>=25) return "Poor";
    return "Critical";
}

/* Escape for normal HTML text — converts \n to <br> */
static void he(const char *src, char *dst, size_t n)
{
    size_t d = 0;
    for (const char *s = src; *s && d < n-1; s++) {
        const char *e = NULL;
        switch (*s) {
        case '&':  e = "&amp;";  break;
        case '<':  e = "&lt;";   break;
        case '>':  e = "&gt;";   break;
        case '"':  e = "&quot;"; break;
        case '\n': e = "<br>";   break;
        default: dst[d++] = *s; continue;
        }
        while (*e && d < n-1) dst[d++] = *e++;
    }
    dst[d] = '\0';
}

/* Escape for <pre> blocks — keeps newlines as-is */
static void he_pre(const char *src, char *dst, size_t n)
{
    size_t d = 0;
    for (const char *s = src; *s && d < n-1; s++) {
        const char *e = NULL;
        switch (*s) {
        case '&': e = "&amp;"; break;
        case '<': e = "&lt;";  break;
        case '>': e = "&gt;";  break;
        default: dst[d++] = *s; continue;
        }
        while (*e && d < n-1) dst[d++] = *e++;
    }
    dst[d] = '\0';
}

static void emit_css(void)
{
    fputs("<style>\n"
"*{box-sizing:border-box;margin:0;padding:0}\n"
"body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
     "background:#f1f5f9;color:#1e293b;font-size:14px;line-height:1.6}\n"
".wrap{max-width:960px;margin:0 auto;padding:24px 16px}\n"

/* header */
".hdr{display:flex;align-items:center;justify-content:space-between;"
     "background:#1e293b;color:#fff;border-radius:12px 12px 0 0;padding:24px 32px}\n"
".brand h1{font-size:26px;font-weight:700;letter-spacing:-.5px}\n"
".brand h1 em{color:#94a3b8;font-size:13px;font-weight:400;font-style:normal;margin-left:8px}\n"
".brand p{color:#94a3b8;font-size:12px;margin-top:2px}\n"
".gauge-wrap{text-align:center}\n"
".gauge{width:96px;height:96px;transform:rotate(-90deg)}\n"
".gauge .tr{fill:none;stroke:#334155;stroke-width:9}\n"
".gauge .fi{fill:none;stroke-width:9;stroke-linecap:round}\n"
".gnum{font-size:26px;font-weight:700;dominant-baseline:middle;"
      "transform:rotate(90deg);transform-origin:50px 50px}\n"
".ggrade{font-size:11px;dominant-baseline:middle;"
        "transform:rotate(90deg);transform-origin:50px 65px}\n"
".gauge-lbl{color:#94a3b8;font-size:11px;margin-top:4px}\n"

/* info */
".info{background:#fff;border:1px solid #e2e8f0;border-top:none;"
      "padding:20px 32px;display:grid;grid-template-columns:1fr 1fr;gap:20px}\n"
".isec h3{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;"
          "color:#94a3b8;margin-bottom:8px}\n"
".irow{display:flex;gap:8px;margin-bottom:3px}\n"
".ilbl{color:#64748b;min-width:86px;font-size:12px}\n"
".ival{color:#1e293b;font-size:12px;font-weight:500}\n"

/* severity bar */
".sbar{background:#fff;border:1px solid #e2e8f0;border-top:none;"
      "padding:10px 32px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}\n"
".sbar-lbl{font-size:11px;color:#94a3b8;margin-right:4px}\n"
".pill{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;"
      "border-radius:9999px;font-size:11px;font-weight:700}\n"

/* findings */
".findings{margin-top:16px}\n"
".grp{background:#fff;border:1px solid #e2e8f0;border-radius:8px;"
     "margin-bottom:10px;overflow:hidden}\n"
".grp-hdr{background:#f8fafc;border-bottom:1px solid #e2e8f0;padding:8px 20px}\n"
".grp-hdr h2{font-size:11px;font-weight:700;text-transform:uppercase;"
             "letter-spacing:.6px;color:#475569}\n"
".row{padding:10px 20px;border-bottom:1px solid #f1f5f9;"
     "display:grid;grid-template-columns:88px 82px 1fr;gap:8px;align-items:start}\n"
".row:last-child{border-bottom:none}\n"
".row.exp{grid-template-columns:1fr}\n"
".row-top{display:grid;grid-template-columns:88px 82px 1fr;gap:8px;align-items:center}\n"
".fid{font-family:ui-monospace,'SF Mono','Fira Code',monospace;font-size:11px;"
     "color:#94a3b8;font-weight:600}\n"
".badge{display:inline-block;padding:2px 7px;border-radius:4px;"
       "font-size:10px;font-weight:700}\n"
".ftitle{font-size:13px;color:#1e293b}\n"
".fdetail{margin-top:10px;padding-top:10px;border-top:1px dashed #e2e8f0}\n"
".dlbl{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;"
      "color:#94a3b8;margin-bottom:4px}\n"
".dtext{font-size:13px;color:#475569}\n"
".fixblk{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;"
        "padding:10px 14px;margin-top:8px}\n"
".fixlbl{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;"
        "color:#16a34a;margin-bottom:6px}\n"
".fixlbl.restart{color:#d97706}\n"
".fixpre{font-family:ui-monospace,'SF Mono','Fira Code',monospace;font-size:11px;"
        "color:#1e293b;white-space:pre-wrap;line-height:1.5}\n"
".fixblk.restart{background:#fffbeb;border-color:#fed7aa}\n"
".manblk{background:#fafafa;border:1px solid #e2e8f0;border-radius:6px;"
        "padding:10px 14px;margin-top:8px}\n"
".manlbl{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;"
        "color:#94a3b8;margin-bottom:4px}\n"

/* footer */
".footer{margin-top:20px;text-align:center;font-size:11px;color:#94a3b8;padding:12px}\n"
".footer a{color:#0284c7;text-decoration:none}\n"
"@media(max-width:600px){"
".hdr{flex-direction:column;gap:16px;text-align:center}"
".info{grid-template-columns:1fr}"
".row,.row-top{grid-template-columns:1fr;gap:4px}"
"}\n"
"</style>\n", stdout);
}

void htmlreport_print(Finding **findings, int count, int score,
                      const Options *opts, PGconn *conn)
{
    qsort(findings, count, sizeof(Finding *), cmp_findings);

    /* Metadata */
    char scan_ts[32];
    time_t now = time(NULL);
    strftime(scan_ts, sizeof(scan_ts), "%Y-%m-%d %H:%M:%S UTC", gmtime(&now));

    char client_host[128] = "unknown";
    gethostname(client_host, sizeof(client_host) - 1);
    char client_user[64] = "unknown";
    struct passwd *pw = getpwuid(getuid());
    if (pw) strncpy(client_user, pw->pw_name, sizeof(client_user)-1);
    else if (getenv("USER")) strncpy(client_user, getenv("USER"), sizeof(client_user)-1);

    char platform[256] = "unknown";
    struct utsname uts;
    if (uname(&uts) == 0)
        snprintf(platform, sizeof(platform), "%s %s %s",
                 uts.sysname, uts.release, uts.machine);

    char db[128]="", host[160]="", pguser[64]="", ver[32]="";
    PGresult *res = PQexec(conn,
        "SELECT current_database(), current_user,"
        "  COALESCE(host(inet_server_addr())||':'||inet_server_port()::text,'local'),"
        "  current_setting('server_version')");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        strncpy(db,     PQgetvalue(res,0,0), sizeof(db)-1);
        strncpy(pguser, PQgetvalue(res,0,1), sizeof(pguser)-1);
        strncpy(host,   PQgetvalue(res,0,2), sizeof(host)-1);
        strncpy(ver,    PQgetvalue(res,0,3), sizeof(ver)-1);
    }
    PQclear(res);

    const char *provider = cloud_provider_name(opts->cloud);

    /* Severity counts (all findings) */
    int cnt[6] = {0};
    for (int i = 0; i < count; i++)
        for (Finding *f = findings[i]; f; f = f->next)
            if (f->priority >= 1 && f->priority <= 5)
                cnt[(int)f->priority]++;

    /* Score gauge: circle r=40, circumference = 2*PI*40 ≈ 251.3 */
    float circ   = 251.3f;
    float offset = circ * (1.0f - (float)score / 100.0f);
    const char *sc    = score_color(score);
    const char *grade = score_grade(score);

    /* Escaped strings */
    char db_e[256], host_e[256], pguser_e[128], ver_e[64];
    char platform_e[256], client_e[128];
    he(db,          db_e,       sizeof(db_e));
    he(host,        host_e,     sizeof(host_e));
    he(pguser,      pguser_e,   sizeof(pguser_e));
    he(ver,         ver_e,      sizeof(ver_e));
    he(platform,    platform_e, sizeof(platform_e));
    he(client_user, client_e,   sizeof(client_e));

    /* ── DOCTYPE + head ── */
    printf("<!DOCTYPE html>\n"
           "<html lang=\"en\">\n"
           "<head>\n"
           "  <meta charset=\"UTF-8\">\n"
           "  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
           "  <title>pgopps Report \xe2\x80\x94 %s</title>\n",
           db_e);
    emit_css();
    printf("</head>\n<body>\n<div class=\"wrap\">\n\n");

    /* ── Header ── */
    printf(
        "<div class=\"hdr\">\n"
        "  <div class=\"brand\">\n"
        "    <h1>pgopps <em>v%s</em></h1>\n"
        "    <p>PostgreSQL OPPortunit\xc3\xadS \xe2\x80\x94 Health Report</p>\n"
        "  </div>\n"
        "  <div class=\"gauge-wrap\">\n"
        "    <svg class=\"gauge\" viewBox=\"0 0 100 100\">\n"
        "      <circle class=\"tr\" cx=\"50\" cy=\"50\" r=\"40\"/>\n"
        "      <circle class=\"fi\" cx=\"50\" cy=\"50\" r=\"40\""
        " style=\"stroke:%s;stroke-dasharray:%.1f;stroke-dashoffset:%.1f\"/>\n"
        "      <text class=\"gnum\" x=\"50\" y=\"50\" text-anchor=\"middle\""
        " fill=\"white\">%d</text>\n"
        "      <text class=\"ggrade\" x=\"50\" y=\"65\" text-anchor=\"middle\""
        " fill=\"#94a3b8\">%s</text>\n"
        "    </svg>\n"
        "    <div class=\"gauge-lbl\">Opps Score / 100</div>\n"
        "  </div>\n"
        "</div>\n\n",
        PGOPPS_VERSION,
        sc, circ, offset, score, grade);

    /* ── Info grid ── */
    printf("<div class=\"info\">\n"
           "  <div class=\"isec\">\n"
           "    <h3>Target</h3>\n"
           "    <div class=\"irow\"><span class=\"ilbl\">Host</span>"
           "<span class=\"ival\">%s</span></div>\n"
           "    <div class=\"irow\"><span class=\"ilbl\">Database</span>"
           "<span class=\"ival\">%s</span></div>\n"
           "    <div class=\"irow\"><span class=\"ilbl\">PG User</span>"
           "<span class=\"ival\">%s</span></div>\n"
           "    <div class=\"irow\"><span class=\"ilbl\">PostgreSQL</span>"
           "<span class=\"ival\">%s</span></div>\n",
           host_e, db_e, pguser_e, ver_e);
    if (provider) {
        char prov_e[64]; he(provider, prov_e, sizeof(prov_e));
        printf("    <div class=\"irow\"><span class=\"ilbl\">Provider</span>"
               "<span class=\"ival\">%s</span></div>\n", prov_e);
    }
    printf("  </div>\n"
           "  <div class=\"isec\">\n"
           "    <h3>Auditor</h3>\n"
           "    <div class=\"irow\"><span class=\"ilbl\">Scanned</span>"
           "<span class=\"ival\">%s</span></div>\n"
           "    <div class=\"irow\"><span class=\"ilbl\">Client</span>"
           "<span class=\"ival\">%s@%s</span></div>\n"
           "    <div class=\"irow\"><span class=\"ilbl\">Platform</span>"
           "<span class=\"ival\">%s</span></div>\n"
           "  </div>\n"
           "</div>\n\n",
           scan_ts, client_e, client_host, platform_e);

    /* ── Severity bar ── */
    printf("<div class=\"sbar\">\n"
           "  <span class=\"sbar-lbl\">Findings:</span>\n");
    if (cnt[1]) printf("  <span class=\"pill\" style=\"background:#fef2f2;color:#dc2626\">"
                       "&#9679; CRITICAL %d</span>\n", cnt[1]);
    if (cnt[2]) printf("  <span class=\"pill\" style=\"background:#fff7ed;color:#ea580c\">"
                       "&#9679; HIGH %d</span>\n", cnt[2]);
    if (cnt[3]) printf("  <span class=\"pill\" style=\"background:#fffbeb;color:#d97706\">"
                       "&#9679; MEDIUM %d</span>\n", cnt[3]);
    if (cnt[4]) printf("  <span class=\"pill\" style=\"background:#f0f9ff;color:#0284c7\">"
                       "&#9679; LOW %d</span>\n", cnt[4]);
    if (cnt[5]) printf("  <span class=\"pill\" style=\"background:#f9fafb;color:#6b7280\">"
                       "&#9679; INFO %d</span>\n", cnt[5]);
    printf("</div>\n\n");

    /* ── Findings ── */
    printf("<div class=\"findings\">\n");
    CheckGroup cur = (CheckGroup)-1;
    int shown = 0;

    for (int i = 0; i < count; i++) {
        Finding *f = findings[i];
        if (!f) continue;
        if ((int)f->priority > opts->min_priority) continue;

        if (f->group != cur) {
            if (cur != (CheckGroup)-1) printf("</div>\n\n");
            cur = f->group;
            char grpname_e[64]; he(group_name(cur), grpname_e, sizeof(grpname_e));
            printf("<div class=\"grp\">\n"
                   "  <div class=\"grp-hdr\"><h2>%s</h2></div>\n", grpname_e);
        }

        char fid[16];
        snprintf(fid, sizeof(fid), "%s-%03d", group_abbrev(f->group), f->id);
        char title_e[512]; he(f->title, title_e, sizeof(title_e));
        const char *c  = pri_color(f->priority);
        const char *bg = pri_bg(f->priority);

        if (opts->verbose) {
            printf("  <div class=\"row exp\">\n"
                   "    <div class=\"row-top\">\n"
                   "      <span class=\"fid\">%s</span>\n"
                   "      <span class=\"badge\" style=\"background:%s;color:%s\">%s</span>\n"
                   "      <span class=\"ftitle\">%s</span>\n"
                   "    </div>\n",
                   fid, bg, c, priority_name(f->priority), title_e);

            if (f->description[0]) {
                char desc_e[2048]; he(f->description, desc_e, sizeof(desc_e));
                printf("    <div class=\"fdetail\">\n"
                       "      <div class=\"dlbl\">Detail</div>\n"
                       "      <div class=\"dtext\">%s</div>\n"
                       "    </div>\n", desc_e);
            }

            if (f->fix_sql[0]) {
                char sql_e[2048]; he_pre(f->fix_sql, sql_e, sizeof(sql_e));
                int restart = (f->fix_type == FIX_RESTART);
                printf("    <div class=\"fixblk%s\">\n"
                       "      <div class=\"fixlbl%s\">%s</div>\n"
                       "      <pre class=\"fixpre\">%s</pre>\n"
                       "    </div>\n",
                       restart ? " restart" : "",
                       restart ? " restart" : "",
                       restart ? "SQL Fix \xe2\x80\x94 restart required"
                               : "SQL Fix \xe2\x80\x94 reload sufficient",
                       sql_e);
            } else if (f->remediation[0]) {
                char rem_e[1024]; he(f->remediation, rem_e, sizeof(rem_e));
                printf("    <div class=\"manblk\">\n"
                       "      <div class=\"manlbl\">Remediation</div>\n"
                       "      <div class=\"dtext\">%s</div>\n"
                       "    </div>\n", rem_e);
            }
            printf("  </div>\n");
        } else {
            printf("  <div class=\"row\">\n"
                   "    <span class=\"fid\">%s</span>\n"
                   "    <span class=\"badge\" style=\"background:%s;color:%s\">%s</span>\n"
                   "    <span class=\"ftitle\">%s</span>\n"
                   "  </div>\n",
                   fid, bg, c, priority_name(f->priority), title_e);
        }
        shown++;
    }

    if (cur != (CheckGroup)-1) printf("</div>\n");
    if (shown == 0)
        printf("<div class=\"grp\"><div style=\"padding:20px;color:#94a3b8\">"
               "No findings at this priority level.</div></div>\n");

    printf("</div>\n\n"); /* .findings */

    /* ── Footer ── */
    printf("<div class=\"footer\">\n"
           "  Generated by "
           "<a href=\"https://github.com/deepcraftdata/pgopps\">pgopps</a>"
           " v%s &middot; %s\n"
           "</div>\n\n",
           PGOPPS_VERSION, scan_ts);

    printf("</div>\n</body>\n</html>\n");
}
