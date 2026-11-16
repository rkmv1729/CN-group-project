#include "log.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static FILE     *g_out;
static int       g_own;
static log_level g_level = LOGLVL_INFO;
static const char *names[] = { "ERROR", "WARN", "INFO", "DEBUG", "TRACE" };

int log_init(const char *path, log_level lvl)
{
    g_level = lvl;
    if (path) {
        FILE *f = fopen(path, "ae");
        if (!f) return -1;
        g_out = f;
        g_own = 1;
    } else {
        g_out = stderr;
    }
    return 0;
}

void log_close(void)
{
    if (g_own && g_out) fclose(g_out);
    g_out = NULL;
    g_own = 0;
}

int log_level_from_str(const char *s, log_level *out)
{
    for (int i = 0; i < 5; i++)
        if (strcasecmp(s, names[i]) == 0) { *out = (log_level)i; return 0; }
    return -1;
}

void log_msg(log_level lvl, const char *fmt, ...)
{
    if (lvl > g_level) return;
    if (!g_out) g_out = stderr;
    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(g_out, "%s [%s] ", ts, names[lvl]);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_out, fmt, ap);
    va_end(ap);
    fputc('\n', g_out);
    fflush(g_out);
}
