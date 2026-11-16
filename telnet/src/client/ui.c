#include "client.h"
#include "terminal.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void help(void)
{
    puts("Commands:\n"
         "  quit | close | q           disconnect and exit\n"
         "  status                     show connection and negotiated options\n"
         "  send ao|ayt|brk|ip|nop|ec|el|ga   send a Telnet command\n"
         "  help | ?                   this text\n"
         "  (empty line)               return to the session");
}

static void status(const client *c)
{
    printf("Connected to %s port %s.\n", c->cfg->host, c->cfg->port);
    printf("Terminal type: %s\n", c->term);
    printf("Local echo: %s\n", c->local_echo ? "on" : "off (server echoes)");
    printf("Options in effect:\n");
    int any = 0;
    for (int o = 0; o < 256; o++) {
        if (tn_opts_us_on(&c->opts, (uint8_t)o))  { printf("  WILL %s (%d)\n", tn_opt_name((uint8_t)o), o); any = 1; }
        if (tn_opts_him_on(&c->opts, (uint8_t)o)) { printf("  DO   %s (%d)\n", tn_opt_name((uint8_t)o), o); any = 1; }
    }
    if (!any) printf("  (none)\n");
}

static int cmd_from_name(const char *n)
{
    static const struct { const char *name; int cmd; } t[] = {
        {"ao", TN_AO}, {"ayt", TN_AYT}, {"brk", TN_BRK}, {"ip", TN_IP},
        {"nop", TN_NOP}, {"ec", TN_EC}, {"el", TN_EL}, {"ga", TN_GA}
    };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++)
        if (strcmp(n, t[i].name) == 0) return t[i].cmd;
    return -1;
}

void ui_command_mode(client *c)
{
    int was_raw = term_in_raw();
    term_raw_leave();

    fputs("telnet> ", stdout);
    fflush(stdout);

    char line[128];
    ssize_t n = read(STDIN_FILENO, line, sizeof line - 1);   /* cooked mode: one line */
    if (n > 0) {
        line[n] = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char *e = p + strlen(p);
        while (e > p && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) *--e = '\0';

        if (*p == '\0') {
            /* resume */
        } else if (!strcmp(p, "quit") || !strcmp(p, "close") || !strcmp(p, "q")) {
            c->quit = true;
        } else if (!strcmp(p, "status")) {
            status(c);
        } else if (!strcmp(p, "help") || !strcmp(p, "?")) {
            help();
        } else if (!strncmp(p, "send ", 5)) {
            int cmd = cmd_from_name(p + 5);
            if (cmd < 0) printf("Unknown command '%s'. Try: ao ayt brk ip nop ec el ga\n", p + 5);
            else { client_send_cmd(c, (uint8_t)cmd); printf("Sent %s.\n", p + 5); }
        } else {
            printf("Unknown command '%s'. Type 'help'.\n", p);
        }
    } else if (n == 0) {
        /* EOF at the prompt: just resume */
    }
    fflush(stdout);
    if (was_raw && !c->quit) term_raw_enter();
}
