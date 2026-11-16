#include "client_config.h"
#include "net_util.h"
#include "telnet_proto.h"
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static void usage(FILE *f, const char *prog)
{
    fprintf(f,
"Usage: %s [options] host [port]\n"
"\n"
"  -4                    use IPv4 only\n"
"  -6                    use IPv6 only\n"
"  -e CHAR               escape character, e.g. '^]' (default ^])\n"
"  -E                    disable the escape character\n"
"  -t TYPE               terminal type to report (default $TERM)\n"
"  -p PORT               port (alternative to the positional argument)\n"
"  -c SEC                connect timeout in seconds (default 10)\n"
"  -d                    print option negotiation to stderr\n"
"  -v                    print version and exit\n"
"  -h                    print this help and exit\n"
"\n"
"Port defaults to %d. At the escape character you get a \"telnet>\" prompt:\n"
"quit, status, send <ao|ayt|brk|ip|nop|ec|el|ga>, help.\n",
        prog, TN_DEFAULT_PORT);
}

/* "^]" -> 0x1d, "^?" -> 0x7f, single char -> itself. Returns -2 on error. */
static int parse_escape(const char *s)
{
    size_t n = strlen(s);
    if (n == 1) return (unsigned char)s[0];
    if (n == 2 && s[0] == '^') {
        if (s[1] == '?') return 0x7f;
        int c = toupper((unsigned char)s[1]);
        if (c >= '@' && c <= '_') return c - 64;
    }
    return -2;
}

int client_parse_args(int argc, char **argv, client_config *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    cfg->port            = "2323";
    cfg->family          = AF_UNSPEC;
    cfg->escape          = 0x1d;
    cfg->connect_timeout = 10;

    int c;
    long v;
    while ((c = getopt(argc, argv, "46e:Et:p:c:dvh")) != -1) {
        switch (c) {
        case '4': cfg->family = AF_INET; break;
        case '6': cfg->family = AF_INET6; break;
        case 'e':
            cfg->escape = parse_escape(optarg);
            if (cfg->escape == -2) { fprintf(stderr, "%s: invalid escape character '%s'\n", argv[0], optarg); return -1; }
            break;
        case 'E': cfg->escape = -1; break;
        case 't': cfg->term = optarg; break;
        case 'p': cfg->port = optarg; break;
        case 'c':
            if (parse_long(optarg, 1, 600, &v)) { fprintf(stderr, "%s: invalid timeout '%s'\n", argv[0], optarg); return -1; }
            cfg->connect_timeout = (int)v; break;
        case 'd': cfg->debug = true; break;
        case 'v': printf("telnet-client %s\n", TN_VERSION); return 1;
        case 'h': usage(stdout, argv[0]); return 1;
        default:  usage(stderr, argv[0]); return -1;
        }
    }
    if (optind >= argc) { fprintf(stderr, "%s: missing host\n", argv[0]); usage(stderr, argv[0]); return -1; }
    cfg->host = argv[optind++];
    if (optind < argc) cfg->port = argv[optind++];
    if (optind < argc) { fprintf(stderr, "%s: too many arguments\n", argv[0]); usage(stderr, argv[0]); return -1; }

    /* If the port is purely numeric it must be in range; otherwise treat as a service name. */
    char *end;
    long p = strtol(cfg->port, &end, 10);
    if (*end == '\0' && (p < 1 || p > 65535)) { fprintf(stderr, "%s: invalid port '%s'\n", argv[0], cfg->port); return -1; }
    return 0;
}
