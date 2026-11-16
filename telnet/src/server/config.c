#include "server_config.h"
#include "net_util.h"
#include "telnet_proto.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *f, const char *prog)
{
    fprintf(f,
"Usage: %s [options]\n"
"\n"
"  -p, --port PORT         TCP port to listen on (default %d)\n"
"  -b, --bind ADDR         address to bind (default 127.0.0.1; use 0.0.0.0 or :: to expose)\n"
"  -s, --shell PROGRAM     program run inside each PTY (default /bin/sh)\n"
"  -m, --max-clients N     maximum simultaneous sessions (default 32)\n"
"  -w, --idle-timeout SEC  disconnect sessions idle this long (default 0 = off)\n"
"  -B, --banner FILE       text shown to clients on connect\n"
"  -l, --log-file FILE     write log to FILE (default stderr)\n"
"  -L, --log-level LEVEL   error, warn, info, debug, trace (default info)\n"
"  -R, --allow-root        allow running as root (not recommended)\n"
"  -v, --version           print version and exit\n"
"  -h, --help              print this help and exit\n"
"\n"
"WARNING: Telnet is unencrypted. Use only on trusted networks or loopback.\n",
        prog, TN_DEFAULT_PORT);
}

static char *load_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n;
    while ((n = fread(buf + len, 1, cap - len, f)) > 0) {
        len += n;
        if (len == cap) {
            if (cap >= (1u << 20)) break;          /* cap banner at 1 MiB */
            cap *= 2;
            char *nb = realloc(buf, cap + 1);
            if (!nb) { free(buf); fclose(f); return NULL; }
            buf = nb;
        }
    }
    buf[len] = '\0';
    fclose(f);
    return buf;
}

int server_parse_args(int argc, char **argv, server_config *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    cfg->bind_addr    = "127.0.0.1";
    cfg->port         = TN_DEFAULT_PORT;
    cfg->shell        = "/bin/sh";
    cfg->max_clients  = 32;
    cfg->idle_timeout = 0;
    cfg->log_level    = LOGLVL_INFO;

    static const struct option longopts[] = {
        {"port", required_argument, 0, 'p'},     {"bind", required_argument, 0, 'b'},
        {"shell", required_argument, 0, 's'},    {"max-clients", required_argument, 0, 'm'},
        {"idle-timeout", required_argument, 0, 'w'}, {"banner", required_argument, 0, 'B'},
        {"log-file", required_argument, 0, 'l'}, {"log-level", required_argument, 0, 'L'},
        {"allow-root", no_argument, 0, 'R'},     {"version", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},           {0, 0, 0, 0}
    };

    long v;
    int c;
    while ((c = getopt_long(argc, argv, "p:b:s:m:w:B:l:L:Rvh", longopts, NULL)) != -1) {
        switch (c) {
        case 'p':
            if (parse_long(optarg, 1, 65535, &v)) { fprintf(stderr, "%s: invalid port '%s'\n", argv[0], optarg); return -1; }
            cfg->port = (uint16_t)v; break;
        case 'b': cfg->bind_addr = optarg; break;
        case 's': cfg->shell = optarg; break;
        case 'm':
            if (parse_long(optarg, 1, 1024, &v)) { fprintf(stderr, "%s: --max-clients must be 1-1024\n", argv[0]); return -1; }
            cfg->max_clients = (int)v; break;
        case 'w':
            if (parse_long(optarg, 0, 86400, &v)) { fprintf(stderr, "%s: invalid idle timeout '%s'\n", argv[0], optarg); return -1; }
            cfg->idle_timeout = (int)v; break;
        case 'B': cfg->banner_file = optarg; break;
        case 'l': cfg->log_file = optarg; break;
        case 'L':
            if (log_level_from_str(optarg, &cfg->log_level)) { fprintf(stderr, "%s: invalid log level '%s'\n", argv[0], optarg); return -1; }
            break;
        case 'R': cfg->allow_root = true; break;
        case 'v': printf("telnet-server %s\n", TN_VERSION); return 1;
        case 'h': usage(stdout, argv[0]); return 1;
        default:  usage(stderr, argv[0]); return -1;
        }
    }
    if (optind < argc) { fprintf(stderr, "%s: unexpected argument '%s'\n", argv[0], argv[optind]); usage(stderr, argv[0]); return -1; }

    if (access(cfg->shell, X_OK) != 0) { fprintf(stderr, "%s: cannot execute shell '%s'\n", argv[0], cfg->shell); return -1; }
    if (cfg->banner_file) {
        cfg->banner_text = load_file(cfg->banner_file);
        if (!cfg->banner_text) { perror(cfg->banner_file); return -1; }
    }
    return 0;
}

void server_config_free(server_config *cfg)
{
    free(cfg->banner_text);
    cfg->banner_text = NULL;
}
