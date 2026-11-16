#include "log.h"
#include "server.h"
#include "server_config.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void on_stop(int sig) { (void)sig; server_request_stop(); }

static void on_child(int sig)
{
    (void)sig;
    int saved = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) { }
    errno = saved;
}

static void install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = on_stop;                    /* no SA_RESTART: poll() must wake up */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sa.sa_handler = on_child;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);
}

static int is_loopback(const char *a)
{
    return !strcmp(a, "127.0.0.1") || !strcmp(a, "::1") || !strcmp(a, "localhost");
}

int main(int argc, char **argv)
{
    server_config cfg;
    int pr = server_parse_args(argc, argv, &cfg);
    if (pr != 0) return pr > 0 ? 0 : 2;

    if (log_init(cfg.log_file, cfg.log_level) < 0) {
        perror(cfg.log_file);
        server_config_free(&cfg);
        return 1;
    }
    if (geteuid() == 0 && !cfg.allow_root) {
        LOGE("refusing to run as root (a Telnet shell would be a root shell); use -R to override");
        server_config_free(&cfg);
        return 1;
    }
    if (!is_loopback(cfg.bind_addr))
        LOGW("binding to %s: traffic, including passwords, is sent in plaintext", cfg.bind_addr);

    install_signals();
    int rc = server_run(&cfg);

    log_close();
    server_config_free(&cfg);
    return rc == 0 ? 0 : 1;
}
