#include "client.h"
#include "log.h"
#include "net_util.h"
#include "terminal.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t g_winch, g_term;
static void on_winch(int s) { (void)s; g_winch = 1; }
static void on_term(int s)  { (void)s; g_term = 1; }

void client_debug(const client *c, const char *fmt, ...)
{
    if (!c->cfg->debug) return;
    va_list ap;
    va_start(ap, fmt);
    fputs("[telnet] ", stderr);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputs(term_in_raw() ? "\r\n" : "\n", stderr);
}

/* ---------- I/O helpers ---------- */

static int write_all(int fd, const uint8_t *p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) { struct pollfd pf = { fd, POLLOUT, 0 }; poll(&pf, 1, -1); continue; }
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static void send_bytes(client *c, const uint8_t *p, size_t n)
{
    while (n && !c->quit) {
        ssize_t w = send(c->sock, p, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            c->peer_closed = true;
            c->quit = true;
            return;
        }
        p += w;
        n -= (size_t)w;
    }
}

void client_send_cmd(client *c, uint8_t cmd)
{
    uint8_t b[2];
    send_bytes(c, b, tn_encode_cmd(cmd, b));
    client_debug(c, "SENT %s", tn_cmd_name(cmd));
}

static void send_naws(client *c)
{
    if (!tn_opts_us_on(&c->opts, TNO_NAWS)) return;
    uint16_t cols, rows;
    term_size(&cols, &rows);
    uint8_t b[16];
    send_bytes(c, b, tn_encode_naws(cols, rows, b, sizeof b));
    client_debug(c, "SENT SB NAWS %ux%u", cols, rows);
}

static void send_ttype(client *c)
{
    uint8_t b[96];
    send_bytes(c, b, tn_encode_ttype_is(c->term, b, sizeof b));
    client_debug(c, "SENT SB TTYPE IS %s", c->term);
}

/* ---------- incoming events ---------- */

static void on_event(const tn_event *ev, void *user)
{
    client *c = user;
    switch (ev->type) {
    case TN_EV_DATA:
        if (write_all(STDOUT_FILENO, ev->data, ev->len) < 0) c->quit = true;
        break;
    case TN_EV_NEGOTIATE: {
        uint8_t reply[3];
        size_t  rl = 0;
        client_debug(c, "RCVD %s %s(%u)", tn_cmd_name(ev->cmd), tn_opt_name(ev->opt), ev->opt);
        int changed = tn_opts_recv(&c->opts, ev->cmd, ev->opt, reply, &rl);
        if (rl) {
            send_bytes(c, reply, rl);
            client_debug(c, "SENT %s %s(%u)", tn_cmd_name(reply[1]), tn_opt_name(reply[2]), reply[2]);
        }
        if (ev->opt == TNO_ECHO)        /* server echoing -> stop local echo */
            c->local_echo = !tn_opts_him_on(&c->opts, TNO_ECHO) && c->stdin_tty;
        if (changed && ev->cmd == TN_DO && ev->opt == TNO_NAWS) send_naws(c);
        break;
    }
    case TN_EV_SUBNEG:
        client_debug(c, "RCVD SB %s(%u) len=%zu", tn_opt_name(ev->opt), ev->opt, ev->len);
        if (ev->opt == TNO_TTYPE && ev->len >= 1 && ev->data[0] == TNSB_SEND &&
            tn_opts_us_on(&c->opts, TNO_TTYPE))
            send_ttype(c);
        break;
    case TN_EV_CMD:
        client_debug(c, "RCVD %s", tn_cmd_name(ev->cmd));
        break;
    }
}

/* ---------- outgoing user input ---------- */

static void send_user_bytes(client *c, const uint8_t *p, size_t n)
{
    if (n == 0 || c->quit) return;
    if (c->local_echo) {
        for (size_t i = 0; i < n; i++) {
            if (p[i] == '\r') write_all(STDOUT_FILENO, (const uint8_t *)"\r\n", 2);
            else              write_all(STDOUT_FILENO, &p[i], 1);
        }
    }
    uint8_t out[512 * 3];
    while (n) {
        size_t chunk = n > 512 ? 512 : n;
        size_t m = tn_encode_data(&c->enc, p, chunk, out, sizeof out);
        send_bytes(c, out, m);
        p += chunk;
        n -= chunk;
    }
}

static void handle_stdin(client *c)
{
    uint8_t buf[512];
    ssize_t n = read(STDIN_FILENO, buf, sizeof buf);
    if (n == 0) {
        if (c->stdin_tty) c->quit = true;
        else c->stdin_open = false;         /* piped input done: keep reading the server */
        return;
    }
    if (n < 0) {
        if (errno != EINTR && errno != EAGAIN) c->quit = true;
        return;
    }
    size_t start = 0;
    for (size_t i = 0; i < (size_t)n && !c->quit; i++) {
        if (c->stdin_tty && c->cfg->escape >= 0 && buf[i] == (uint8_t)c->cfg->escape) {
            send_user_bytes(c, buf + start, i - start);
            ui_command_mode(c);
            start = i + 1;
        }
    }
    if (!c->quit) send_user_bytes(c, buf + start, (size_t)n - start);
}

static void handle_socket(client *c)
{
    uint8_t buf[4096];
    ssize_t n = recv(c->sock, buf, sizeof buf, 0);
    if (n == 0) { c->peer_closed = true; c->quit = true; return; }
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN) return;
        c->peer_closed = true;
        c->quit = true;
        return;
    }
    tn_parser_feed(c->parser, buf, (size_t)n, on_event, c);
}

/* ---------- main loop ---------- */

static void escape_name(int ch, char *out, size_t cap)
{
    if (ch < 32) snprintf(out, cap, "^%c", ch + 64);
    else if (ch == 0x7f) snprintf(out, cap, "^?");
    else snprintf(out, cap, "%c", ch);
}

int client_run(const client_config *cfg)
{
    log_init(NULL, LOGLVL_WARN);

    client c;
    memset(&c, 0, sizeof c);
    c.cfg = cfg;
    c.stdin_tty = isatty(STDIN_FILENO);
    c.stdin_open = true;
    c.local_echo = c.stdin_tty;
    const char *t = cfg->term ? cfg->term : getenv("TERM");
    snprintf(c.term, sizeof c.term, "%s", t && *t ? t : "UNKNOWN");

    c.sock = net_connect(cfg->host, cfg->port, cfg->family, cfg->connect_timeout);
    if (c.sock < 0) return 1;

    fprintf(stderr, "Connected to %s port %s.\n", cfg->host, cfg->port);
    if (c.stdin_tty && cfg->escape >= 0) {
        char en[8];
        escape_name(cfg->escape, en, sizeof en);
        fprintf(stderr, "Escape character is '%s'.\n", en);
    }

    c.parser = tn_parser_new(false);
    if (!c.parser) { close(c.sock); return 1; }
    tn_encoder_init(&c.enc);
    tn_opts_init(&c.opts);
    tn_opts_allow(&c.opts, TNO_NAWS,  true,  false);
    tn_opts_allow(&c.opts, TNO_TTYPE, true,  false);
    tn_opts_allow(&c.opts, TNO_SGA,   true,  true);
    tn_opts_allow(&c.opts, TNO_ECHO,  false, true);     /* server may echo; we never echo for it */

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = on_winch; sigaction(SIGWINCH, &sa, NULL);
    sa.sa_handler = on_term;  sigaction(SIGTERM, &sa, NULL); sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = SIG_IGN;  sigaction(SIGPIPE, &sa, NULL);

    uint8_t b[3];
    send_bytes(&c, b, tn_opts_ask_us(&c.opts,  TNO_NAWS,  true, b));
    send_bytes(&c, b, tn_opts_ask_us(&c.opts,  TNO_TTYPE, true, b));
    send_bytes(&c, b, tn_opts_ask_him(&c.opts, TNO_SGA,   true, b));

    if (c.stdin_tty) term_raw_enter();

    while (!c.quit && !g_term) {
        struct pollfd p[2] = {
            { .fd = c.stdin_open ? STDIN_FILENO : -1, .events = POLLIN },
            { .fd = c.sock, .events = POLLIN }
        };
        int r = poll(p, 2, -1);
        if (g_winch) { g_winch = 0; send_naws(&c); }
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (p[1].revents & (POLLIN | POLLHUP | POLLERR)) handle_socket(&c);
        if (!c.quit && (p[0].revents & (POLLIN | POLLHUP))) handle_stdin(&c);
    }

    term_raw_leave();
    close(c.sock);
    tn_parser_free(c.parser);
    if (c.peer_closed) fprintf(stderr, "Connection closed by foreign host.\n");
    return 0;
}
