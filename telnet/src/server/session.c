#include "session.h"
#include "log.h"
#include "net_util.h"
#include "telnet_proto.h"
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef __APPLE__
#include <util.h>
#else
#include <pty.h>
#endif

#define OUT_BUF_SIZE     65536
#define IN_BUF_SIZE      16384
#define NEGOTIATION_SECS 2
#define RECV_CHUNK       1024
#define SOCK_READ_GATE   2048     /* only read socket if to_pty has this much room */
#define PTY_READ_GATE    4096     /* only read PTY if to_client has this much room */

/* ---------- helpers ---------- */

static void mark_dead(session *s, const char *why)
{
    if (!s->dead) { LOGI("%s: session closed (%s)", s->peer, why); s->dead = true; }
}

static void queue_out(session *s, const uint8_t *d, size_t n)
{
    if (n && rb_write(&s->to_client, d, n) != n) mark_dead(s, "output buffer overflow");
}

static void flush_text(session *s, const uint8_t *tmp, size_t n)
{
    uint8_t enc[512 * 3];
    size_t m = tn_encode_data(&s->enc, tmp, n, enc, sizeof enc);
    queue_out(s, enc, m);
}

/* Queue human-readable text ("\n" becomes CR LF) for the client. */
static void queue_text(session *s, const char *txt)
{
    uint8_t tmp[512];
    size_t n = 0;
    for (; *txt; txt++) {
        if (n > sizeof tmp - 2) { flush_text(s, tmp, n); n = 0; }
        if (*txt == '\n') tmp[n++] = '\r';
        tmp[n++] = (uint8_t)*txt;
    }
    if (n) flush_text(s, tmp, n);
}

static void set_term(session *s, const uint8_t *d, size_t n)
{
    size_t j = 0;
    for (size_t i = 0; i < n && j < sizeof s->term - 1; i++) {
        uint8_t c = d[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '+')   /* no env/shell injection */
            s->term[j++] = (char)c;
    }
    s->term[j] = '\0';
}

static void apply_winsize(session *s)
{
    if (s->pty < 0) return;
    struct winsize ws = { .ws_row = s->rows, .ws_col = s->cols };
    ioctl(s->pty, TIOCSWINSZ, &ws);        /* kernel raises SIGWINCH for the shell */
}

static void release_pty(session *s)
{
    if (s->pty >= 0) { close(s->pty); s->pty = -1; }
    if (s->pid > 0)  { kill(s->pid, SIGHUP); s->pid = -1; }   /* SIGCHLD handler reaps */
}

static void to_pty_byte(session *s, uint8_t b) { rb_write(&s->to_pty, &b, 1); }

/* ---------- shell spawning ---------- */

static int spawn_shell(session *s)
{
    struct winsize ws = { .ws_row = s->rows, .ws_col = s->cols };
    int master;
    pid_t pid = forkpty(&master, NULL, NULL, &ws);
    if (pid < 0) { LOGE("%s: forkpty: %s", s->peer, strerror(errno)); return -1; }
    if (pid == 0) {
        signal(SIGINT, SIG_DFL);  signal(SIGTERM, SIG_DFL);
        signal(SIGPIPE, SIG_DFL); signal(SIGCHLD, SIG_DFL);
        setenv("TERM", s->term[0] ? s->term : "xterm", 1);
        const char *base = strrchr(s->cfg->shell, '/');
        base = base ? base + 1 : s->cfg->shell;
        execl(s->cfg->shell, base, (char *)NULL);
        _exit(127);
    }
    net_set_cloexec(master);
    net_set_nonblock(master, true);
    s->pty = master;
    s->pid = pid;
    LOGI("%s: shell started (pid %d, TERM=%s, %ux%u)", s->peer, (int)pid,
         s->term[0] ? s->term : "xterm", s->cols, s->rows);
    return 0;
}

static bool resolved(const session *s, uint8_t opt, bool got_data)
{
    return got_data || s->opts.him[opt] == Q_NO;      /* answered, or refused */
}

static void maybe_spawn(session *s, time_t now)
{
    if (s->spawned || s->closing || s->dead) return;
    bool ready = resolved(s, TNO_TTYPE, s->got_ttype) && resolved(s, TNO_NAWS, s->got_naws);
    if (!ready && now - s->created < NEGOTIATION_SECS) return;
    s->spawned = true;
    if (spawn_shell(s) < 0) {
        queue_text(s, "Failed to start shell.\n");
        s->closing = true;
    }
}

/* ---------- Telnet event handling ---------- */

static void handle_subneg(session *s, const tn_event *ev)
{
    if (ev->opt == TNO_NAWS && ev->len == 4) {
        uint16_t cols = (uint16_t)((ev->data[0] << 8) | ev->data[1]);
        uint16_t rows = (uint16_t)((ev->data[2] << 8) | ev->data[3]);
        s->cols = cols ? (cols > 1000 ? 1000 : cols) : 80;
        s->rows = rows ? (rows > 1000 ? 1000 : rows) : 24;
        s->got_naws = true;
        LOGD("%s: NAWS %ux%u", s->peer, s->cols, s->rows);
        apply_winsize(s);
    } else if (ev->opt == TNO_TTYPE && ev->len >= 1 && ev->data[0] == TNSB_IS) {
        set_term(s, ev->data + 1, ev->len - 1);
        s->got_ttype = true;
        LOGD("%s: TTYPE IS %s", s->peer, s->term);
    }
}

static void handle_cmd(session *s, uint8_t cmd)
{
    switch (cmd) {
    case TN_IP:
    case TN_BRK: to_pty_byte(s, 0x03); break;                 /* ^C */
    case TN_EC:  to_pty_byte(s, 0x7f); break;                 /* erase char */
    case TN_EL:  to_pty_byte(s, 0x15); break;                 /* kill line  */
    case TN_AYT: queue_text(s, "\n[Yes]\n"); break;
    default: break;                                           /* NOP, AO, GA, DM ignored */
    }
}

static void on_event(const tn_event *ev, void *user)
{
    session *s = user;
    if (s->dead) return;
    switch (ev->type) {
    case TN_EV_DATA:
        rb_write(&s->to_pty, ev->data, ev->len);
        break;
    case TN_EV_NEGOTIATE: {
        uint8_t reply[3];
        size_t  rl = 0;
        LOGT("%s: RCVD %s %s(%u)", s->peer, tn_cmd_name(ev->cmd), tn_opt_name(ev->opt), ev->opt);
        int changed = tn_opts_recv(&s->opts, ev->cmd, ev->opt, reply, &rl);
        queue_out(s, reply, rl);
        if (changed && ev->cmd == TN_WILL && ev->opt == TNO_TTYPE) {
            uint8_t b[16];
            queue_out(s, b, tn_encode_ttype_send(b, sizeof b));
        }
        break;
    }
    case TN_EV_SUBNEG: handle_subneg(s, ev); break;
    case TN_EV_CMD:    handle_cmd(s, ev->cmd); break;
    }
}

/* ---------- public API ---------- */

session *session_new(int sock, const char *peer, const server_config *cfg)
{
    session *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->sock = sock;
    s->pty  = -1;
    s->cfg  = cfg;
    s->cols = 80;
    s->rows = 24;
    s->created = s->last_activity = time(NULL);
    snprintf(s->peer, sizeof s->peer, "%s", peer);

    s->parser = tn_parser_new(true);
    if (!s->parser || rb_init(&s->to_client, OUT_BUF_SIZE) < 0 ||
        rb_init(&s->to_pty, IN_BUF_SIZE) < 0) {
        session_free(s);
        return NULL;
    }
    tn_encoder_init(&s->enc);
    tn_opts_init(&s->opts);
    tn_opts_allow(&s->opts, TNO_ECHO,  true,  false);   /* we echo; client must not */
    tn_opts_allow(&s->opts, TNO_SGA,   true,  true);
    tn_opts_allow(&s->opts, TNO_NAWS,  false, true);
    tn_opts_allow(&s->opts, TNO_TTYPE, false, true);

    uint8_t b[3];
    queue_out(s, b, tn_opts_ask_us(&s->opts,  TNO_ECHO,  true, b));
    queue_out(s, b, tn_opts_ask_us(&s->opts,  TNO_SGA,   true, b));
    queue_out(s, b, tn_opts_ask_him(&s->opts, TNO_SGA,   true, b));
    queue_out(s, b, tn_opts_ask_him(&s->opts, TNO_NAWS,  true, b));
    queue_out(s, b, tn_opts_ask_him(&s->opts, TNO_TTYPE, true, b));
    if (cfg->banner_text) queue_text(s, cfg->banner_text);
    return s;
}

void session_free(session *s)
{
    if (!s) return;
    release_pty(s);
    if (s->sock >= 0) close(s->sock);
    tn_parser_free(s->parser);
    rb_free(&s->to_client);
    rb_free(&s->to_pty);
    free(s);
}

short session_sock_events(const session *s)
{
    short ev = 0;
    if (!s->closing && rb_space(&s->to_pty) >= SOCK_READ_GATE) ev |= POLLIN;
    if (rb_len(&s->to_client) > 0) ev |= POLLOUT;
    return ev;
}

short session_pty_events(const session *s)
{
    if (s->pty < 0) return 0;
    short ev = 0;
    if (rb_space(&s->to_client) >= PTY_READ_GATE) ev |= POLLIN;
    if (rb_len(&s->to_pty) > 0) ev |= POLLOUT;
    return ev;
}

static void sock_writable(session *s)
{
    size_t n;
    const uint8_t *p = rb_peek(&s->to_client, &n);
    if (n == 0) return;
    ssize_t w = send(s->sock, p, n, MSG_NOSIGNAL);
    if (w > 0) rb_consume(&s->to_client, (size_t)w);
    else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        mark_dead(s, strerror(errno));
}

static void sock_readable(session *s)
{
    uint8_t buf[RECV_CHUNK];
    ssize_t n = recv(s->sock, buf, sizeof buf, 0);
    if (n == 0) { mark_dead(s, "peer closed"); return; }
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) mark_dead(s, strerror(errno));
        return;
    }
    s->last_activity = time(NULL);
    tn_parser_feed(s->parser, buf, (size_t)n, on_event, s);
    maybe_spawn(s, s->last_activity);
}

void session_handle_sock(session *s, short revents)
{
    if (s->dead) return;
    if (revents & (POLLERR | POLLNVAL)) { mark_dead(s, "socket error"); return; }
    if (revents & POLLOUT) sock_writable(s);
    if (s->dead) return;
    if (revents & POLLIN) sock_readable(s);
    else if (revents & POLLHUP) mark_dead(s, "peer hung up");
}

static void pty_readable(session *s)
{
    uint8_t in[1024], out[1024 * 3];
    ssize_t n = read(s->pty, in, sizeof in);
    if (n > 0) {
        size_t m = tn_encode_data(&s->enc, in, (size_t)n, out, sizeof out);
        queue_out(s, out, m);
        return;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
    /* EOF or EIO: the shell exited */
    LOGI("%s: shell exited", s->peer);
    release_pty(s);
    queue_text(s, "\nConnection closed by server.\n");
    s->closing = true;
}

static void pty_writable(session *s)
{
    size_t n;
    const uint8_t *p = rb_peek(&s->to_pty, &n);
    if (n == 0) return;
    ssize_t w = write(s->pty, p, n);
    if (w > 0) rb_consume(&s->to_pty, (size_t)w);
    else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        release_pty(s);
        s->closing = true;
    }
}

void session_handle_pty(session *s, short revents)
{
    if (s->dead || s->pty < 0) return;
    if (revents & POLLOUT) pty_writable(s);
    if (s->pty >= 0 && (revents & (POLLIN | POLLHUP | POLLERR))) pty_readable(s);
}

void session_tick(session *s, time_t now)
{
    if (s->dead) return;
    maybe_spawn(s, now);
    if (s->cfg->idle_timeout > 0 && !s->closing &&
        now - s->last_activity >= s->cfg->idle_timeout) {
        LOGI("%s: idle timeout", s->peer);
        queue_text(s, "\nIdle timeout, closing connection.\n");
        release_pty(s);
        s->closing = true;
    }
    if (s->closing && rb_len(&s->to_client) == 0) mark_dead(s, "finished");
}
