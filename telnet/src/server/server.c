#include "server.h"
#include "log.h"
#include "net_util.h"
#include "session.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;

void server_request_stop(void) { g_stop = 1; }

struct ref { session *s; int kind; };    /* kind 0 = socket, 1 = pty */

typedef struct {
    const server_config *cfg;
    session *head;
    int      count;
} server_ctx;

static void accept_clients(server_ctx *sv, int lfd)
{
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        int fd = accept4(lfd, (struct sockaddr *)&ss, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR || errno == ECONNABORTED) continue;
            LOGW("accept: %s", strerror(errno));
            return;
        }
        char peer[64];
        net_peer_name((struct sockaddr *)&ss, sl, peer, sizeof peer);

        if (sv->count >= sv->cfg->max_clients) {
            static const char msg[] = "Server busy, try again later.\r\n";
            send(fd, msg, sizeof msg - 1, MSG_NOSIGNAL);
            close(fd);
            LOGW("%s: rejected (max clients reached)", peer);
            continue;
        }
        net_set_nodelay(fd);
        session *s = session_new(fd, peer, sv->cfg);
        if (!s) { close(fd); LOGE("%s: out of memory", peer); continue; }
        s->next = sv->head;
        sv->head = s;
        sv->count++;
        LOGI("%s: connected (%d active)", peer, sv->count);
    }
}

static void reap_sessions(server_ctx *sv, time_t now)
{
    session **pp = &sv->head;
    while (*pp) {
        session *s = *pp;
        session_tick(s, now);
        if (s->dead) {
            *pp = s->next;
            session_free(s);
            sv->count--;
        } else {
            pp = &s->next;
        }
    }
}

int server_run(const server_config *cfg)
{
    int lfd = net_listen(cfg->bind_addr, cfg->port, 64);
    if (lfd < 0) return -1;

    size_t maxp = 1 + 2 * (size_t)cfg->max_clients;
    struct pollfd *pfds = calloc(maxp, sizeof *pfds);
    struct ref    *refs = calloc(maxp, sizeof *refs);
    if (!pfds || !refs) { close(lfd); free(pfds); free(refs); return -1; }

    server_ctx sv = { .cfg = cfg };
    LOGI("listening on %s port %u (max %d clients, shell %s)",
         cfg->bind_addr, (unsigned)cfg->port, cfg->max_clients, cfg->shell);

    int rc = 0;
    while (!g_stop) {
        size_t np = 0;
        pfds[np] = (struct pollfd){ .fd = lfd, .events = POLLIN };
        refs[np] = (struct ref){ NULL, 0 };
        np++;
        for (session *s = sv.head; s; s = s->next) {
            pfds[np] = (struct pollfd){ .fd = s->sock, .events = session_sock_events(s) };
            refs[np] = (struct ref){ s, 0 };
            np++;
            short pe = session_pty_events(s);
            if (pe) {
                pfds[np] = (struct pollfd){ .fd = s->pty, .events = pe };
                refs[np] = (struct ref){ s, 1 };
                np++;
            }
        }

        int r = poll(pfds, (nfds_t)np, 250);
        if (r < 0) {
            if (errno == EINTR) continue;
            LOGE("poll: %s", strerror(errno));
            rc = -1;
            break;
        }
        if (r > 0) {
            if (pfds[0].revents & POLLIN) accept_clients(&sv, lfd);
            for (size_t i = 1; i < np; i++) {
                if (!pfds[i].revents) continue;
                if (refs[i].kind == 0) session_handle_sock(refs[i].s, pfds[i].revents);
                else                   session_handle_pty(refs[i].s, pfds[i].revents);
            }
        }
        reap_sessions(&sv, time(NULL));
    }

    LOGI("shutting down (%d session(s))", sv.count);
    while (sv.head) {
        session *s = sv.head;
        sv.head = s->next;
        session_free(s);
    }
    close(lfd);
    free(pfds);
    free(refs);
    return rc;
}
