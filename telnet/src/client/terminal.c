#include "terminal.h"
#include <stdlib.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

static struct termios g_saved;
static bool g_have_saved;
static bool g_raw;
static bool g_atexit_set;

int term_raw_enter(void)
{
    if (!g_have_saved) {
        if (tcgetattr(STDIN_FILENO, &g_saved) < 0) return -1;
        g_have_saved = true;
    }
    struct termios raw = g_saved;
    cfmakeraw(&raw);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0) return -1;
    g_raw = true;
    if (!g_atexit_set) { atexit(term_raw_leave); g_atexit_set = true; }
    return 0;
}

void term_raw_leave(void)
{
    if (g_raw && g_have_saved) tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved);
    g_raw = false;
}

bool term_in_raw(void) { return g_raw; }

void term_size(uint16_t *cols, uint16_t *rows)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        *cols = ws.ws_col;
        *rows = ws.ws_row;
    } else {
        *cols = 80;
        *rows = 24;
    }
}
