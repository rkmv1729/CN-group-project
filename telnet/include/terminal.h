#ifndef TERMINAL_H
#define TERMINAL_H

#include <stdbool.h>
#include <stdint.h>

int  term_raw_enter(void);                 /* 0 ok, -1 if stdin is not a tty */
void term_raw_leave(void);                 /* restore saved termios (idempotent) */
bool term_in_raw(void);
void term_size(uint16_t *cols, uint16_t *rows);   /* falls back to 80x24 */

#endif
