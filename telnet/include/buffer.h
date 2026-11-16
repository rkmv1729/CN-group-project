/* Fixed-capacity byte ring buffer. */
#ifndef BUFFER_H
#define BUFFER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t   cap, head, len;
} ring_buf;

int           rb_init(ring_buf *rb, size_t cap);          /* 0 ok, -1 error */
void          rb_free(ring_buf *rb);
size_t        rb_len(const ring_buf *rb);
size_t        rb_space(const ring_buf *rb);
size_t        rb_write(ring_buf *rb, const uint8_t *src, size_t n); /* returns bytes stored */
const uint8_t *rb_peek(const ring_buf *rb, size_t *contig);       /* contiguous readable chunk */
void          rb_consume(ring_buf *rb, size_t n);

#endif
