#include "buffer.h"
#include <stdlib.h>
#include <string.h>

int rb_init(ring_buf *rb, size_t cap)
{
    memset(rb, 0, sizeof *rb);
    if (cap == 0) return -1;
    rb->data = malloc(cap);
    if (!rb->data) return -1;
    rb->cap = cap;
    return 0;
}

void rb_free(ring_buf *rb)
{
    free(rb->data);
    memset(rb, 0, sizeof *rb);
}

size_t rb_len(const ring_buf *rb)   { return rb->len; }
size_t rb_space(const ring_buf *rb) { return rb->cap - rb->len; }

size_t rb_write(ring_buf *rb, const uint8_t *src, size_t n)
{
    if (n > rb_space(rb)) n = rb_space(rb);
    if (n == 0) return 0;
    size_t tail  = (rb->head + rb->len) % rb->cap;
    size_t first = rb->cap - tail;
    if (first > n) first = n;
    memcpy(rb->data + tail, src, first);
    memcpy(rb->data, src + first, n - first);
    rb->len += n;
    return n;
}

const uint8_t *rb_peek(const ring_buf *rb, size_t *contig)
{
    size_t c = rb->cap - rb->head;
    *contig = rb->len < c ? rb->len : c;
    return rb->data + rb->head;
}

void rb_consume(ring_buf *rb, size_t n)
{
    if (n > rb->len) n = rb->len;
    rb->head = (rb->head + n) % rb->cap;
    rb->len -= n;
    if (rb->len == 0) rb->head = 0;
}
