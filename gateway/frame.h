#ifndef FRAME_H
#define FRAME_H

/*
 * Length-prefixed message framing over the SCTP one-to-one (SOCK_STREAM) socket.
 *
 * The streaming relay (Phase 3 / Workstream C) carries MANY messages over ONE
 * long-lived association, so we cannot rely on recv() boundaries. Each message is
 * sent as [4-byte big-endian length][payload]. Header-only (static inline) so both
 * the gateway and the receiver share it with no extra Makefile object.
 *
 * NOTE: framing starts AFTER the PQC handshake (which uses its own fixed-size reads).
 */
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>

static inline int frame_write(int fd, const void *buf, uint32_t len)
{
    uint32_t n = htonl(len);
    uint8_t *hp = (uint8_t *)&n;
    size_t off = 0;
    while (off < 4) { ssize_t w = write(fd, hp + off, 4 - off); if (w <= 0) return -1; off += (size_t)w; }
    const uint8_t *p = (const uint8_t *)buf;
    off = 0;
    while (off < len) { ssize_t w = write(fd, p + off, len - off); if (w <= 0) return -1; off += (size_t)w; }
    return 0;
}

/* Returns 0 and sets *out_len on success; -1 on EOF/error or oversized frame. */
static inline int frame_read(int fd, void *buf, uint32_t cap, uint32_t *out_len)
{
    uint32_t n;
    uint8_t *hp = (uint8_t *)&n;
    size_t off = 0;
    while (off < 4) { ssize_t r = read(fd, hp + off, 4 - off); if (r <= 0) return -1; off += (size_t)r; }
    uint32_t len = ntohl(n);
    if (len > cap) return -1;
    uint8_t *p = (uint8_t *)buf;
    off = 0;
    while (off < len) { ssize_t r = read(fd, p + off, len - off); if (r <= 0) return -1; off += (size_t)r; }
    *out_len = len;
    return 0;
}

#endif /* FRAME_H */
