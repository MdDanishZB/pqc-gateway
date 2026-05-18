#include "multihoming.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/sctp.h>

/* ── timing helper (local, mirrors metrics.c) ───────────────────────────── */

static double mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* ── address helpers ────────────────────────────────────────────────────── */

static void fill_addr(struct sockaddr_in *a, const char *ip, int port)
{
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &a->sin_addr);
}

/* ── server ─────────────────────────────────────────────────────────────── */

int multihome_server_create(const char *primary_ip,
                             const char *secondary_ip,
                             int         port)
{
    int fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (fd < 0) { perror("[MH] SCTP socket"); return -1; }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind primary address */
    struct sockaddr_in primary;
    fill_addr(&primary, primary_ip, port);

    if (bind(fd, (struct sockaddr *)&primary, sizeof(primary)) < 0) {
        perror("[MH] bind primary");
        close(fd);
        return -1;
    }

    /* Add secondary address via sctp_bindx */
    struct sockaddr_in secondary;
    fill_addr(&secondary, secondary_ip, port);

    if (sctp_bindx(fd, (struct sockaddr *)&secondary, 1,
                   SCTP_BINDX_ADD_ADDR) < 0) {
        /* Non-fatal: secondary path unavailable, continue single-homed */
        perror("[MH] sctp_bindx secondary (non-fatal, continuing single-homed)");
    } else {
        printf("[MH] Server bound: %s:%d (primary) + %s:%d (secondary)\n",
               primary_ip, port, secondary_ip, port);
    }

    if (listen(fd, 5) < 0) {
        perror("[MH] listen");
        close(fd);
        return -1;
    }

    return fd;
}

/* ── client ─────────────────────────────────────────────────────────────── */

int multihome_client_connect(const char *primary_ip,
                              const char *secondary_ip,
                              int         port,
                              double     *latency_ms_out)
{
    int fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (fd < 0) { perror("[MH] SCTP socket"); return -1; }

    /*
     * sctp_connectx() sends INIT with both peer addresses so the SCTP
     * association is multi-homed from the very first handshake chunk.
     */
    struct sockaddr_in addrs[2];
    fill_addr(&addrs[0], primary_ip,   port);
    fill_addr(&addrs[1], secondary_ip, port);

    sctp_assoc_t assoc_id = 0;
    double t0 = mono_ms();

    int rc = sctp_connectx(fd, (struct sockaddr *)addrs, 2, &assoc_id);

    double elapsed = mono_ms() - t0;

    if (rc < 0) {
        /* sctp_connectx may return EINPROGRESS; treat as partial success
         * only if the secondary address was unreachable.  A real failure
         * (primary also down) surfaces as ECONNREFUSED. */
        perror("[MH] sctp_connectx");
        close(fd);
        return -1;
    }

    if (latency_ms_out) *latency_ms_out = elapsed;

    printf("[MH] Client connected: primary=%s secondary=%s  latency=%.3fms\n",
           primary_ip, secondary_ip, elapsed);

    return fd;
}

/* ── heartbeat ──────────────────────────────────────────────────────────── */

int enable_sctp_heartbeat(int fd, int interval_ms)
{
    struct sctp_paddrparams hb;
    memset(&hb, 0, sizeof(hb));
    hb.spp_assoc_id  = 0;              /* apply to all associations */
    hb.spp_flags     = SPP_HB_ENABLE;
    hb.spp_hbinterval = (interval_ms > 0) ? (uint32_t)interval_ms : 1000;

    if (setsockopt(fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
                   &hb, sizeof(hb)) < 0) {
        perror("[MH] enable heartbeat");
        return -1;
    }

    printf("[MH] Heartbeat enabled (interval=%d ms)\n", hb.spp_hbinterval);
    return 0;
}

/* ── path status query ──────────────────────────────────────────────────── */

const char *path_state_str(PathState s)
{
    switch (s) {
        case PATH_ACTIVE:      return "ACTIVE";
        case PATH_INACTIVE:    return "INACTIVE";
        case PATH_UNCONFIRMED: return "UNCONFIRMED";
        default:               return "UNKNOWN";
    }
}

int get_path_status(int fd, const char *peer_ip, int port,
                    PathStatus *out)
{
    struct sctp_paddrinfo pinfo;
    memset(&pinfo, 0, sizeof(pinfo));

    struct sockaddr_in *addr =
        (struct sockaddr_in *)&pinfo.spinfo_address;
    fill_addr(addr, peer_ip, port);

    socklen_t len = sizeof(pinfo);
    if (getsockopt(fd, IPPROTO_SCTP, SCTP_GET_PEER_ADDR_INFO,
                   &pinfo, &len) < 0) {
        perror("[MH] SCTP_GET_PEER_ADDR_INFO");
        return -1;
    }

    strncpy(out->ip, peer_ip, sizeof(out->ip) - 1);
    out->rtt_ms = pinfo.spinfo_srtt;
    out->cwnd   = pinfo.spinfo_cwnd;

    switch (pinfo.spinfo_state) {
        case SCTP_ACTIVE:      out->state = PATH_ACTIVE;      break;
        case SCTP_INACTIVE:    out->state = PATH_INACTIVE;    break;
        case SCTP_UNCONFIRMED: out->state = PATH_UNCONFIRMED; break;
        default:               out->state = PATH_UNKNOWN;     break;
    }

    return 0;
}

/* ── path switching ─────────────────────────────────────────────────────── */

int switch_primary_path(int fd, const char *new_ip, int port)
{
    struct sctp_setprim prim;
    memset(&prim, 0, sizeof(prim));
    prim.ssp_assoc_id = 0;

    struct sockaddr_in *addr = (struct sockaddr_in *)&prim.ssp_addr;
    fill_addr(addr, new_ip, port);

    if (setsockopt(fd, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
                   &prim, sizeof(prim)) < 0) {
        perror("[MH] switch primary path");
        return -1;
    }

    printf("[MH] Primary path switched to %s:%d\n", new_ip, port);
    return 0;
}
