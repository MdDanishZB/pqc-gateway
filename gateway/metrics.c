#include "metrics.h"

#include <time.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>

/* ── timing helper ───────────────────────────────────────────────────────── */

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* ── timed connect ───────────────────────────────────────────────────────── */

double timed_connect(int fd, struct sockaddr *addr, socklen_t addrlen)
{
    double t0 = now_ms();
    if (connect(fd, addr, addrlen) < 0)
        return -1.0;
    return now_ms() - t0;
}

/* ── jitter (RFC 3550 §A.8) ─────────────────────────────────────────────── */

static pthread_mutex_t jitter_mtx  = PTHREAD_MUTEX_INITIALIZER;
static double          last_lat_ms = 0.0;
static int             jitter_init = 0;

double update_jitter(double latency_ms)
{
    pthread_mutex_lock(&jitter_mtx);
    double jitter = 0.0;
    if (jitter_init) {
        double delta = latency_ms - last_lat_ms;
        jitter = delta < 0.0 ? -delta : delta;
    }
    last_lat_ms = latency_ms;
    jitter_init = 1;
    pthread_mutex_unlock(&jitter_mtx);
    return jitter;
}

double get_last_latency_ms(void)
{
    pthread_mutex_lock(&jitter_mtx);
    double v = last_lat_ms;
    pthread_mutex_unlock(&jitter_mtx);
    return v;
}

/* ── rolling packet-loss window ─────────────────────────────────────────── */

#define LOSS_WINDOW 100

static pthread_mutex_t loss_mtx    = PTHREAD_MUTEX_INITIALIZER;
static int             loss_buf[LOSS_WINDOW];
static int             loss_head   = 0;
static int             loss_filled = 0;

void record_send_result(int success)
{
    pthread_mutex_lock(&loss_mtx);
    loss_buf[loss_head] = success;
    loss_head = (loss_head + 1) % LOSS_WINDOW;
    if (loss_filled < LOSS_WINDOW) loss_filled++;
    pthread_mutex_unlock(&loss_mtx);
}

double get_packet_loss_pct(void)
{
    pthread_mutex_lock(&loss_mtx);
    if (loss_filled == 0) { pthread_mutex_unlock(&loss_mtx); return 0.0; }
    int failures = 0;
    for (int i = 0; i < loss_filled; i++) {
        int idx = (loss_head - loss_filled + i + LOSS_WINDOW) % LOSS_WINDOW;
        if (!loss_buf[idx]) failures++;
    }
    double pct = (double)failures / loss_filled * 100.0;
    pthread_mutex_unlock(&loss_mtx);
    return pct;
}

/* ── inter-arrival time ─────────────────────────────────────────────────── */

static pthread_mutex_t iat_mtx   = PTHREAD_MUTEX_INITIALIZER;
static double          last_arrival_ms = 0.0;
static int             iat_init  = 0;

double measure_iat_ms(void)
{
    double now = now_ms();
    pthread_mutex_lock(&iat_mtx);
    double iat = 0.0;
    if (iat_init)
        iat = now - last_arrival_ms;
    last_arrival_ms = now;
    iat_init = 1;
    pthread_mutex_unlock(&iat_mtx);
    return iat;
}

/* ── bandwidth EMA ──────────────────────────────────────────────────────── */

/*
 * Reference link: 1 MB/s — realistic for a loopback SCTP test.
 * Raise this for production (e.g. 100 MB/s Ethernet).
 */
#define REF_BANDWIDTH_BPS 1000000.0
#define EMA_ALPHA         0.3

static pthread_mutex_t bw_mtx       = PTHREAD_MUTEX_INITIALIZER;
static double          ema_bps      = 0.0;

void update_bandwidth_ema(int bytes, double elapsed_ms)
{
    if (elapsed_ms <= 0.0) return;
    double bps = bytes / (elapsed_ms / 1000.0);
    pthread_mutex_lock(&bw_mtx);
    ema_bps = EMA_ALPHA * bps + (1.0 - EMA_ALPHA) * ema_bps;
    pthread_mutex_unlock(&bw_mtx);
}

double get_bandwidth_util_pct(void)
{
    pthread_mutex_lock(&bw_mtx);
    double v = ema_bps;
    pthread_mutex_unlock(&bw_mtx);
    double pct = (v / REF_BANDWIDTH_BPS) * 100.0;
    return pct > 100.0 ? 100.0 : pct;
}
