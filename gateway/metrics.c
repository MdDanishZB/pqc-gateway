#include "metrics.h"

#include <time.h>
#include <math.h>
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

/* ── last-session throughput (payload bytes) ────────────────────────────── */

static pthread_mutex_t thru_mtx        = PTHREAD_MUTEX_INITIALIZER;
static double          last_thru_bytes = 0.0;

void record_throughput_bytes(int bytes)
{
    pthread_mutex_lock(&thru_mtx);
    last_thru_bytes = (double)bytes;
    pthread_mutex_unlock(&thru_mtx);
}

double get_last_throughput_bytes(void)
{
    pthread_mutex_lock(&thru_mtx);
    double v = last_thru_bytes;
    pthread_mutex_unlock(&thru_mtx);
    return v;
}

/* ── sliding-window flow features (Phase 3 / Workstream B) ──────────────── */

static double now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static pthread_mutex_t win_mtx = PTHREAD_MUTEX_INITIALIZER;
static double          win_ts[FEATURE_WINDOW];   /* arrival timestamps (us) */
static int             win_sz[FEATURE_WINDOW];   /* packet sizes (bytes)    */
static int             win_head  = 0;            /* next write slot         */
static int             win_count = 0;            /* filled (<= FEATURE_WINDOW) */

void record_packet(int size_bytes)
{
    double t = now_us();
    pthread_mutex_lock(&win_mtx);
    win_ts[win_head] = t;
    win_sz[win_head] = size_bytes;
    win_head = (win_head + 1) % FEATURE_WINDOW;
    if (win_count < FEATURE_WINDOW) win_count++;
    pthread_mutex_unlock(&win_mtx);
}

void get_window_features(double out[6])
{
    pthread_mutex_lock(&win_mtx);
    int n = win_count;

    if (n < 2) {                       /* need >= 2 arrivals for an IAT */
        pthread_mutex_unlock(&win_mtx);
        for (int i = 0; i < 6; i++) out[i] = 0.0;
        return;
    }

    int    start   = (win_head - n + FEATURE_WINDOW) % FEATURE_WINDOW;  /* oldest */
    double first_ts = win_ts[start];
    double last_ts  = win_ts[(win_head - 1 + FEATURE_WINDOW) % FEATURE_WINDOW];
    double span_us  = last_ts - first_ts;

    double    sum_iat = 0.0, sum_iat2 = 0.0;
    long long total_bytes = 0;
    double    prev = first_ts;
    for (int i = 0; i < n; i++) {
        int idx = (start + i) % FEATURE_WINDOW;
        total_bytes += win_sz[idx];
        if (i > 0) {
            double gap = win_ts[idx] - prev;
            sum_iat  += gap;
            sum_iat2 += gap * gap;
            prev = win_ts[idx];
        }
    }
    pthread_mutex_unlock(&win_mtx);

    int    gaps     = n - 1;
    double iat_mean = sum_iat / gaps;
    double var      = (sum_iat2 / gaps) - (iat_mean * iat_mean);
    if (var < 0.0) var = 0.0;          /* guard FP round-off */
    double span_s   = span_us / 1e6;

    out[0] = iat_mean;                                  /* iat_mean      (us)   */
    out[1] = sqrt(var);                                 /* iat_std       (us)   */
    out[2] = (span_s > 0.0) ? (double)n / span_s : 0.0; /* pkt_rate      (/s)   */
    out[3] = (span_s > 0.0) ? (double)total_bytes / span_s : 0.0; /* byte_rate  */
    out[4] = (double)total_bytes / n;                   /* mean_pkt_size (bytes)*/
    out[5] = span_us;                                   /* flow_duration (us)   */
}
