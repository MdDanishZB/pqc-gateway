#include "path_monitor.h"
#include "multihoming.h"
#include "net_config.h"
#include "metrics.h"
#include "transport_policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

/* ── external: ai query (defined in ai_bridge.c) ───────────────────────── */
void query_ai(char *metrics, char *response);

/* ── shared state ───────────────────────────────────────────────────────── */

static pthread_mutex_t  state_lock   = PTHREAD_MUTEX_INITIALIZER;
static int              active_fd    = -1;
static int              on_secondary = 0;   /* 1 = currently using secondary */

static pthread_t  monitor_tid;
static volatile int monitor_running = 0;

/* ── helpers ────────────────────────────────────────────────────────────── */

static void ms_sleep(int ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* Read fd safely under the lock. Returns -1 if none registered. */
static int safe_fd(void)
{
    pthread_mutex_lock(&state_lock);
    int fd = active_fd;
    pthread_mutex_unlock(&state_lock);
    return fd;
}

/* ── monitor thread ─────────────────────────────────────────────────────── */

static void *monitor_loop(void *arg)
{
    (void)arg;
    printf("[Monitor] Path monitor started\n");

    while (monitor_running) {
        ms_sleep(MONITOR_INTERVAL_MS);

        int fd = safe_fd();
        if (fd < 0) {
            printf("[Monitor] No active association — waiting\n");
            continue;
        }

        /* ── query both paths ──────────────────────────────────────────── */
        PathStatus primary_ps, secondary_ps;
        int p_ok = get_path_status(fd, gw_peer_primary(),   gw_sctp_port(), &primary_ps);
        int s_ok = get_path_status(fd, gw_peer_secondary(), gw_sctp_port(), &secondary_ps);

        if (p_ok < 0) {
            /* fd was closed between safe_fd() and here — that's fine */
            printf("[Monitor] Path query failed (connection closed)\n");
            continue;
        }

        /* ── build metrics for AI ──────────────────────────────────────── */
        /* Same windowed flow-statistics vector the gateway emits (features.py
         * schema, microseconds). Reads the shared packet window; does not mutate
         * the jitter/IAT globals (avoids cross-thread pollution). */
        double latency  = (double)primary_ps.rtt_ms;   /* for logging only */
        double loss_pct = get_packet_loss_pct();        /* for logging only */
        double feats[6];
        get_window_features(feats);

        char metrics_str[256];
        snprintf(metrics_str, sizeof(metrics_str),
                 "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f",
                 feats[0], feats[1], feats[2], feats[3], feats[4], feats[5]);

        /* ── query AI ──────────────────────────────────────────────────── */
        char ai_resp[64];
        memset(ai_resp, 0, sizeof(ai_resp));
        query_ai(metrics_str, ai_resp);

        /* ── log current state ─────────────────────────────────────────── */
        printf("\n[Monitor] ── Path Health ───────────────────────────────\n");
        printf("[Monitor]  Primary   (%s): %-12s  RTT=%u ms  cwnd=%u\n",
               gw_peer_primary(),
               path_state_str(primary_ps.state),
               primary_ps.rtt_ms, primary_ps.cwnd);
        if (s_ok == 0) {
            printf("[Monitor]  Secondary (%s): %-12s  RTT=%u ms  cwnd=%u\n",
                   gw_peer_secondary(),
                   path_state_str(secondary_ps.state),
                   secondary_ps.rtt_ms, secondary_ps.cwnd);
        } else {
            printf("[Monitor]  Secondary (%s): unavailable\n", gw_peer_secondary());
        }
        printf("[Monitor]  AI verdict: %s  (rtt=%.1fms  loss=%.1f%%"
               "  iat_mean=%.0fus  pkt_rate=%.1f/s)\n",
               ai_resp, latency, loss_pct, feats[0], feats[2]);

        /* ── transport decision (crypto strength is NOT touched here) ───── */
        pthread_mutex_lock(&state_lock);
        int currently_secondary = on_secondary;
        pthread_mutex_unlock(&state_lock);

        TransportAction action = decide_transport(
            ai_resp,
            primary_ps.state == PATH_ACTIVE,    /* primary_active      */
            primary_ps.state == PATH_INACTIVE,  /* primary_down        */
            s_ok == 0,                          /* secondary_available */
            currently_secondary);

        switch (action) {
            case TA_FAILOVER:
                printf("[Monitor] *** PRIMARY PATH DOWN — emergency failover to"
                       " secondary ***\n");
                switch_primary_path(fd, gw_peer_secondary(), gw_sctp_port());
                pthread_mutex_lock(&state_lock);
                on_secondary = 1;
                pthread_mutex_unlock(&state_lock);
                break;

            case TA_RATE_LIMIT:
                printf("[Monitor] *** HIGH threat (flood) — RATE_LIMIT/alert;"
                       " crypto floor unchanged, path held ***\n");
                break;

            case TA_RESTORE_PRIMARY:
                printf("[Monitor] *** Threat cleared — restoring primary path ***\n");
                switch_primary_path(fd, gw_peer_primary(), gw_sctp_port());
                pthread_mutex_lock(&state_lock);
                on_secondary = 0;
                pthread_mutex_unlock(&state_lock);
                break;

            case TA_ALERT:
                printf("[Monitor] *** ALERT ***\n");
                break;

            case TA_NORMAL:
            default:
                break;
        }

        printf("[Monitor] ────────────────────────────────────────────────\n");
    }

    printf("[Monitor] Path monitor stopped\n");
    return NULL;
}

/* ── public API ─────────────────────────────────────────────────────────── */

int path_monitor_start(void)
{
    monitor_running = 1;
    if (pthread_create(&monitor_tid, NULL, monitor_loop, NULL) != 0) {
        perror("[Monitor] pthread_create");
        monitor_running = 0;
        return -1;
    }
    pthread_detach(monitor_tid);
    return 0;
}

void path_monitor_stop(void)
{
    monitor_running = 0;
}

void path_monitor_register(int sctp_fd)
{
    pthread_mutex_lock(&state_lock);
    active_fd = sctp_fd;
    pthread_mutex_unlock(&state_lock);
    printf("[Monitor] Registered fd=%d for path monitoring\n", sctp_fd);
}

void path_monitor_unregister(void)
{
    pthread_mutex_lock(&state_lock);
    active_fd = -1;
    pthread_mutex_unlock(&state_lock);
}

const char *path_monitor_preferred_primary(void)
{
    pthread_mutex_lock(&state_lock);
    int sec = on_secondary;
    pthread_mutex_unlock(&state_lock);
    return sec ? gw_peer_secondary() : gw_peer_primary();
}

const char *path_monitor_preferred_secondary(void)
{
    pthread_mutex_lock(&state_lock);
    int sec = on_secondary;
    pthread_mutex_unlock(&state_lock);
    return sec ? gw_peer_primary() : gw_peer_secondary();
}
