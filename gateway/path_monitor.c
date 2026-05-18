#include "path_monitor.h"
#include "multihoming.h"
#include "metrics.h"

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
        int p_ok = get_path_status(fd, PRIMARY_IP,   5000, &primary_ps);
        int s_ok = get_path_status(fd, SECONDARY_IP, 5000, &secondary_ps);

        if (p_ok < 0) {
            /* fd was closed between safe_fd() and here — that's fine */
            printf("[Monitor] Path query failed (connection closed)\n");
            continue;
        }

        /* ── build metrics for AI ──────────────────────────────────────── */
        double latency  = (double)primary_ps.rtt_ms;
        double jitter   = (s_ok == 0)
                          ? (double)(primary_ps.rtt_ms > secondary_ps.rtt_ms
                                     ? primary_ps.rtt_ms - secondary_ps.rtt_ms
                                     : secondary_ps.rtt_ms - primary_ps.rtt_ms)
                          : update_jitter(latency);
        double loss_pct = get_packet_loss_pct();
        double thruput  = (double)primary_ps.cwnd;
        double iat_ms   = measure_iat_ms();
        double bw_util  = get_bandwidth_util_pct();

        char metrics_str[256];
        snprintf(metrics_str, sizeof(metrics_str),
                 "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f",
                 latency, jitter, loss_pct, thruput, iat_ms, bw_util);

        /* ── query AI ──────────────────────────────────────────────────── */
        char ai_resp[64];
        memset(ai_resp, 0, sizeof(ai_resp));
        query_ai(metrics_str, ai_resp);

        /* ── log current state ─────────────────────────────────────────── */
        printf("\n[Monitor] ── Path Health ───────────────────────────────\n");
        printf("[Monitor]  Primary   (%s): %-12s  RTT=%u ms  cwnd=%u\n",
               PRIMARY_IP,
               path_state_str(primary_ps.state),
               primary_ps.rtt_ms, primary_ps.cwnd);
        if (s_ok == 0) {
            printf("[Monitor]  Secondary (%s): %-12s  RTT=%u ms  cwnd=%u\n",
                   SECONDARY_IP,
                   path_state_str(secondary_ps.state),
                   secondary_ps.rtt_ms, secondary_ps.cwnd);
        } else {
            printf("[Monitor]  Secondary (%s): unavailable\n", SECONDARY_IP);
        }
        printf("[Monitor]  AI verdict: %s  (latency=%.1fms  jitter=%.1fms"
               "  loss=%.1f%%)\n",
               ai_resp, latency, jitter, loss_pct);

        /* ── autonomous failover logic ─────────────────────────────────── */
        pthread_mutex_lock(&state_lock);
        int currently_secondary = on_secondary;
        pthread_mutex_unlock(&state_lock);

        int path_down   = (primary_ps.state == PATH_INACTIVE);
        int high_threat = (strcmp(ai_resp, "HIGH") == 0);
        int low_threat  = (strcmp(ai_resp, "LOW")  == 0);

        if (!currently_secondary && s_ok == 0) {
            if (path_down) {
                printf("[Monitor] *** PRIMARY PATH DOWN — emergency failover ***\n");
                switch_primary_path(fd, SECONDARY_IP, 5000);
                pthread_mutex_lock(&state_lock);
                on_secondary = 1;
                pthread_mutex_unlock(&state_lock);

            } else if (high_threat) {
                printf("[Monitor] *** HIGH threat detected — autonomous changeover"
                       " to secondary ***\n");
                switch_primary_path(fd, SECONDARY_IP, 5000);
                pthread_mutex_lock(&state_lock);
                on_secondary = 1;
                pthread_mutex_unlock(&state_lock);
            }

        } else if (currently_secondary && low_threat && p_ok == 0
                   && primary_ps.state == PATH_ACTIVE) {
            /* Threat cleared — restore primary path */
            printf("[Monitor] *** Threat cleared — switching back to primary ***\n");
            switch_primary_path(fd, PRIMARY_IP, 5000);
            pthread_mutex_lock(&state_lock);
            on_secondary = 0;
            pthread_mutex_unlock(&state_lock);
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
    return sec ? SECONDARY_IP : PRIMARY_IP;
}

const char *path_monitor_preferred_secondary(void)
{
    pthread_mutex_lock(&state_lock);
    int sec = on_secondary;
    pthread_mutex_unlock(&state_lock);
    return sec ? PRIMARY_IP : SECONDARY_IP;
}
