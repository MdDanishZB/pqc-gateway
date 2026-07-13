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
#include <math.h>
#include <pthread.h>

/* ── external: ai queries (defined in ai_bridge.c) ─────────────────────── */
void query_ai(char *metrics, char *response);       /* ML-B threat  */
void query_netcond(char *metrics, char *response);  /* ML-A network-condition */

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

        /* ── query AI: ML-B threat (flow-stats) ────────────────────────── */
        char ai_resp[64];
        memset(ai_resp, 0, sizeof(ai_resp));
        query_ai(metrics_str, ai_resp);

        /* ── query AI: ML-A network-condition (path-health signals) ─────── */
        static double prev_rtt = -1.0;
        double rtt        = (double)primary_ps.rtt_ms;
        double jitter     = (prev_rtt < 0) ? 0.0 : fabs(rtt - prev_rtt);
        prev_rtt = rtt;
        double thr_kbps   = get_last_throughput_bytes() * 8.0 / 1000.0;
        char net_metrics[128];
        snprintf(net_metrics, sizeof(net_metrics), "%.1f,%.1f,%.2f,%.1f,%u",
                 rtt, jitter, loss_pct, thr_kbps, primary_ps.cwnd);

        char net_resp[64];
        memset(net_resp, 0, sizeof(net_resp));
        query_netcond(net_metrics, net_resp);
        NetTransportPolicy net_policy =
            netstate_to_policy(net_resp[0] ? net_resp : "STABLE");

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

        /*
         * "down" = PATH_INACTIVE OR PATH_UNKNOWN. The Linux SCTP stack reports an
         * unmapped/default state (e.g. RFC 7829 Potentially-Failed) while a cut link is
         * still working through its retransmit backoff, well before it reaches the
         * formal INACTIVE state — waiting for INACTIVE alone means failover only fires
         * after the full RTO backoff (tens of seconds). PATH_UNCONFIRMED is excluded: it
         * is a normal transient state before the first heartbeat, not a failure signal.
         */
        int primary_down = (primary_ps.state == PATH_INACTIVE ||
                            primary_ps.state == PATH_UNKNOWN);

        TransportAction action = decide_transport(
            ai_resp,
            primary_ps.state == PATH_ACTIVE,    /* primary_active      */
            primary_down,
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

        /* ── ML-A network-condition → transport recommendation (2nd driver) ─── */
        int enforced = net_policy_enforced();
        printf("[NetML] state=%s -> transport: %s  [%s]\n",
               net_resp[0] ? net_resp : "STABLE",
               net_policy_str(net_policy),
               enforced ? "ENFORCED"
                        : "recommendation — single-path, not enforced");

        /* Only when real multihoming is wired (GW_TRANSPORT_ENFORCE=1) does a predicted
         * path failure proactively fail over. Otherwise ML-A stays purely advisory. */
        if (enforced) {
            pthread_mutex_lock(&state_lock);
            int on_sec = on_secondary;
            pthread_mutex_unlock(&state_lock);
            if (!on_sec && s_ok == 0 &&
                (net_policy == NP_FAILOVER || net_policy == NP_PREFER_BACKUP)) {
                printf("[NetML] *** proactive failover on predicted path failure ***\n");
                switch_primary_path(fd, gw_peer_secondary(), gw_sctp_port());
                pthread_mutex_lock(&state_lock);
                on_secondary = 1;
                pthread_mutex_unlock(&state_lock);
            }
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

void path_monitor_reset_preference(void)
{
    pthread_mutex_lock(&state_lock);
    on_secondary = 0;
    pthread_mutex_unlock(&state_lock);
}
