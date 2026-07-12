#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netinet/sctp.h>
#include <pthread.h>
#include <time.h>

#include "pqc_handshake.h"
#include "crypto_policy.h"
#include "metrics.h"
#include "multihoming.h"
#include "net_config.h"
#include "path_monitor.h"
#include "metrics_reporter.h"
#include "frame.h"

static double mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

typedef struct {
    int    session_id;
    char   client_ip[64];
    time_t start_time;
    int    bytes_transferred;
} Session;

void query_ai(char *metrics, char *response);

int encrypt_data_gcm(unsigned char *key,
                     unsigned char *plaintext,
                     int            plain_len,
                     unsigned char *output,
                     int           *output_len);

int global_session_id = 1;

#define TCP_PORT    4000
#define BUFFER_SIZE 1024

/* ── per-connection worker ─────────────────────────────────────────────────── */

void *handle_client(void *arg)
{
    struct timespec wall_start, wall_end;
    clock_gettime(CLOCK_MONOTONIC, &wall_start);

    int tcp_client_fd = *((int *)arg);
    free(arg);

    Session session;
    session.session_id        = global_session_id++;
    session.start_time        = time(NULL);
    session.bytes_transferred = 0;
    strcpy(session.client_ip, "127.0.0.1");

    /* ── 1. Read the first message (establishes the flow) ────────────────── */
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));

    int bytes = recv(tcp_client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) {
        close(tcp_client_fd);
        pthread_exit(NULL);
    }
    buffer[bytes] = '\0';
    session.bytes_transferred = bytes;

    printf("\n========== SESSION %d ==========\n", session.session_id);
    printf("[Gateway] First TCP payload (%d B): %.*s%s\n",
           bytes, bytes > 60 ? 60 : bytes, buffer, bytes > 60 ? "..." : "");

    /* ── 2. AI feature vector (windowed, µs) + verdict (transport/logging) ── */
    record_packet(bytes);
    record_throughput_bytes(bytes);
    double feats[6];
    get_window_features(feats);
    char metrics_str[256];
    snprintf(metrics_str, sizeof(metrics_str),
             "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f",
             feats[0], feats[1], feats[2], feats[3], feats[4], feats[5]);

    char ai_response[64];
    memset(ai_response, 0, sizeof(ai_response));
    double t_ai0 = mono_ms();
    query_ai(metrics_str, ai_response);
    double ai_rtt_ms = mono_ms() - t_ai0;
    printf("[AI] verdict=%s  ai_rtt=%.3fms\n", ai_response, ai_rtt_ms);

    /* ── 3. Crypto strength — floored, DECOUPLED from the verdict ────────── */
    SecurityPosture posture = { .high_assurance = 0, .battery_pressure = 0 };
    KyberLevel level = select_kem(&posture);
    const char *kem_str =
        (level == KYBER_1024) ? "ML-KEM-1024" :
        (level == KYBER_768)  ? "ML-KEM-768"  : "ML-KEM-512";

    /* ── 4. ONE multi-homed SCTP association for the whole flow ──────────── */
    double connect_ms = 0.0;
    int sctp_fd = multihome_client_connect(
                      path_monitor_preferred_primary(),
                      path_monitor_preferred_secondary(),
                      gw_sctp_port(), &connect_ms);
    if (sctp_fd < 0) {
        fprintf(stderr, "[Gateway] SCTP connect failed — dropping session\n");
        record_send_result(0);
        close(tcp_client_fd);
        pthread_exit(NULL);
    }
    enable_sctp_heartbeat(sctp_fd, HB_INTERVAL_MS);
    path_monitor_register(sctp_fd);   /* stays registered for the whole flow */

    /* ── 5. PQC handshake (timed) — derives AES-256-GCM session key ──────── */
    uint8_t shared_secret[PQC_SHARED_SECRET_LEN];
    PqcTiming tm;
    memset(&tm, 0, sizeof(tm));
    if (pqc_initiator_handshake_timed(sctp_fd, level, shared_secret, &tm) != 0) {
        fprintf(stderr, "[Gateway] PQC handshake failed — dropping session\n");
        record_send_result(0);
        path_monitor_unregister();
        close(sctp_fd);
        close(tcp_client_fd);
        pthread_exit(NULL);
    }

    /* ── Workstream D: per-session latency decomposition ─────────────────── */
    printf("[Bench] session=%d connect=%.3fms ai_rtt=%.3fms handshake=%.3fms "
           "[x25519_kg=%.3f kem_kg=%.3f kem_decaps=%.3f net=%.3f] kem=%s\n",
           session.session_id, connect_ms, ai_rtt_ms, tm.total_ms,
           tm.x25519_keygen_ms, tm.kem_keygen_ms, tm.kem_decaps_ms,
           tm.net_ms, kem_str);

    /* ── 6. STREAM: relay every message over the SAME association ─────────── */
    /* Keeps the association (and the path monitor) alive so autonomous failover
     * can actually be exercised while traffic flows (Phase 3 / Workstream C). */
    int  msg_count   = 0;
    long total_bytes = 0;
    while (1) {
        unsigned char encrypted[BUFFER_SIZE + 12 + 16];
        int enc_len = 0;
        if (encrypt_data_gcm(shared_secret, (unsigned char *)buffer, bytes,
                             encrypted, &enc_len) == 0
            && frame_write(sctp_fd, encrypted, (uint32_t)enc_len) == 0) {
            record_send_result(1);
            msg_count++;
            total_bytes += bytes;
        } else {
            record_send_result(0);   /* send failed even after failover */
            break;
        }

        bytes = recv(tcp_client_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) break;       /* client closed the stream */
        buffer[bytes] = '\0';
        record_packet(bytes);
        record_throughput_bytes(bytes);
    }

    /* ── 7. Teardown + report ────────────────────────────────────────────── */
    path_monitor_unregister();
    close(sctp_fd);
    close(tcp_client_fd);

    clock_gettime(CLOCK_MONOTONIC, &wall_end);
    double wall_ms = (wall_end.tv_sec  - wall_start.tv_sec)  * 1000.0
                   + (wall_end.tv_nsec - wall_start.tv_nsec) / 1e6;
    double throughput_bps = (wall_ms > 0) ? total_bytes / (wall_ms / 1000.0) : 0.0;
    double final_loss_pct = get_packet_loss_pct();
    update_bandwidth_ema((int)total_bytes, wall_ms > 0 ? wall_ms : 1.0);

    printf("[Gateway] flow done: %d messages, %ld bytes, %.1f ms, %.0f B/s\n",
           msg_count, total_bytes, wall_ms, throughput_bps);

    report_session_metrics(
        session.session_id,
        connect_ms,
        update_jitter(connect_ms),
        final_loss_pct,
        throughput_bps,
        ai_response,
        kem_str,
        path_monitor_preferred_primary(),
        (int)total_bytes,
        wall_ms);

    return NULL;
}

/* ── gateway main loop ─────────────────────────────────────────────────────── */

void start_gateway(void)
{
    signal(SIGPIPE, SIG_IGN);

    /* Launch AI path monitor — runs for the lifetime of the gateway */
    if (path_monitor_start() != 0) {
        fprintf(stderr, "[Gateway] Warning: path monitor failed to start\n");
    }

    int tcp_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_server_fd < 0) { perror("TCP socket failed"); exit(1); }

    int opt = 1;
    setsockopt(tcp_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in tcp_addr;
    memset(&tcp_addr, 0, sizeof(tcp_addr));
    tcp_addr.sin_family      = AF_INET;
    tcp_addr.sin_port        = htons(TCP_PORT);
    tcp_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(tcp_server_fd,
             (struct sockaddr *)&tcp_addr,
             sizeof(tcp_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }

    listen(tcp_server_fd, 5);
    printf("Gateway listening for TCP clients on port %d...\n", TCP_PORT);

    while (1) {
        int tcp_client_fd = accept(tcp_server_fd, NULL, NULL);
        if (tcp_client_fd < 0) { perror("Accept failed"); continue; }

        printf("\n[Gateway] TCP client connected\n");

        int *client_ptr = malloc(sizeof(int));
        *client_ptr = tcp_client_fd;

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, client_ptr);
        pthread_detach(tid);
    }
}
