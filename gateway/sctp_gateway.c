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
#include "metrics.h"
#include "multihoming.h"
#include "path_monitor.h"
#include "metrics_reporter.h"

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
#define SCTP_PORT   5000
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

    /* ── 1. Receive TCP data ─────────────────────────────────────────────── */
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));

    int bytes = recv(tcp_client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) {
        close(tcp_client_fd);
        pthread_exit(NULL);
    }
    buffer[bytes] = '\0';
    session.bytes_transferred = bytes;

    /* Measure inter-arrival time immediately after recv() returns */
    double iat_ms = measure_iat_ms();

    struct tm *tm_info = localtime(&session.start_time);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("\n========== SESSION INFO ==========\n");
    printf("Session ID     : %d\n",  session.session_id);
    printf("Client IP      : %s\n",  session.client_ip);
    printf("Bytes Received : %d\n",  session.bytes_transferred);
    printf("Start Time     : %s\n",  timebuf);
    printf("==================================\n");
    printf("\n[Gateway] Received TCP Data: %s\n", buffer);

    /* ── 2. Collect real metrics from previous session (bootstrap = 0) ───── */
    double latency_ms   = get_last_latency_ms();   /* 0.0 on first session */
    double jitter_ms    = update_jitter(latency_ms);
    double loss_pct     = get_packet_loss_pct();
    double throughput   = (double)bytes;
    double bw_util      = get_bandwidth_util_pct();

    char metrics_str[256];
    snprintf(metrics_str, sizeof(metrics_str),
             "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f",
             latency_ms, jitter_ms, loss_pct, throughput,
             iat_ms, bw_util);

    /* ── 3. Query AI → Kyber security level ─────────────────────────────── */
    char ai_response[64];
    memset(ai_response, 0, sizeof(ai_response));
    query_ai(metrics_str, ai_response);

    KyberLevel level = ai_response_to_level(ai_response);
    printf("\n[AI] Threat level: %-6s  latency=%.2fms  jitter=%.2fms"
           "  loss=%.1f%%  iat=%.1fms  bw=%.1f%%\n",
           ai_response, latency_ms, jitter_ms, loss_pct, iat_ms, bw_util);

    /* ── 4. Open multi-homed SCTP connection using AI-preferred path ────── */
    double connect_ms = 0.0;
    int sctp_fd = multihome_client_connect(
                      path_monitor_preferred_primary(),
                      path_monitor_preferred_secondary(),
                      SCTP_PORT, &connect_ms);
    if (sctp_fd < 0) {
        fprintf(stderr, "[Gateway] SCTP connect failed — dropping session\n");
        record_send_result(0);
        close(tcp_client_fd);
        pthread_exit(NULL);
    }

    /* Enable heartbeat so the SCTP stack probes both paths */
    enable_sctp_heartbeat(sctp_fd, HB_INTERVAL_MS);

    /* Register with path monitor for real-time path health checks */
    path_monitor_register(sctp_fd);

    /* Feed real latency into jitter tracker for the next session */
    update_jitter(connect_ms);
    printf("[Metrics] SCTP connect latency: %.3f ms\n", connect_ms);

    /* ── 5. PQC handshake — derives AES-256-GCM session key ─────────────── */
    uint8_t shared_secret[PQC_SHARED_SECRET_LEN];
    if (pqc_initiator_handshake(sctp_fd, level, shared_secret) != 0) {
        fprintf(stderr, "[Gateway] PQC handshake failed — dropping session\n");
        record_send_result(0);
        close(sctp_fd);
        close(tcp_client_fd);
        pthread_exit(NULL);
    }

    /* ── 6. Encrypt with AES-256-GCM using the PQC-derived key ──────────── */
    unsigned char encrypted[BUFFER_SIZE + 12 + 16];
    int encrypted_len = 0;

    if (encrypt_data_gcm(shared_secret,
                         (unsigned char *)buffer,
                         bytes,
                         encrypted,
                         &encrypted_len) != 0) {
        fprintf(stderr, "[Gateway] Encryption failed\n");
        record_send_result(0);
        close(sctp_fd);
        close(tcp_client_fd);
        pthread_exit(NULL);
    }

    /* ── 7. Forward payload & record outcome ─────────────────────────────── */
    int sent = (int)send(sctp_fd, encrypted, encrypted_len, 0);
    record_send_result(sent > 0);

    if (sent > 0) {
        printf("[Gateway] AES-256-GCM payload forwarded (%d bytes)\n",
               encrypted_len);
    } else {
        perror("Send failed");
    }

    path_monitor_unregister();
    close(sctp_fd);
    close(tcp_client_fd);

    /* ── 8. Print final session metrics ──────────────────────────────────── */
    clock_gettime(CLOCK_MONOTONIC, &wall_end);
    double wall_ms = (wall_end.tv_sec  - wall_start.tv_sec)  * 1000.0
                   + (wall_end.tv_nsec - wall_start.tv_nsec) / 1e6;

    update_bandwidth_ema(bytes, wall_ms > 0 ? wall_ms : 1.0);

    double throughput_bps = bytes / (wall_ms / 1000.0);
    double final_loss_pct = get_packet_loss_pct();

    printf("[Metrics] Total processing  : %.3f ms\n", wall_ms);
    printf("[Metrics] Throughput        : %.2f bytes/sec\n", throughput_bps);
    printf("[Metrics] Rolling loss      : %.1f%%\n", final_loss_pct);

    /* Determine Kyber level name from AI response for the dashboard */
    const char *kyber_str =
        (strcmp(ai_response, "HIGH")   == 0) ? "Kyber-1024" :
        (strcmp(ai_response, "MEDIUM") == 0) ? "Kyber-768"  : "Kyber-512";

    report_session_metrics(
        session.session_id,
        connect_ms,
        update_jitter(connect_ms),
        final_loss_pct,
        throughput_bps,
        ai_response,
        kyber_str,
        path_monitor_preferred_primary(),
        bytes,
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
