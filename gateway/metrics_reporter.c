#include "metrics_reporter.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define DASHBOARD_HOST "192.168.64.1"   /* Mac host IP as seen from UTM VM — change if different */
#define DASHBOARD_PORT 8080
#define CONN_TIMEOUT_S 1

/*
 * Opens a TCP connection to the Spring Boot server, sends a raw HTTP/1.1
 * POST request with a JSON body, then closes immediately.
 * Non-blocking: if the server is down, connect() fails fast and we return.
 */
static void http_post(const char *path, const char *json_body)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;

    /* Short connect timeout via SO_RCVTIMEO trick */
    struct timeval tv = { CONN_TIMEOUT_S, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(DASHBOARD_PORT);
    inet_pton(AF_INET, DASHBOARD_HOST, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return;   /* dashboard not running — silent drop */
    }

    int body_len = (int)strlen(json_body);
    char request[2048];
    int  req_len = snprintf(request, sizeof(request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        path, DASHBOARD_HOST, DASHBOARD_PORT, body_len, json_body);

    send(fd, request, (size_t)req_len, 0);
    close(fd);
}

/* ── public API ─────────────────────────────────────────────────────────── */

void report_session_metrics(int         session_id,
                             double      latency_ms,
                             double      jitter_ms,
                             double      packet_loss_pct,
                             double      throughput_bps,
                             const char *ai_decision,
                             const char *kyber_level,
                             const char *active_path,
                             int         bytes_transferred,
                             double      processing_ms)
{
    char body[512];
    snprintf(body, sizeof(body),
        "{"
        "\"sessionId\":%d,"
        "\"latencyMs\":%.2f,"
        "\"jitterMs\":%.2f,"
        "\"packetLossPct\":%.2f,"
        "\"throughputBps\":%.2f,"
        "\"aiDecision\":\"%s\","
        "\"kyberLevel\":\"%s\","
        "\"activePath\":\"%s\","
        "\"bytesTransferred\":%d,"
        "\"processingTimeMs\":%.2f"
        "}",
        session_id, latency_ms, jitter_ms, packet_loss_pct,
        throughput_bps, ai_decision ? ai_decision : "",
        kyber_level  ? kyber_level  : "",
        active_path  ? active_path  : "",
        bytes_transferred, processing_ms);

    http_post("/api/metrics", body);
}

void report_path_event(const char *from_path,
                       const char *to_path,
                       const char *reason)
{
    char body[256];
    snprintf(body, sizeof(body),
        "{\"fromPath\":\"%s\",\"toPath\":\"%s\",\"reason\":\"%s\"}",
        from_path ? from_path : "",
        to_path   ? to_path   : "",
        reason    ? reason    : "");

    http_post("/api/path-event", body);
}
