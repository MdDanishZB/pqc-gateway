/*
 * ai_bridge.c — the gateway's client side of the two ML sockets served by model_server.py.
 *
 *   query_ai      -> /tmp/ai_gateway.sock  (ML-B threat: 6 flow-stats -> LOW/MEDIUM/HIGH)
 *   query_netcond -> /tmp/ai_netcond.sock  (ML-A net-condition: 5 health feats -> STATE)
 *
 * Both send one comma-separated metric line and read back a short label. The reply is
 * null-terminated here so callers can strcmp() it directly. On any failure the response is
 * set to an empty string (callers treat that as "no verdict" and fall back to safe defaults).
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

#define AI_THREAT_SOCK  "/tmp/ai_gateway.sock"
#define AI_NETCOND_SOCK "/tmp/ai_netcond.sock"

/* Query one Unix-socket model endpoint. `response` must hold at least `cap` bytes. */
static void query_sock(const char *sock_path, const char *metrics,
                       char *response, size_t cap)
{
    if (cap) response[0] = '\0';

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("AI socket failed"); return; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        /* model_server not running (or this endpoint not served) — caller falls back. */
        close(fd);
        return;
    }

    send(fd, metrics, strlen(metrics), 0);

    ssize_t n = recv(fd, response, cap - 1, 0);
    response[(n > 0) ? (size_t)n : 0] = '\0';

    /* trim a trailing newline if the server added one */
    size_t len = strlen(response);
    if (len && response[len - 1] == '\n') response[len - 1] = '\0';

    close(fd);
}

/* ML-B threat detector. Kept as the original 2-arg signature (callers pass a >=64B buffer). */
void query_ai(char *metrics, char *response)
{
    query_sock(AI_THREAT_SOCK, metrics, response, 64);
}

/* ML-A network-condition classifier. */
void query_netcond(char *metrics, char *response)
{
    query_sock(AI_NETCOND_SOCK, metrics, response, 64);
}
