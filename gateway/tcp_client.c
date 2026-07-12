#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <arpa/inet.h>

#define TCP_PORT  4000
#define SERVER_IP "127.0.0.1"

/*
 * Usage:
 *   tcp_client                         one message, then close (legacy behavior)
 *   tcp_client "<msg>" <count> <ms>    hold the connection open and send <count>
 *                                      messages <ms> apart — a sustained flow that
 *                                      keeps ONE SCTP association alive at the gateway
 *                                      so failover can be exercised mid-stream
 *                                      (Phase 3 / Workstream C). count<=0 => forever.
 */
int main(int argc, char **argv)
{
    const char *msg   = (argc > 1) ? argv[1] : "Message from Legacy TCP Client";
    long        count = (argc > 2) ? atol(argv[2]) : 1;
    long        gap_ms = (argc > 3) ? atol(argv[3]) : 200;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("TCP socket failed"); exit(1); }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(TCP_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("TCP connection failed");
        exit(1);
    }

    struct timespec gap = { gap_ms / 1000, (gap_ms % 1000) * 1000000L };
    char payload[256];
    long i = 0;
    while (count <= 0 || i < count) {
        int n = snprintf(payload, sizeof(payload), "%s #%ld", msg, i + 1);
        if (send(sockfd, payload, (size_t)n, 0) <= 0) { perror("send"); break; }
        i++;
        if (count == 1) break;
        nanosleep(&gap, NULL);
    }

    printf("Sent %ld message(s)\n", i);
    close(sockfd);
    return 0;
}
