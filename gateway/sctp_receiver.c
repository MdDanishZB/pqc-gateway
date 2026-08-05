#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/sctp.h>

#include "pqc_handshake.h"
#include "multihoming.h"
#include "net_config.h"
#include "frame.h"

#define BUFFER_SIZE 2048   /* large enough for IV + payload + TAG */

int decrypt_data_gcm(unsigned char *key,
                     unsigned char *input,
                     int            input_len,
                     unsigned char *plaintext,
                     int           *plain_len);

int main(void)
{
    /* Bind to both local IPs so the SCTP association spans both paths.
     * Addresses/port are env-configurable (net_config); default = loopback pair. */
    int server_fd = multihome_server_create(gw_local_primary(),
                                            gw_local_secondary(),
                                            gw_sctp_port());
    if (server_fd < 0) exit(1);

    printf("SCTP Receiver ready (multi-homed).\n");

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) { perror("accept"); continue; }

        printf("\n[Receiver] Gateway connected\n");

        /* Enable heartbeat on accepted association */
        enable_sctp_heartbeat(client_fd, HB_INTERVAL_MS);

        /* ── PQC handshake — derive session key ────────────────────────── */
        uint8_t shared_secret[PQC_SHARED_SECRET_LEN];
        if (pqc_responder_handshake(client_fd, shared_secret) != 0) {
            fprintf(stderr, "[Receiver] PQC handshake failed\n");
            close(client_fd);
            continue;
        }

        /* ── Receive framed encrypted messages until the peer closes ────── */
        /* Streaming relay (Phase 3 / Workstream C): one association carries many
         * length-prefixed messages, so we loop instead of a single recv(). */
        unsigned char buffer[BUFFER_SIZE];
        uint32_t flen;
        int count = 0;
        while (frame_read(client_fd, buffer, sizeof(buffer), &flen) == 0) {
            unsigned char plaintext[BUFFER_SIZE];
            int plain_len = 0;
            if (decrypt_data_gcm(shared_secret, buffer, (int)flen,
                                  plaintext, &plain_len) == 0) {
                int t = (plain_len < (int)sizeof(plaintext)) ? plain_len
                                                             : (int)sizeof(plaintext) - 1;
                plaintext[t] = '\0';
                printf("[Receiver] msg %d (%d B): %s\n", ++count, plain_len, plaintext);
            } else {
                printf("[Receiver] Decryption / auth-tag check FAILED\n");
            }
        }
        printf("[Receiver] flow closed after %d message(s)\n", count);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
