#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/sctp.h>

#include "pqc_handshake.h"
#include "multihoming.h"

#define BUFFER_SIZE 2048   /* large enough for IV + payload + TAG */

int decrypt_data_gcm(unsigned char *key,
                     unsigned char *input,
                     int            input_len,
                     unsigned char *plaintext,
                     int           *plain_len);

int main(void)
{
    /* Bind to both loopback IPs so the SCTP association spans both paths */
    int server_fd = multihome_server_create(PRIMARY_IP, SECONDARY_IP, 5000);
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

        /* ── Receive encrypted payload ─────────────────────────────────── */
        unsigned char buffer[BUFFER_SIZE];
        memset(buffer, 0, sizeof(buffer));

        int bytes = recv(client_fd, buffer, sizeof(buffer), 0);
        if (bytes > 0) {
            unsigned char plaintext[BUFFER_SIZE];
            int plain_len = 0;

            if (decrypt_data_gcm(shared_secret, buffer, bytes,
                                  plaintext, &plain_len) == 0) {
                printf("[Receiver] Decrypted message (%d bytes): %s\n",
                       plain_len, plaintext);
            } else {
                printf("[Receiver] Decryption / auth-tag check FAILED\n");
            }
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
