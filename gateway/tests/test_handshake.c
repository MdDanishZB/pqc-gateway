/*
 * test_handshake.c — end-to-end test of the authenticated hybrid handshake.
 *
 * Runs pqc_initiator_handshake and pqc_responder_handshake against each other over a
 * socketpair (initiator in a forked child, responder in the parent), exercising the SAME
 * code path the gateway/receiver use — minus SCTP. Checks:
 *   A. authenticated handshake succeeds and BOTH sides derive the identical AES key,
 *   B. a wrong pinned peer key makes the responder ABORT (MitM/forgery is rejected).
 *
 *   cd gateway && make tests/test_handshake && ./tests/test_handshake
 */
#include "../pqc_handshake.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

/* Run one handshake round. Returns 0 if BOTH sides succeed and keys match, else -1.
 * Env for the responder (peer pinning) is set by the caller before this runs. */
static int run_round(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return -1; }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }

    if (pid == 0) {
        /* child = initiator */
        close(sv[0]);
        uint8_t key[PQC_SHARED_SECRET_LEN];
        int rc = pqc_initiator_handshake(sv[1], KYBER_768, key);
        /* hand the derived key (or a failure marker) back to the parent over the socket */
        uint8_t out[1 + PQC_SHARED_SECRET_LEN];
        out[0] = (rc == 0) ? 1 : 0;
        memcpy(out + 1, key, PQC_SHARED_SECRET_LEN);
        if (write(sv[1], out, sizeof(out)) < 0) { /* parent may have aborted */ }
        close(sv[1]);
        _exit(0);
    }

    /* parent = responder */
    close(sv[1]);
    uint8_t rkey[PQC_SHARED_SECRET_LEN];
    int rrc = pqc_responder_handshake(sv[0], rkey);

    int ok = 0;
    if (rrc == 0) {
        uint8_t in[1 + PQC_SHARED_SECRET_LEN];
        ssize_t n = read(sv[0], in, sizeof(in));
        if (n == (ssize_t)sizeof(in) && in[0] == 1 &&
            memcmp(in + 1, rkey, PQC_SHARED_SECRET_LEN) == 0)
            ok = 1;
    }
    close(sv[0]);
    waitpid(pid, NULL, 0);
    return ok ? 0 : -1;
}

int main(void)
{
    int fail = 0;

    /* Pin the correct identities (defaults resolve to keys/, but be explicit). */
    setenv("GW_INIT_SK", "keys/gateway_sk.bin",  1);
    setenv("GW_RESP_PK", "keys/receiver_pk.bin", 1);
    setenv("GW_RESP_SK", "keys/receiver_sk.bin", 1);
    setenv("GW_INIT_PK", "keys/gateway_pk.bin",  1);   /* responder pins the gateway */

    printf("== A. authenticated handshake with correct pinned keys ==\n");
    if (run_round() == 0) printf("OK  : handshake succeeded and both sides derived the SAME key\n");
    else { printf("FAIL: authenticated handshake did not agree on a key\n"); fail = 1; }

    printf("\n== B. responder pins the WRONG peer key (simulated forgery/MitM) ==\n");
    /* Make the responder verify the gateway-signed transcript against the receiver's own
     * public key. The signature can't validate -> the responder must abort. */
    setenv("GW_INIT_PK", "keys/receiver_pk.bin", 1);
    if (run_round() != 0) printf("OK  : responder REJECTED the handshake (forgery blocked)\n");
    else { printf("FAIL: responder accepted a handshake it should have rejected!\n"); fail = 1; }

    printf(fail ? "\nHANDSHAKE TEST FAILED\n" : "\nHANDSHAKE TEST PASSED\n");
    return fail;
}
