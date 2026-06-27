/*
 * Phase 1 policy unit tests.
 *
 * Verifies the two coherence invariants:
 *   1. select_kem() NEVER returns below the security floor, for any posture
 *      (including maximal battery pressure) — the downgrade-resistance claim.
 *   2. decide_transport() maps verdicts to TRANSPORT actions only, and never
 *      reacts to a flood by switching paths.
 *
 * Builds with just crypto_policy.c + transport_policy.c (no liboqs/openssl/sctp).
 */
#include "../crypto_policy.h"
#include "../transport_policy.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg) do {                                   \
    if (!(cond)) { printf("  FAIL: %s\n", (msg)); failures++; } \
    else         { printf("  ok  : %s\n", (msg)); }             \
} while (0)

static void test_floor_invariant(void)
{
    printf("[floor invariant] select_kem never drops below CRYPTO_FLOOR\n");

    /* Battery pressure — even maxed out — must not breach the floor. */
    for (int bp = 0; bp <= 100; bp += 10) {
        SecurityPosture p = { .high_assurance = 0, .battery_pressure = bp };
        KyberLevel lvl = select_kem(&p);
        CHECK(lvl >= CRYPTO_FLOOR, "battery pressure cannot go below floor");
    }

    /* Default posture sits exactly at the floor (ML-KEM-768). */
    SecurityPosture base = { .high_assurance = 0, .battery_pressure = 0 };
    CHECK(select_kem(&base) == CRYPTO_FLOOR, "default posture == floor");

    /* High-assurance may RAISE above the floor. */
    SecurityPosture ha = { .high_assurance = 1, .battery_pressure = 100 };
    CHECK(select_kem(&ha) == KYBER_1024, "high_assurance raises to ML-KEM-1024");
    CHECK(select_kem(&ha) >= CRYPTO_FLOOR, "high_assurance still >= floor");

    /* The floor itself must never be the weakest parameter set. */
    CHECK(CRYPTO_FLOOR > KYBER_512, "floor excludes ML-KEM-512");
}

static void test_transport_mapping(void)
{
    printf("[transport policy] verdict -> transport action (never crypto)\n");

    /* primary down + secondary available -> failover (availability). */
    CHECK(decide_transport("LOW", 0, 1, 1, 0) == TA_FAILOVER,
          "primary down -> failover");

    /* HIGH on a healthy path -> rate-limit, NOT failover (flood). */
    CHECK(decide_transport("HIGH", 1, 0, 1, 0) == TA_RATE_LIMIT,
          "HIGH flood -> rate-limit, path held");

    /* On secondary, threat clears, primary healthy -> restore. */
    CHECK(decide_transport("LOW", 1, 0, 1, 1) == TA_RESTORE_PRIMARY,
          "threat cleared -> restore primary");

    /* Quiet states -> no action. */
    CHECK(decide_transport("LOW", 1, 0, 1, 0) == TA_NORMAL,
          "LOW on primary -> normal");
    CHECK(decide_transport("MEDIUM", 1, 0, 1, 0) == TA_NORMAL,
          "MEDIUM on primary -> normal");

    /* Still on secondary but threat not cleared -> hold. */
    CHECK(decide_transport("HIGH", 1, 0, 1, 1) == TA_NORMAL,
          "HIGH on secondary -> hold (no restore)");
}

int main(void)
{
    test_floor_invariant();
    test_transport_mapping();

    if (failures == 0) {
        printf("\nAll policy tests passed.\n");
        return 0;
    }
    printf("\n%d policy test(s) FAILED.\n", failures);
    return 1;
}
