/*
 * Phase 1 policy unit tests.
 *
 * Verifies the two coherence invariants:
 *   1. select_kem() is driven ONLY by data classification: ML-KEM-768 floor for
 *      ROUTINE/SENSITIVE, ML-KEM-1024 only for CRITICAL, and it can never fall below
 *      the floor. (Its type signature makes network/ML/battery inputs impossible.)
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
    printf("[crypto policy] select_kem driven ONLY by data classification\n");

    /* ROUTINE / SENSITIVE both sit exactly at the floor (ML-KEM-768). */
    CHECK(select_kem(CLASS_ROUTINE)   == CRYPTO_FLOOR, "ROUTINE   -> floor (ML-KEM-768)");
    CHECK(select_kem(CLASS_SENSITIVE) == CRYPTO_FLOOR, "SENSITIVE -> floor (ML-KEM-768)");

    /* Only CRITICAL raises to ML-KEM-1024. */
    CHECK(select_kem(CLASS_CRITICAL)  == ML_KEM_1024,  "CRITICAL  -> ML-KEM-1024");

    /* Every classification is always at or above the floor. */
    CHECK(select_kem(CLASS_ROUTINE)   >= CRYPTO_FLOOR, "ROUTINE   >= floor");
    CHECK(select_kem(CLASS_SENSITIVE) >= CRYPTO_FLOOR, "SENSITIVE >= floor");
    CHECK(select_kem(CLASS_CRITICAL)  >= CRYPTO_FLOOR, "CRITICAL  >= floor");

    /* The floor itself must never be the weakest parameter set. */
    CHECK(CRYPTO_FLOOR > ML_KEM_512, "floor excludes ML-KEM-512");

    /* String parsing is case-insensitive and defaults safely to ROUTINE. */
    CHECK(data_class_from_str("critical")  == CLASS_CRITICAL,  "\"critical\"  parses");
    CHECK(data_class_from_str("SENSITIVE") == CLASS_SENSITIVE, "\"SENSITIVE\" parses");
    CHECK(data_class_from_str("garbage")   == CLASS_ROUTINE,   "unknown -> ROUTINE (safe default)");
    CHECK(data_class_from_str(NULL)        == CLASS_ROUTINE,   "NULL    -> ROUTINE (safe default)");
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

static void test_netstate_mapping(void)
{
    printf("[netcond -> transport] ML-A state maps to transport recommendation\n");
    CHECK(netstate_to_policy("STABLE")                == NP_NORMAL,
          "STABLE -> NORMAL");
    CHECK(netstate_to_policy("CONGESTED")             == NP_CONGESTION_RESPONSE,
          "CONGESTED -> CONGESTION_RESPONSE");
    CHECK(netstate_to_policy("DEGRADED")              == NP_FAILOVER_READY,
          "DEGRADED -> FAILOVER_READY");
    CHECK(netstate_to_policy("UNSTABLE")              == NP_PREFER_BACKUP,
          "UNSTABLE -> PREFER_BACKUP");
    CHECK(netstate_to_policy("POSSIBLE_PATH_FAILURE") == NP_FAILOVER,
          "POSSIBLE_PATH_FAILURE -> FAILOVER");
    CHECK(netstate_to_policy(NULL)                    == NP_NORMAL,
          "NULL -> NORMAL (safe default)");
    CHECK(netstate_to_policy("garbage")               == NP_NORMAL,
          "unknown -> NORMAL (safe default)");
}

int main(void)
{
    test_floor_invariant();
    test_transport_mapping();
    test_netstate_mapping();

    if (failures == 0) {
        printf("\nAll policy tests passed.\n");
        return 0;
    }
    printf("\n%d policy test(s) FAILED.\n", failures);
    return 1;
}
