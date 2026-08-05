/*
 * Phase 3 / Workstream B: sliding-window feature tests.
 * Verifies get_window_features() byte accounting (deterministic) and that the
 * timing fields are emitted in plausible MICROSECOND magnitudes.
 * Builds with just metrics.c (no liboqs/openssl/sctp).
 */
#include "../metrics.h"

#include <stdio.h>
#include <time.h>

static int failures = 0;

#define CHECK(cond, msg) do {                                   \
    if (!(cond)) { printf("  FAIL: %s\n", (msg)); failures++; } \
    else         { printf("  ok  : %s\n", (msg)); }             \
} while (0)

static void sleep_us(long us)
{
    struct timespec ts = { us / 1000000, (us % 1000000) * 1000 };
    nanosleep(&ts, NULL);
}

int main(void)
{
    double f[6];

    printf("[window features]\n");

    /* Fewer than 2 arrivals -> all zeros (no IAT definable). */
    get_window_features(f);
    CHECK(f[0] == 0.0 && f[5] == 0.0, "empty window -> zeros");

    /* 10 packets of 100 bytes, ~500 us apart. */
    for (int i = 0; i < 10; i++) { record_packet(100); sleep_us(500); }
    get_window_features(f);

    CHECK(f[4] == 100.0, "mean_pkt_size exact (=100 bytes)");
    CHECK(f[5] > 0.0, "flow_duration positive (us)");
    CHECK(f[0] > 50.0 && f[0] < 100000.0, "iat_mean plausible microseconds");
    CHECK(f[1] >= 0.0, "iat_std non-negative");
    CHECK(f[2] > 0.0, "pkt_rate positive (/s)");
    CHECK(f[3] > 0.0, "byte_rate positive (B/s)");

    if (failures == 0) { printf("\nAll window-feature tests passed.\n"); return 0; }
    printf("\n%d window-feature test(s) FAILED.\n", failures);
    return 1;
}
