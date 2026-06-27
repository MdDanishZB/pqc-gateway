#include "crypto_policy.h"

KyberLevel select_kem(const SecurityPosture *posture)
{
    /* Start at the floor; an explicit high-assurance signal may raise it. */
    KyberLevel level = (posture && posture->high_assurance) ? KYBER_1024
                                                            : CRYPTO_FLOOR;

    /*
     * battery_pressure is intentionally NOT allowed to lower `level`. This is the
     * floor invariant: a drained or spoofed battery signal can never weaken crypto.
     * The clamp below makes the guarantee explicit and defensive.
     */
    if (level < CRYPTO_FLOOR)
        level = CRYPTO_FLOOR;

    return level;
}
