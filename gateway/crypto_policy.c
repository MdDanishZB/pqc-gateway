#include "crypto_policy.h"

#include <string.h>
#include <strings.h>   /* strcasecmp */

MlKemLevel select_kem(DataClassification cls)
{
    /*
     * The ONLY input is the data classification. Only an explicit CRITICAL
     * classification raises strength above the floor; everything else stays at the
     * floor. No network, ML, or battery signal can reach this function.
     */
    MlKemLevel level = (cls == CLASS_CRITICAL) ? ML_KEM_1024 : CRYPTO_FLOOR;

    /* Defensive clamp: the level can never be below the floor, whatever the input. */
    if (level < CRYPTO_FLOOR)
        level = CRYPTO_FLOOR;

    return level;
}

DataClassification data_class_from_str(const char *s)
{
    if (!s) return CLASS_ROUTINE;
    if (strcasecmp(s, "critical")  == 0) return CLASS_CRITICAL;
    if (strcasecmp(s, "sensitive") == 0) return CLASS_SENSITIVE;
    return CLASS_ROUTINE;   /* default / "routine" / anything else */
}

const char *data_class_name(DataClassification cls)
{
    switch (cls) {
        case CLASS_CRITICAL:  return "CRITICAL";
        case CLASS_SENSITIVE: return "SENSITIVE";
        default:              return "ROUTINE";
    }
}

const char *ml_kem_name(MlKemLevel level)
{
    switch (level) {
        case ML_KEM_1024: return "ML-KEM-1024";
        case ML_KEM_512:  return "ML-KEM-512";
        default:          return "ML-KEM-768";
    }
}
