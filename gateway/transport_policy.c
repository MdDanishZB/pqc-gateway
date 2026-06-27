#include "transport_policy.h"

#include <string.h>

TransportAction decide_transport(const char *verdict,
                                 int primary_active,
                                 int primary_down,
                                 int secondary_available,
                                 int currently_secondary)
{
    int high = (verdict && strcmp(verdict, "HIGH") == 0);
    int low  = (verdict && strcmp(verdict, "LOW")  == 0);

    if (!currently_secondary) {
        /* On primary. */
        if (secondary_available && primary_down)
            return TA_FAILOVER;            /* availability first */
        if (high)
            return TA_RATE_LIMIT;          /* flood: throttle, do NOT switch paths */
        return TA_NORMAL;
    }

    /* On secondary. Restore primary once the threat clears and primary is healthy. */
    if (low && primary_active)
        return TA_RESTORE_PRIMARY;

    return TA_NORMAL;
}

const char *transport_action_str(TransportAction a)
{
    switch (a) {
        case TA_NORMAL:          return "NORMAL";
        case TA_RATE_LIMIT:      return "RATE_LIMIT";
        case TA_FAILOVER:        return "FAILOVER";
        case TA_RESTORE_PRIMARY: return "RESTORE_PRIMARY";
        case TA_ALERT:           return "ALERT";
        default:                 return "UNKNOWN";
    }
}
