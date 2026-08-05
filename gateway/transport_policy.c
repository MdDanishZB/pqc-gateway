#include "transport_policy.h"

#include <stdlib.h>
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

/* ── Network-condition (ML-A) → transport recommendation ─────────────────────── */

NetTransportPolicy netstate_to_policy(const char *state)
{
    if (!state)                                          return NP_NORMAL;
    if (strcmp(state, "POSSIBLE_PATH_FAILURE") == 0)     return NP_FAILOVER;
    if (strcmp(state, "UNSTABLE") == 0)                  return NP_PREFER_BACKUP;
    if (strcmp(state, "DEGRADED") == 0)                  return NP_FAILOVER_READY;
    if (strcmp(state, "CONGESTED") == 0)                 return NP_CONGESTION_RESPONSE;
    return NP_NORMAL;   /* STABLE / unknown */
}

const char *net_policy_str(NetTransportPolicy p)
{
    switch (p) {
        case NP_CONGESTION_RESPONSE: return "CONGESTION_RESPONSE";
        case NP_FAILOVER_READY:      return "FAILOVER_READY";
        case NP_PREFER_BACKUP:       return "PREFER_BACKUP";
        case NP_FAILOVER:            return "FAILOVER";
        default:                     return "NORMAL";
    }
}

int net_policy_enforced(void)
{
    const char *e = getenv("GW_TRANSPORT_ENFORCE");
    return (e && atoi(e) != 0) ? 1 : 0;
}
