#ifndef TRANSPORT_POLICY_H
#define TRANSPORT_POLICY_H

/*
 * transport_policy — maps a network-threat verdict + path health to a TRANSPORT
 * action. This is the *only* place the LOW/MEDIUM/HIGH detector output is allowed
 * to act on. It deliberately knows nothing about KEM levels (see crypto_policy.h).
 *
 * Rationale for the mapping:
 *   - A down/inactive primary is an AVAILABILITY problem  → fail over (unconditional).
 *   - A HIGH verdict on a healthy path is a flood-like     → rate-limit + alert.
 *     pattern; failing over does NOT help a volumetric       (moving a flood to the
 *     attack, so we throttle instead of switching paths.     other path is pointless)
 *   - Once on secondary and the threat clears (LOW) with   → restore primary.
 *     the primary healthy again.
 */

typedef enum {
    TA_NORMAL,            /* no action */
    TA_RATE_LIMIT,        /* flood-like load: throttle/alert; crypto untouched */
    TA_FAILOVER,          /* primary degraded/down: move association to secondary */
    TA_RESTORE_PRIMARY,   /* threat cleared: move back to primary */
    TA_ALERT              /* surface for the operator, no automatic action */
} TransportAction;

/*
 * decide_transport
 *   verdict             — "LOW" / "MEDIUM" / "HIGH" from the detector
 *   primary_active      — primary path is PATH_ACTIVE
 *   primary_down        — primary path is PATH_INACTIVE
 *   secondary_available — secondary path status query succeeded
 *   currently_secondary — association is currently using the secondary path
 */
TransportAction decide_transport(const char *verdict,
                                 int primary_active,
                                 int primary_down,
                                 int secondary_available,
                                 int currently_secondary);

const char *transport_action_str(TransportAction a);

#endif /* TRANSPORT_POLICY_H */
