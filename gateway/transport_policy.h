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

/*
 * ── Network-condition (ML-A) → SCTP transport policy ──────────────────────────
 * The ML network-condition classifier's state maps to a transport RECOMMENDATION.
 * This is the second, independent driver of transport (the threat verdict above is the
 * first); like it, it never touches cryptographic strength.
 *
 * HONESTY GATE: until SCTP multihoming over multiple REAL paths is implemented,
 * these are advisory only — net_policy_enforced() returns 0 and the monitor merely
 * LOGS the recommendation rather than switching paths. When a real two-path testbed
 * exists, set GW_TRANSPORT_ENFORCE=1 to let PREFER_BACKUP / FAILOVER act.
 */
typedef enum {
    NP_NORMAL,               /* STABLE                -> normal operation         */
    NP_CONGESTION_RESPONSE,  /* CONGESTED             -> pace / rate-limit sends   */
    NP_FAILOVER_READY,       /* DEGRADED              -> raise failover readiness  */
    NP_PREFER_BACKUP,        /* UNSTABLE              -> prefer / pre-warm secondary*/
    NP_FAILOVER              /* POSSIBLE_PATH_FAILURE -> fail over to secondary    */
} NetTransportPolicy;

NetTransportPolicy netstate_to_policy(const char *state);
const char        *net_policy_str(NetTransportPolicy p);

/* 1 if GW_TRANSPORT_ENFORCE is set (real multihoming wired); else 0 = recommendation-only. */
int net_policy_enforced(void);

#endif /* TRANSPORT_POLICY_H */
