#ifndef NET_CONFIG_H
#define NET_CONFIG_H

/*
 * Runtime network configuration (environment-overridable).
 *
 * Defaults are the loopback pair, so single-host development keeps working with no
 * environment set. For the network-namespace / two-host testbed (PHASE3_ALTER.md),
 * export the real addresses on each process:
 *
 *   Receiver (server) binds its LOCAL addresses:
 *     GW_LOCAL_PRIMARY   (default 127.0.0.1)
 *     GW_LOCAL_SECONDARY (default 127.0.0.2)
 *
 *   Gateway (client + path monitor) connects to / monitors the PEER addresses:
 *     GW_PEER_PRIMARY    (default 127.0.0.1)
 *     GW_PEER_SECONDARY  (default 127.0.0.2)
 *
 *   Shared:
 *     GW_SCTP_PORT       (default 5000)
 *
 * Example (netns): receiver -> GW_LOCAL_PRIMARY=10.0.0.2 GW_LOCAL_SECONDARY=10.0.1.2
 *                  gateway  -> GW_PEER_PRIMARY=10.0.0.2  GW_PEER_SECONDARY=10.0.1.2
 */

const char *gw_local_primary(void);
const char *gw_local_secondary(void);
const char *gw_peer_primary(void);
const char *gw_peer_secondary(void);
int         gw_sctp_port(void);

#endif /* NET_CONFIG_H */
