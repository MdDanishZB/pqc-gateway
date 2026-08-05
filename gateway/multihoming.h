#ifndef MULTIHOMING_H
#define MULTIHOMING_H

#include <stdint.h>

/*
 * VM SETUP (run once on your Ubuntu VM before testing):
 *   sudo ip addr add 127.0.0.2/8 dev lo
 *
 * This adds a second loopback alias that acts as the "secondary" SCTP path.
 */

#define PRIMARY_IP       "127.0.0.1"
#define SECONDARY_IP     "127.0.0.2"
#define HB_INTERVAL_MS   1000   /* heartbeat every 1 s */

typedef enum {
    PATH_ACTIVE,
    PATH_INACTIVE,
    PATH_UNCONFIRMED,
    PATH_UNKNOWN
} PathState;

typedef struct {
    char      ip[64];
    PathState state;
    uint32_t  rtt_ms;   /* smoothed RTT reported by SCTP stack */
    uint32_t  cwnd;     /* congestion window (bytes) */
} PathStatus;

/*
 * multihome_server_create:
 *   Creates an SCTP listening socket bound to two local IPs.
 *   Primary IP is bound first with bind(); secondary is added via sctp_bindx().
 *   Returns the listening fd, or -1 on error.
 */
int multihome_server_create(const char *primary_ip,
                             const char *secondary_ip,
                             int         port);

/*
 * multihome_client_connect:
 *   Creates an SCTP socket and calls sctp_connectx() with both server IPs so
 *   the association is established across both paths from the start.
 *   Writes elapsed connect time to *latency_ms_out (may be NULL).
 *   Returns the connected fd, or -1 on error.
 */
int multihome_client_connect(const char *primary_ip,
                              const char *secondary_ip,
                              int         port,
                              double     *latency_ms_out);

/*
 * enable_sctp_heartbeat:
 *   Enables SCTP path heartbeat at the given interval (ms) on fd.
 *   Returns 0 on success, -1 on failure.
 */
int enable_sctp_heartbeat(int fd, int interval_ms);

/*
 * get_path_status:
 *   Queries SCTP_GET_PEER_ADDR_INFO for the given peer IP:port.
 *   Fills *out with state, RTT, and cwnd.
 *   Returns 0 on success, -1 on failure.
 */
int get_path_status(int fd, const char *peer_ip, int port,
                    PathStatus *out);

/*
 * switch_primary_path:
 *   Sets a new primary path via SCTP_PRIMARY_ADDR.
 *   Returns 0 on success, -1 on failure.
 */
int switch_primary_path(int fd, const char *new_ip, int port);

/* Human-readable path state string. */
const char *path_state_str(PathState s);

#endif /* MULTIHOMING_H */
