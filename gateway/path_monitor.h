#ifndef PATH_MONITOR_H
#define PATH_MONITOR_H

/*
 * AI-driven SCTP path monitor.
 *
 * Lifecycle:
 *   path_monitor_start()         — call once from start_gateway()
 *   path_monitor_register(fd)    — call after each sctp_connectx() succeeds
 *   path_monitor_unregister()    — call just before close(sctp_fd)
 *   path_monitor_stop()          — call on gateway shutdown
 *
 * Decisions made by the monitor persist across connections via
 * path_monitor_preferred_primary(), so new connections immediately
 * use the AI-chosen path.
 */

/* Poll interval — shorter = more responsive, higher CPU cost */
#define MONITOR_INTERVAL_MS 2000

/* Start the background monitor thread. Returns 0 on success. */
int path_monitor_start(void);

/* Gracefully stop the monitor thread. */
void path_monitor_stop(void);

/* Register the current active SCTP fd for monitoring.
 * Replaces any previously registered fd. */
void path_monitor_register(int sctp_fd);

/* Unregister — called just before the fd is closed. */
void path_monitor_unregister(void);

/* Returns the IP the monitor recommends as primary for the next connection.
 * Defaults to PRIMARY_IP until the AI triggers a changeover. */
const char *path_monitor_preferred_primary(void);

/* Returns the IP for the secondary slot (opposite of preferred primary). */
const char *path_monitor_preferred_secondary(void);

/*
 * Forget any failover memory and go back to preferring the CONFIGURED primary
 * (gw_peer_primary()) for the next connection. The monitor's stickiness (see the
 * lifecycle note above) is intentional in normal operation — a path that just failed
 * shouldn't be retried blindly. This is an explicit escape hatch for operators/tests
 * that need a deterministic fresh start (e.g. repeated failover measurement trials).
 */
void path_monitor_reset_preference(void);

#endif /* PATH_MONITOR_H */
