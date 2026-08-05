#ifndef METRICS_REPORTER_H
#define METRICS_REPORTER_H

/*
 * Fire-and-forget HTTP POST to the Spring Boot dashboard server.
 * If the server is not running the call returns immediately with no error.
 */
void report_session_metrics(int         session_id,
                             double      latency_ms,
                             double      jitter_ms,
                             double      packet_loss_pct,
                             double      throughput_bps,
                             const char *ai_decision,
                             const char *kyber_level,
                             const char *active_path,
                             int         bytes_transferred,
                             double      processing_ms);

void report_path_event(const char *from_path,
                       const char *to_path,
                       const char *reason);

#endif /* METRICS_REPORTER_H */
