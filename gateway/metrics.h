#ifndef METRICS_H
#define METRICS_H

#include <sys/socket.h>

/*
 * timed_connect — calls connect(), returns elapsed ms. Returns -1.0 on failure.
 */
double timed_connect(int fd, struct sockaddr *addr, socklen_t addrlen);

/*
 * update_jitter — RFC-3550 jitter estimator. Returns |current - previous|.
 * Thread-safe; first call returns 0.
 */
double update_jitter(double latency_ms);

/*
 * get_last_latency_ms — latency from the most recent timed_connect().
 * Returns 0.0 before the first measurement.
 */
double get_last_latency_ms(void);

/*
 * record_send_result — push outcome into rolling loss window (1=ok, 0=drop).
 */
void record_send_result(int success);

/*
 * get_packet_loss_pct — % failed sends over last LOSS_WINDOW attempts.
 */
double get_packet_loss_pct(void);

/*
 * measure_iat_ms — inter-arrival time since the previous call (ms).
 * Call once per incoming packet (at the top of handle_client).
 * Returns 0.0 on the first call (no previous arrival to compare).
 * Thread-safe.
 */
double measure_iat_ms(void);

/*
 * update_bandwidth_ema — feed bytes + elapsed_ms from the latest session
 * into an exponential moving average of throughput.
 */
void update_bandwidth_ema(int bytes, double elapsed_ms);

/*
 * get_bandwidth_util_pct — EMA throughput expressed as a percentage of
 * REF_BANDWIDTH_BPS (1 MB/s by default). Saturates at 100.
 */
double get_bandwidth_util_pct(void);

/*
 * record_throughput_bytes / get_last_throughput_bytes —
 * stores the payload size (bytes) of the most recent session so the path
 * monitor can report the SAME "throughput" feature the model trained on,
 * instead of substituting an unrelated quantity (e.g. the SCTP cwnd).
 * Thread-safe. Returns 0.0 before the first session.
 */
void   record_throughput_bytes(int bytes);
double get_last_throughput_bytes(void);

#endif /* METRICS_H */
