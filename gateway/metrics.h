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

/*
 * ── Phase 3 / Workstream B: sliding-window flow features ──────────────────
 *
 * The Phase-2 model is trained on CIC-IDS2017 flow statistics. record_packet()
 * feeds every received packet (size in bytes) into a mutex-guarded ring buffer of
 * recent arrivals; get_window_features() computes the 6 features the model expects,
 * in features.py order and UNITS:
 *
 *   out[0] iat_mean       mean inter-arrival gap        microseconds (us)
 *   out[1] iat_std        std of inter-arrival gaps     microseconds (us)
 *   out[2] pkt_rate       packets / second
 *   out[3] byte_rate      bytes / second
 *   out[4] mean_pkt_size  mean packet size              bytes
 *   out[5] flow_duration  window span (last - first)    microseconds (us)
 *
 * NOTE (units): CIC times are microseconds; emit us here (NOT ms) or the model
 * sees a 1000x train/serve skew. Thread-safe. Returns all zeros before 2 packets.
 */
#define FEATURE_WINDOW 256   /* ring buffer depth (recent arrivals) */

void record_packet(int size_bytes);
void get_window_features(double out[6]);

#endif /* METRICS_H */
