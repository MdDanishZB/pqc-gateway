package com.pqcgateway.analytics;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Stateless utility class for computing aggregate statistics over
 * a window of SessionMetrics-like objects.
 *
 * Operates on duck-typed interfaces so it can be used by both the
 * Spring Boot server and the JavaFX dashboard without a hard dependency
 * on the server model classes.
 */
public final class MetricsAggregator {

    private MetricsAggregator() {}

    /* ── generic double-list aggregates ─────────────────────────────────── */

    public static double avg(List<Double> values) {
        if (values == null || values.isEmpty()) return 0.0;
        return values.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
    }

    public static double max(List<Double> values) {
        if (values == null || values.isEmpty()) return 0.0;
        return values.stream().mapToDouble(Double::doubleValue).max().orElse(0.0);
    }

    public static double min(List<Double> values) {
        if (values == null || values.isEmpty()) return 0.0;
        return values.stream().mapToDouble(Double::doubleValue).min().orElse(0.0);
    }

    /* ── SessionMetrics-aware aggregates ────────────────────────────────── */

    public static <T extends MetricsSummary> double avgLatency(List<T> sessions) {
        return avg(sessions.stream().map(T::getLatencyMs).collect(Collectors.toList()));
    }

    public static <T extends MetricsSummary> double avgThroughput(List<T> sessions) {
        return avg(sessions.stream().map(T::getThroughputBps).collect(Collectors.toList()));
    }

    public static <T extends MetricsSummary> double avgPacketLoss(List<T> sessions) {
        return avg(sessions.stream().map(T::getPacketLossPct).collect(Collectors.toList()));
    }

    public static <T extends MetricsSummary> double maxLatency(List<T> sessions) {
        return max(sessions.stream().map(T::getLatencyMs).collect(Collectors.toList()));
    }

    /**
     * Returns the most frequent AI decision (LOW / MEDIUM / HIGH) in the window.
     */
    public static <T extends MetricsSummary> String dominantAiMode(List<T> sessions) {
        if (sessions == null || sessions.isEmpty()) return "N/A";
        return sessions.stream()
                .map(T::getAiDecision)
                .filter(d -> d != null && !d.isBlank())
                .collect(Collectors.groupingBy(d -> d, Collectors.counting()))
                .entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse("N/A");
    }

    /**
     * Interface so MetricsAggregator stays independent of the Spring server's
     * SessionMetrics class (dashboard-ui can implement this with its own DTO).
     */
    public interface MetricsSummary {
        double getLatencyMs();
        double getThroughputBps();
        double getPacketLossPct();
        String getAiDecision();
    }
}
