package com.pqcgateway.server.service;

import com.pqcgateway.analytics.MetricsAggregator;
import com.pqcgateway.server.model.PathEvent;
import com.pqcgateway.server.model.SessionMetrics;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.stream.Collectors;

@Service
public class MetricsStore {

    private static final int MAX_SESSIONS    = 200;
    private static final int MAX_PATH_EVENTS = 100;

    private final Deque<SessionMetrics> sessions   = new ConcurrentLinkedDeque<>();
    private final Deque<PathEvent>      pathEvents = new ConcurrentLinkedDeque<>();

    /* ── write ─────────────────────────────────────────────────────────── */

    public void addSession(SessionMetrics m) {
        sessions.addFirst(m);
        if (sessions.size() > MAX_SESSIONS) sessions.removeLast();
    }

    public void addPathEvent(PathEvent e) {
        pathEvents.addFirst(e);
        if (pathEvents.size() > MAX_PATH_EVENTS) pathEvents.removeLast();
    }

    /* ── read ──────────────────────────────────────────────────────────── */

    public List<SessionMetrics> getRecentSessions(int n) {
        return sessions.stream().limit(n).collect(Collectors.toList());
    }

    public List<PathEvent> getRecentPathEvents(int n) {
        return pathEvents.stream().limit(n).collect(Collectors.toList());
    }

    /* ── summary (consumed by /api/status) ─────────────────────────────── */

    public Map<String, Object> getStatus() {
        List<SessionMetrics> recent = getRecentSessions(50);

        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalSessions",    sessions.size());
        status.put("totalPathEvents",  pathEvents.size());
        status.put("avgLatencyMs",     MetricsAggregator.avgLatency(recent));
        status.put("avgThroughputBps", MetricsAggregator.avgThroughput(recent));
        status.put("avgPacketLossPct", MetricsAggregator.avgPacketLoss(recent));
        status.put("dominantAiMode",   MetricsAggregator.dominantAiMode(recent));

        if (!sessions.isEmpty()) {
            SessionMetrics latest = sessions.peekFirst();
            status.put("currentKyberLevel", latest.getKyberLevel());
            status.put("currentActivePath", latest.getActivePath());
            status.put("currentAiDecision", latest.getAiDecision());
        }

        if (!pathEvents.isEmpty()) {
            PathEvent latest = pathEvents.peekFirst();
            status.put("lastFailoverReason", latest.getReason());
            status.put("lastFailoverTime",   latest.getTimestamp());
        }

        return status;
    }
}
