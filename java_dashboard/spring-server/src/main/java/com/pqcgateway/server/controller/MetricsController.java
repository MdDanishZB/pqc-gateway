package com.pqcgateway.server.controller;

import com.pqcgateway.server.model.PathEvent;
import com.pqcgateway.server.model.SessionMetrics;
import com.pqcgateway.server.service.MetricsStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")   /* allow JavaFX dashboard on any port */
public class MetricsController {

    @Autowired
    private MetricsStore store;

    /* ── ingest (called by C gateway) ─────────────────────────────────── */

    @PostMapping("/metrics")
    public ResponseEntity<String> receiveMetrics(@RequestBody SessionMetrics m) {
        m.setTimestamp(System.currentTimeMillis());
        store.addSession(m);
        System.out.printf("[Server] Session #%d  AI=%s  Kyber=%s  latency=%.1fms%n",
                m.getSessionId(), m.getAiDecision(),
                m.getKyberLevel(), m.getLatencyMs());
        return ResponseEntity.ok("ok");
    }

    @PostMapping("/path-event")
    public ResponseEntity<String> receivePathEvent(@RequestBody PathEvent e) {
        e.setTimestamp(System.currentTimeMillis());
        store.addPathEvent(e);
        System.out.printf("[Server] Path event: %s → %s  reason=%s%n",
                e.getFromPath(), e.getToPath(), e.getReason());
        return ResponseEntity.ok("ok");
    }

    /* ── query (called by JavaFX dashboard) ────────────────────────────── */

    @GetMapping("/metrics/recent")
    public List<Map<String, Object>> recentMetrics(
            @RequestParam(defaultValue = "50") int n) {
        return store.getRecentSessions(n).stream().map(m -> {
            Map<String, Object> row = new java.util.LinkedHashMap<>();
            row.put("sessionId",        m.getSessionId());
            row.put("timestamp",        m.getTimestamp());
            row.put("latencyMs",        m.getLatencyMs());
            row.put("jitterMs",         m.getJitterMs());
            row.put("packetLossPct",    m.getPacketLossPct());
            row.put("throughputBps",    m.getThroughputBps());
            row.put("aiDecision",       m.getAiDecision());
            row.put("kyberLevel",       m.getKyberLevel());
            row.put("activePath",       m.getActivePath());
            row.put("bytesTransferred", m.getBytesTransferred());
            row.put("processingTimeMs", m.getProcessingTimeMs());
            return row;
        }).collect(java.util.stream.Collectors.toList());
    }

    @GetMapping("/path-events/recent")
    public List<Map<String, Object>> recentPathEvents(
            @RequestParam(defaultValue = "20") int n) {
        return store.getRecentPathEvents(n).stream().map(e -> {
            Map<String, Object> row = new java.util.LinkedHashMap<>();
            row.put("timestamp", e.getTimestamp());
            row.put("fromPath",  e.getFromPath());
            row.put("toPath",    e.getToPath());
            row.put("reason",    e.getReason());
            return row;
        }).collect(java.util.stream.Collectors.toList());
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        return store.getStatus();
    }
}
