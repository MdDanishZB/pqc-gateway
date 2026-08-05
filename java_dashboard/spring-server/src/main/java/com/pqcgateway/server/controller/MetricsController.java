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
    public List<SessionMetrics> recentMetrics(
            @RequestParam(defaultValue = "50") int n) {
        return store.getRecentSessions(n);
    }

    @GetMapping("/path-events/recent")
    public List<PathEvent> recentPathEvents(
            @RequestParam(defaultValue = "20") int n) {
        return store.getRecentPathEvents(n);
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        return store.getStatus();
    }
}
