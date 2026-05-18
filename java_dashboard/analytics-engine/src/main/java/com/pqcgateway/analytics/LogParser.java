package com.pqcgateway.analytics;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/**
 * Parses the gateway's stdout log file and extracts structured events.
 * Used when you redirect gateway output: ./gateway 2>&1 | tee gateway.log
 */
public class LogParser {

    private static final Pattern SESSION_ID   = Pattern.compile("Session ID\\s*:\\s*(\\d+)");
    private static final Pattern BYTES_RECV   = Pattern.compile("Bytes Received\\s*:\\s*(\\d+)");
    private static final Pattern AI_DECISION  = Pattern.compile("\\[AI\\].*?Threat level:\\s*(\\w+)");
    private static final Pattern KYBER_LEVEL  = Pattern.compile("\\[PQC\\] Hybrid handshake.*?(Kyber-\\d+)");
    private static final Pattern LATENCY      = Pattern.compile("SCTP connect latency:\\s*([\\d.]+)");
    private static final Pattern PROCESSING   = Pattern.compile("Total processing\\s*:\\s*([\\d.]+)");
    private static final Pattern THROUGHPUT   = Pattern.compile("Throughput\\s*:\\s*([\\d.]+)");
    private static final Pattern PATH_SWITCH  = Pattern.compile("Primary path switched to ([\\d.]+):(\\d+)");
    private static final Pattern PATH_DOWN    = Pattern.compile("PRIMARY PATH DOWN");
    private static final Pattern THREAT_CLEAR = Pattern.compile("Threat cleared");

    public record ParsedSession(
            int    sessionId,
            int    bytes,
            String aiDecision,
            String kyberLevel,
            double latencyMs,
            double processingMs,
            double throughputBps
    ) {}

    public record ParsedPathEvent(
            String type,     /* PATH_DOWN | PATH_SWITCH | THREAT_CLEARED */
            String toPath
    ) {}

    /**
     * Parse a gateway log file and return extracted sessions.
     */
    public static List<ParsedSession> parseSessions(Path logFile) throws IOException {
        List<String> lines = Files.readAllLines(logFile);
        List<ParsedSession> result = new ArrayList<>();

        int    sessionId   = -1;
        int    bytes       = 0;
        String aiDecision  = "UNKNOWN";
        String kyberLevel  = "UNKNOWN";
        double latencyMs   = 0;
        double processingMs = 0;
        double throughput  = 0;

        for (String line : lines) {
            Matcher m;

            if ((m = SESSION_ID.matcher(line)).find()) {
                if (sessionId >= 0)
                    result.add(new ParsedSession(sessionId, bytes, aiDecision,
                            kyberLevel, latencyMs, processingMs, throughput));
                sessionId  = Integer.parseInt(m.group(1));
                bytes = 0; aiDecision = "UNKNOWN"; kyberLevel = "UNKNOWN";
                latencyMs = 0; processingMs = 0; throughput = 0;
            }
            else if ((m = BYTES_RECV.matcher(line)).find())
                bytes = Integer.parseInt(m.group(1));
            else if ((m = AI_DECISION.matcher(line)).find())
                aiDecision = m.group(1);
            else if ((m = KYBER_LEVEL.matcher(line)).find())
                kyberLevel = m.group(1);
            else if ((m = LATENCY.matcher(line)).find())
                latencyMs = Double.parseDouble(m.group(1));
            else if ((m = PROCESSING.matcher(line)).find())
                processingMs = Double.parseDouble(m.group(1));
            else if ((m = THROUGHPUT.matcher(line)).find())
                throughput = Double.parseDouble(m.group(1));
        }

        if (sessionId >= 0)
            result.add(new ParsedSession(sessionId, bytes, aiDecision,
                    kyberLevel, latencyMs, processingMs, throughput));

        return result;
    }

    /**
     * Parse path-switch events from a log file.
     */
    public static List<ParsedPathEvent> parsePathEvents(Path logFile) throws IOException {
        List<String> lines = Files.readAllLines(logFile);
        List<ParsedPathEvent> result = new ArrayList<>();

        for (String line : lines) {
            Matcher m;
            if (PATH_DOWN.matcher(line).find())
                result.add(new ParsedPathEvent("PATH_DOWN", "secondary"));
            else if (THREAT_CLEAR.matcher(line).find())
                result.add(new ParsedPathEvent("THREAT_CLEARED", "primary"));
            else if ((m = PATH_SWITCH.matcher(line)).find())
                result.add(new ParsedPathEvent("PATH_SWITCH", m.group(1)));
        }

        return result;
    }
}
