package com.pqcgateway.server.model;

import com.pqcgateway.analytics.MetricsAggregator;

public class SessionMetrics implements MetricsAggregator.MetricsSummary {
    private long   timestamp;
    private int    sessionId;
    private double latencyMs;
    private double jitterMs;
    private double packetLossPct;
    private double throughputBps;
    private String aiDecision;
    private String kyberLevel;
    private String activePath;
    private int    bytesTransferred;
    private double processingTimeMs;

    public long   getTimestamp()        { return timestamp; }
    public int    getSessionId()        { return sessionId; }
    public double getLatencyMs()        { return latencyMs; }
    public double getJitterMs()         { return jitterMs; }
    public double getPacketLossPct()    { return packetLossPct; }
    public double getThroughputBps()    { return throughputBps; }
    public String getAiDecision()       { return aiDecision; }
    public String getKyberLevel()       { return kyberLevel; }
    public String getActivePath()       { return activePath; }
    public int    getBytesTransferred() { return bytesTransferred; }
    public double getProcessingTimeMs() { return processingTimeMs; }

    public void setTimestamp(long v)        { timestamp = v; }
    public void setSessionId(int v)         { sessionId = v; }
    public void setLatencyMs(double v)      { latencyMs = v; }
    public void setJitterMs(double v)       { jitterMs = v; }
    public void setPacketLossPct(double v)  { packetLossPct = v; }
    public void setThroughputBps(double v)  { throughputBps = v; }
    public void setAiDecision(String v)     { aiDecision = v; }
    public void setKyberLevel(String v)     { kyberLevel = v; }
    public void setActivePath(String v)     { activePath = v; }
    public void setBytesTransferred(int v)  { bytesTransferred = v; }
    public void setProcessingTimeMs(double v){ processingTimeMs = v; }
}
