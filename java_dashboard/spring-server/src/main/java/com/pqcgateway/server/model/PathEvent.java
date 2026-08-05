package com.pqcgateway.server.model;

public class PathEvent {
    private long   timestamp;
    private String fromPath;
    private String toPath;
    private String reason;   /* "AI_HIGH_THREAT" | "PATH_DOWN" | "THREAT_CLEARED" */

    public long   getTimestamp() { return timestamp; }
    public String getFromPath()  { return fromPath; }
    public String getToPath()    { return toPath; }
    public String getReason()    { return reason; }

    public void setTimestamp(long v)   { timestamp = v; }
    public void setFromPath(String v)  { fromPath = v; }
    public void setToPath(String v)    { toPath = v; }
    public void setReason(String v)    { reason = v; }
}
