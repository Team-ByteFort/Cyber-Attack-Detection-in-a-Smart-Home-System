package com.smarthome;

import java.time.Instant;
import java.util.Map;

public class SecurityEvent {
    private String eventName;
    private String userRole;
    private String userId;
    private String sourceId;
    private Instant timestamp;
    private Map<String, Object> context;
    private boolean isAttack;
    private String attackType;

    // Constructor
    public SecurityEvent(String eventName, String userRole, String userId, 
                        String sourceId, Instant timestamp, Map<String, Object> context) {
        this.eventName = eventName;
        this.userRole = userRole;
        this.userId = userId;
        this.sourceId = sourceId;
        this.timestamp = timestamp;
        this.context = context;
        this.isAttack = false;
        this.attackType = null;
    }

    // Getters and setters
    public String getEventName() { return eventName; }
    public String getUserRole() { return userRole; }
    public String getUserId() { return userId; }
    public String getSourceId() { return sourceId; }
    public Instant getTimestamp() { return timestamp; }
    public Map<String, Object> getContext() { return context; }
    public boolean isAttack() { return isAttack; }
    public String getAttackType() { return attackType; }
    
    public void markAsAttack(String attackType) {
        this.isAttack = true;
        this.attackType = attackType;
    }
}