package com.smarthome;

import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class AttackDetector {
    private static final List<SecurityEvent> eventLog = new ArrayList<>();
    private static final Map<String, Double> powerAverages = new ConcurrentHashMap<>();
    private static final Map<String, List<Instant>> failedLogins = new ConcurrentHashMap<>();
    private static final Map<String, List<Instant>> toggleEvents = new ConcurrentHashMap<>();
    private static final Map<String, Instant> lastSpamAlerts = new ConcurrentHashMap<>();
    
    private static final LocalTime BUSINESS_START = LocalTime.of(8, 0);
    private static final LocalTime BUSINESS_END = LocalTime.of(18, 0);

    public static void instrument(String eventName, String userRole, String userId,
                                String sourceId, Instant timestamp, Map<String, Object> context) {
        SecurityEvent event = new SecurityEvent(eventName, userRole, userId, sourceId, timestamp, context);
        
        checkFailedLogins(event);
        checkToggleSpam(event);
        checkPowerAnomalies(event);
        checkRoleViolations(event);
        checkOffHoursActivity(event);
        
        eventLog.add(event);
        
        if ("power_reading".equals(eventName) && !event.isAttack()) {
            double currentValue = (double) context.getOrDefault("value", 0.0);
            updatePowerAverage(sourceId, currentValue);
        }
    }

    private static void checkFailedLogins(SecurityEvent event) {
        if ("login_attempt".equals(event.getEventName())) {
            boolean success = (boolean) event.getContext().getOrDefault("success", true);
            if (!success) {
                failedLogins.computeIfAbsent(event.getSourceId(), k -> new ArrayList<>())
                           .add(event.getTimestamp());
                
                Instant oneMinuteAgo = event.getTimestamp().minus(1, ChronoUnit.MINUTES);
                long recentFailures = failedLogins.get(event.getSourceId()).stream()
                    .filter(t -> t.isAfter(oneMinuteAgo))
                    .count();
                
                if (recentFailures > 5 && !"ADMIN".equals(event.getUserRole())) {
                    event.markAsAttack("BRUTE_FORCE_LOGIN");
                }
            }
        }
    }

    private static void checkToggleSpam(SecurityEvent event) {
        if (event.getEventName().startsWith("toggle_")) {
            String sourceKey = event.getSourceId() + ":" + event.getEventName();
            toggleEvents.computeIfAbsent(sourceKey, k -> new ArrayList<>())
                       .add(event.getTimestamp());
            
            Instant thirtySecondsAgo = event.getTimestamp().minus(30, ChronoUnit.SECONDS);
            long recentToggles = toggleEvents.get(sourceKey).stream()
                .filter(t -> t.isAfter(thirtySecondsAgo))
                .count();
            
            boolean isAdminDuringBusiness = "ADMIN".equals(event.getUserRole()) && 
                                          isBusinessHours(event.getTimestamp());
            
            if (recentToggles > 10 && !isAdminDuringBusiness) {
                if (recentToggles == 11 || 
                    (lastSpamAlerts.getOrDefault(sourceKey, Instant.MIN)
                                  .isBefore(event.getTimestamp().minus(5, ChronoUnit.MINUTES)))) {
                    event.markAsAttack("TOGGLE_SPAM");
                    lastSpamAlerts.put(sourceKey, event.getTimestamp());
                }
            }
        }
    }

    private static void checkPowerAnomalies(SecurityEvent event) {
        if ("power_reading".equals(event.getEventName())) {
            double currentValue = (double) event.getContext().getOrDefault("value", 0.0);
            double historicalAvg = powerAverages.getOrDefault(event.getSourceId(), 100.0);
            
            if (currentValue <= 0) {
                event.markAsAttack("INVALID_POWER_READING");
            } else if (currentValue > 1.5 * historicalAvg) {
                event.markAsAttack("POWER_SPIKE");
            }
        }
    }

    private static void checkRoleViolations(SecurityEvent event) {
        if ("USER".equals(event.getUserRole()) && isAdminOnlyEvent(event.getEventName())) {
            event.markAsAttack("ROLE_VIOLATION");
        }
    }

    private static void checkOffHoursActivity(SecurityEvent event) {
        if ("USER".equals(event.getUserRole()) && !isBusinessHours(event.getTimestamp()) && 
            !"login_attempt".equals(event.getEventName())) {
            event.markAsAttack("OFF_HOURS_ACTIVITY");
        }
    }

    private static boolean isBusinessHours(Instant timestamp) {
        LocalTime time = timestamp.atZone(ZoneId.systemDefault()).toLocalTime();
        return !time.isBefore(BUSINESS_START) && !time.isAfter(BUSINESS_END);
    }

    private static boolean isAdminOnlyEvent(String eventName) {
        return eventName.startsWith("admin_") || 
               eventName.equals("system_reboot") || 
               eventName.equals("user_management");
    }

    private static void updatePowerAverage(String sourceId, double newValue) {
        powerAverages.merge(sourceId, newValue, (oldValue, value) -> (oldValue + value) / 2);
    }

    public static List<SecurityEvent> getEventLog() {
        return new ArrayList<>(eventLog);
    }

    public static List<SecurityEvent> getAttackLog() {
        return eventLog.stream().filter(SecurityEvent::isAttack).collect(Collectors.toList());
    }

    public static void clearLogs() {
        eventLog.clear();
        failedLogins.clear();
        toggleEvents.clear();
        lastSpamAlerts.clear();
    }
}