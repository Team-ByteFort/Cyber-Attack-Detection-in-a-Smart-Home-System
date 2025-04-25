package com.smarthome;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AttackDetectorTest {

    @BeforeEach
    @AfterEach
    void clearLogs() {
        AttackDetector.clearLogs();
    }

    @Test
    void testNormalLogin() {
        Map<String, Object> context = new HashMap<>();
        context.put("success", true);
        
        AttackDetector.instrument("login_attempt", "USER", "user1", "192.168.1.1", 
                                Instant.now(), context);
        
        List<SecurityEvent> attacks = AttackDetector.getAttackLog();
        assertEquals(0, attacks.size(), "Normal login should not trigger attack detection");
    }

    @Test
    void testBruteForceAttack() {
        Instant now = Instant.now();
        Map<String, Object> context = new HashMap<>();
        context.put("success", false);
        
        for (int i = 0; i < 6; i++) {
            AttackDetector.instrument("login_attempt", "USER", "attacker", "192.168.1.66",
                                    now.minus(50 - i*10, ChronoUnit.SECONDS), context);
        }
        
        List<SecurityEvent> attacks = AttackDetector.getAttackLog();
        assertEquals(1, attacks.size(), "Should detect brute force attack");
        assertEquals("BRUTE_FORCE_LOGIN", attacks.get(0).getAttackType());
    }

    @Test
    void testToggleSpam() {
        Instant now = Instant.now();
        
        for (int i = 0; i < 15; i++) {
            AttackDetector.instrument("toggle_light", "USER", "user2", "192.168.1.2",
                                    now.minus(28 - i*2, ChronoUnit.SECONDS), new HashMap<>());
        }
        
        List<SecurityEvent> attacks = AttackDetector.getAttackLog();
        assertEquals(1, attacks.size(), "Should detect toggle spam");
        assertEquals("TOGGLE_SPAM", attacks.get(0).getAttackType());
    }

    @Test
    void testToggleSpamCooldown() {
        Instant now = Instant.now();
        
        // First spam sequence (should trigger alert)
        for (int i = 0; i < 15; i++) {
            AttackDetector.instrument("toggle_light", "USER", "user2", "192.168.1.2",
                                    now.minus(28 - i*2, ChronoUnit.SECONDS), new HashMap<>());
        }
        
        // Second spam sequence within 5 minutes (should not trigger new alert)
        for (int i = 0; i < 15; i++) {
            AttackDetector.instrument("toggle_light", "USER", "user2", "192.168.1.2",
                                    now.minus(2, ChronoUnit.MINUTES).minus(28 - i*2, ChronoUnit.SECONDS), 
                                    new HashMap<>());
        }
        
        List<SecurityEvent> attacks = AttackDetector.getAttackLog();
        assertEquals(1, attacks.size(), "Should only detect one attack due to cooldown");
    }

    @Test
    void testAdminToggleSpamDuringBusinessHours() {
        Instant businessHour = Instant.now().atZone(java.time.ZoneId.systemDefault())
                                   .withHour(14).withMinute(0).toInstant();
        
        for (int i = 0; i < 15; i++) {
            AttackDetector.instrument("toggle_light", "ADMIN", "admin1", "192.168.1.100",
                                    businessHour.minus(30 - i*2, ChronoUnit.SECONDS), new HashMap<>());
        }
        
        List<SecurityEvent> attacks = AttackDetector.getAttackLog();
        assertEquals(0, attacks.size(), "Admin toggle spam during business hours should be allowed");
    }

    @Test
    void testPowerSpike() {
        Map<String, Object> context = new HashMap<>();
        context.put("value", 100.0);
        AttackDetector.instrument("power_reading", "SYSTEM", "sensor1", "sensor-001", 
                                Instant.now().minus(1, ChronoUnit.HOURS), context);
        
        context.put("value", 160.0);
        AttackDetector.instrument("power_reading", "SYSTEM", "sensor1", "sensor-001", 
                                Instant.now(), context);
        
        List<SecurityEvent> attacks = AttackDetector.getAttackLog();
        assertEquals(1, attacks.size(), "Should detect power spike");
        assertEquals("POWER_SPIKE", attacks.get(0).getAttackType());
    }

    @Test
    void testRoleViolation() {
        AttackDetector.instrument("admin_settings", "USER", "user3", "192.168.1.3",
                                Instant.now(), new HashMap<>());
        
        List<SecurityEvent> attacks = AttackDetector.getAttackLog();
        assertEquals(1, attacks.size(), "Should detect role violation");
        assertEquals("ROLE_VIOLATION", attacks.get(0).getAttackType());
    }

    @Test
    void testOffHoursActivity() {
        Instant offHour = Instant.now().atZone(java.time.ZoneId.systemDefault())
                              .withHour(20).withMinute(0).toInstant();
        
        AttackDetector.instrument("toggle_light", "USER", "user4", "192.168.1.4",
                                offHour, new HashMap<>());
        
        List<SecurityEvent> attacks = AttackDetector.getAttackLog();
        assertEquals(1, attacks.size(), "Should detect off-hours activity");
        assertEquals("OFF_HOURS_ACTIVITY", attacks.get(0).getAttackType());
    }
}