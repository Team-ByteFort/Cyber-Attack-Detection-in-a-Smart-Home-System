# Smart Home Cyber-Attack Detection System

This system provides lightweight security monitoring for smart home environments by detecting potential cyber-attacks using rule-based approaches.

## Features

- Detects brute force login attempts (>5 fails in 1 minute)
- Identifies device toggle spamming (>10 toggles in 30 seconds)
- Flags power consumption anomalies (>150% of historical average)
- Detects role violations (users performing admin actions)
- Identifies suspicious off-hours activity (non-admin users)
- Logs all security events with attack flags

## Detection Rules

1. **Brute Force Login**: >5 failed login attempts from same source in 1 minute
2. **Toggle Spam**: >10 toggle commands from same source in 30 seconds (admins exempt during business hours)
3. **Power Anomalies**: 
   - Negative or zero power readings
   - Readings >150% of historical average
4. **Role Violations**: Regular users attempting admin-only actions
5. **Off-Hours Activity**: Regular users performing actions outside business hours (8AM-6PM)

## How to Use

1. Call `AttackDetector.instrument()` at key points in your smart home system:
   ```java
   AttackDetector.instrument(
       "login_attempt",          // Event type
       "USER",                   // User role
       "user123",                // User ID
       "192.168.1.1",            // Source IP/device
       Instant.now(),            // Timestamp
       Map.of("success", false)  // Context
   );