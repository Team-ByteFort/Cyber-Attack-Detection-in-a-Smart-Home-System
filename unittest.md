To thoroughly test the anomaly detection system in a smart home setup, we need to create separate test cases that demonstrate both legitimate high-frequency events and attack signatures. These test cases will cover all implemented anomaly detection mechanisms, including failed login rate, control command rate, power consumption, unusual device access, and suspicious command sequences. Below is a comprehensive set of test cases designed to validate the system's ability to distinguish between normal and malicious activities, exploring all possible anomalies that could occur.

---

### Test Cases

#### **1. Legitimate High-Frequency Events**
These test cases ensure the system allows authorized high-frequency actions without triggering false positives.

- **Test Case 1: Admin Issuing High-Frequency Commands During Business Hours**
  - **Scenario**: An admin performs maintenance, issuing 19 control commands within 30 seconds at 10:00 AM (business hours: 9 AM - 5 PM).
  - **Events**:
    - Admin logs in at 10:00 AM with role "ADMIN".
    - Admin issues 19 control commands to "light1" within 30 seconds.
  - **Expected Outcome**: No anomaly triggered (19 < 20, the threshold for admins during business hours).

- **Test Case 2: User Issuing Normal-Frequency Commands**
  - **Scenario**: A regular user adjusts a device, issuing 8 control commands within 30 seconds.
  - **Events**:
    - User logs in at 2:00 PM.
    - User issues 8 control commands to "thermostat1" within 30 seconds.
  - **Expected Outcome**: No anomaly triggered (8 < 10, the threshold for regular users).

---

#### **2. Attack Signatures**
These test cases simulate malicious activities that should trigger anomaly detections.

- **Test Case 3: Brute-Force Login Attack**
  - **Scenario**: An attacker attempts multiple failed logins to guess a password.
  - **Events**:
    - 6 failed login attempts for "user1" within 1 minute.
  - **Expected Outcome**: Failed login rate anomaly triggered (6 > 5 attempts in 1 minute).

- **Test Case 4: Rapid Device Toggling Attack**
  - **Scenario**: An attacker rapidly toggles a device with 12 control commands within 30 seconds.
  - **Events**:
    - User logs in at 3:00 PM.
    - User issues 12 control commands to "light1" within 30 seconds.
  - **Expected Outcome**: Control command rate anomaly triggered (12 > 10 for regular users).

- **Test Case 5: Anomalous Power Reading (Negative Value)**
  - **Scenario**: A device reports an invalid power reading of -50W, indicating possible tampering.
  - **Events**:
    - Power reading of -50W for "appliance1".
  - **Expected Outcome**: Power consumption anomaly triggered (value ≤ 0).

- **Test Case 6: Power Spike**
  - **Scenario**: A device reports 160W, exceeding 150% of its historical average (100W).
  - **Events**:
    - Historical readings: [100W, 100W, 100W, 100W, 100W] (average = 100W).
    - New reading: 160W.
  - **Expected Outcome**: Power consumption anomaly triggered (160W > 150W).

- **Test Case 7: Unusual Device Access**
  - **Scenario**: A user accesses a device outside their usual profile, suggesting compromised credentials.
  - **Events**:
    - "user1" (profile: "light1", "thermostat1") issues a command to "camera1".
  - **Expected Outcome**: Unusual device access anomaly triggered.

- **Test Case 8: Suspicious Command Sequence**
  - **Scenario**: A user disables an alarm and unlocks a door within 5 seconds, indicating a potential break-in attempt.
  - **Events**:
    - "disable_alarm" at 12:00:00.
    - "unlock_door" at 12:00:05.
  - **Expected Outcome**: Suspicious command sequence anomaly triggered (within 10-second window).

---

#### **3. Edge Cases**
These test cases validate system behavior at the boundaries of detection thresholds.

- **Test Case 9: Admin Commands Outside Business Hours**
  - **Scenario**: Admin issues 11 control commands within 30 seconds at 8:00 AM (outside business hours).
  - **Events**:
    - Admin logs in at 8:00 AM with role "ADMIN".
    - Admin issues 11 control commands to "light1" within 30 seconds.
  - **Expected Outcome**: Control command rate anomaly triggered (11 > 10, regular threshold applies outside business hours).

- **Test Case 10: Power Reading at 150% of Average**
  - **Scenario**: A power reading is exactly 150W with a historical average of 100W.
  - **Events**:
    - Historical readings: [100W, 100W, 100W, 100W, 100W] (average = 100W).
    - New reading: 150W.
  - **Expected Outcome**: No anomaly triggered (150W = 150W, condition requires ">").

- **Test Case 11: Power Reading Slightly Above 150%**
  - **Scenario**: A power reading is 151W with a historical average of 100W.
  - **Events**:
    - Historical readings: [100W, 100W, 100W, 100W, 100W] (average = 100W).
    - New reading: 151W.
  - **Expected Outcome**: Power consumption anomaly triggered (151W > 150W).

- **Test Case 12: Suspicious Sequence Outside Time Window**
  - **Scenario**: "disable_alarm" followed by "unlock_door" 15 seconds later.
  - **Events**:
    - "disable_alarm" at 12:00:00.
    - "unlock_door" at 12:00:15.
  - **Expected Outcome**: No anomaly triggered (15s > 10s window).

---

#### **4. Combined Anomalies**
This test case simulates a sophisticated attack triggering multiple anomalies.

- **Test Case 13: Multi-Stage Attack**
  - **Scenario**: An attacker performs a sequence of malicious actions.
  - **Events**:
    - 6 failed login attempts for "user1" within 1 minute.
    - Successful login at 1:01:00.
    - 12 control commands to "light1" within 30 seconds.
    - Command to "camera1" (not in "user1" profile).
    - "disable_alarm" at 1:02:00, "unlock_door" at 1:02:05.
  - **Expected Outcome**:
    - Failed login rate anomaly.
    - Control command rate anomaly.
    - Unusual device access anomaly.
    - Suspicious command sequence anomaly.

---


# Smart Home Anomaly Detection Test Cases

## 1. Legitimate High-Frequency Events

### Test Case 1: Admin Issuing High-Frequency Commands During Business Hours
- **Scenario**: Admin performs maintenance, issuing 19 control commands within 30 seconds at 10:00 AM.
- **Events**:
  - Admin login at 10:00 AM, role "ADMIN".
  - 19 control commands to "light1" within 30 seconds.
- **Expected Outcome**: No anomaly (19 < 20).

### Test Case 2: User Issuing Normal-Frequency Commands
- **Scenario**: User adjusts device, issuing 8 control commands within 30 seconds.
- **Events**:
  - User login at 2:00 PM.
  - 8 control commands to "thermostat1" within 30 seconds.
- **Expected Outcome**: No anomaly (8 < 10).

## 2. Attack Signatures

### Test Case 3: Brute-Force Login Attack
- **Scenario**: Attacker attempts multiple failed logins.
- **Events**:
  - 6 failed login attempts for "user1" within 1 minute.
- **Expected Outcome**: Failed login rate anomaly (6 > 5).

### Test Case 4: Rapid Device Toggling Attack
- **Scenario**: Attacker issues 12 control commands within 30 seconds.
- **Events**:
  - User login at 3:00 PM.
  - 12 control commands to "light1" within 30 seconds.
- **Expected Outcome**: Control command rate anomaly (12 > 10).

### Test Case 5: Anomalous Power Reading (Negative Value)
- **Scenario**: Device reports -50W.
- **Events**:
  - Power reading of -50W for "appliance1".
- **Expected Outcome**: Power consumption anomaly (≤ 0).

### Test Case 6: Power Spike
- **Scenario**: Device reports 160W, historical average 100W.
- **Events**:
  - Historical: [100W, 100W, 100W, 100W, 100W].
  - New: 160W.
- **Expected Outcome**: Power consumption anomaly (160W > 150W).

### Test Case 7: Unusual Device Access
- **Scenario**: User accesses device outside profile.
- **Events**:
  - "user1" (profile: "light1", "thermostat1") commands "camera1".
- **Expected Outcome**: Unusual device access anomaly.

### Test Case 8: Suspicious Command Sequence
- **Scenario**: "disable_alarm" and "unlock_door" within 5 seconds.
- **Events**:
  - "disable_alarm" at 12:00:00.
  - "unlock_door" at 12:00:05.
- **Expected Outcome**: Suspicious command sequence anomaly.

## 3. Edge Cases

### Test Case 9: Admin Commands Outside Business Hours
- **Scenario**: Admin issues 11 commands at 8:00 AM.
- **Events**:
  - Admin login at 8:00 AM, role "ADMIN".
  - 11 control commands to "light1" within 30 seconds.
- **Expected Outcome**: Control command rate anomaly (11 > 10).

### Test Case 10: Power Reading at 150% of Average
- **Scenario**: Power reading 150W, average 100W.
- **Events**:
  - Historical: [100W, 100W, 100W, 100W, 100W].
  - New: 150W.
- **Expected Outcome**: No anomaly (150W = 150W).

### Test Case 11: Power Reading Slightly Above 150%
- **Scenario**: Power reading 151W, average 100W.
- **Events**:
  - Historical: [100W, 100W, 100W, 100W, 100W].
  - New: 151W.
- **Expected Outcome**: Power consumption anomaly (151W > 150W).

### Test Case 12: Suspicious Sequence Outside Time Window
- **Scenario**: "disable_alarm" then "unlock_door" 15 seconds later.
- **Events**:
  - "disable_alarm" at 12:00:00.
  - "unlock_door" at 12:00:15.
- **Expected Outcome**: No anomaly (15s > 10s).

## 4. Combined Anomalies

### Test Case 13: Multi-Stage Attack
- **Scenario**: Attacker performs multiple malicious actions.
- **Events**:
  - 6 failed logins for "user1" within 1 minute.
  - Successful login at 1:01:00.
  - 12 control commands to "light1" within 30 seconds.
  - Command to "camera1" (not in profile).
  - "disable_alarm" at 1:02:00, "unlock_door" at 1:02:05.
- **Expected Outcome**:
  - Failed login rate anomaly.
  - Control command rate anomaly.
  - Unusual device access anomaly.
  - Suspicious command sequence anomaly.


---

### Conclusion
These test cases comprehensively cover the smart home system's anomaly detectors, validating their ability to distinguish legitimate high-frequency events from attack signatures. They also explore edge cases and combined scenarios to ensure robust detection of all possible anomalies.