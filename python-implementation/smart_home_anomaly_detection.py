import datetime
import json
from collections import deque

# Constants
BUSINESS_HOURS_START = 9
BUSINESS_HOURS_END = 20
FAILED_LOGIN_WINDOW = datetime.timedelta(minutes=1)
FAILED_LOGIN_THRESHOLD = 5
CONTROL_COMMAND_WINDOW = datetime.timedelta(seconds=30)
CONTROL_COMMAND_THRESHOLD = 10
CONTROL_COMMAND_THRESHOLD_ADMIN = 20
POWER_READING_HISTORY = 100
SUSPICIOUS_SEQUENCES = [
    (("disable_alarm", "unlock_door"), datetime.timedelta(seconds=10)),
]

# State to track events and historical data
state = {
    "failed_logins": {},  # user_id: deque of timestamps
    "control_commands": {},  # (user_id, device_id): deque of timestamps
    "power_readings": {},  # device_id: list of values
    "user_profiles": {  # user_id: set of device_ids (pre-populated or updated)
        "user1": {"light1", "thermostat1"},
        "user2": {"light1", "thermostat1"},
        "admin1": {"light1", "camera1", "alarm1", "door1"},
    },
    "user_commands": {},  # user_id: list of (command, timestamp)
}


# Helper function to check business hours
def is_business_hours(timestamp):
    hour = timestamp.hour
    return BUSINESS_HOURS_START <= hour < BUSINESS_HOURS_END


# Anomaly detectors
def check_failed_login_rate(event, state):
    if event["type"] == "login_attempt" and not event["success"]:
        user_id = event["user_id"]
        now = event["timestamp"]
        failed_logins = state["failed_logins"].setdefault(user_id, deque())
        while failed_logins and now - failed_logins[0] > FAILED_LOGIN_WINDOW:
            failed_logins.popleft()
        failed_logins.append(now)
        if len(failed_logins) > FAILED_LOGIN_THRESHOLD:
            return True, {
                "type": "failed_login_rate",
                "user_id": user_id,
                "count": len(failed_logins),
            }
    return False, None


def check_control_command_rate(event, state):
    if event["type"] == "control_command":
        user_id = event["user_id"]
        role = event["role"]
        timestamp = event["timestamp"]
        device_id = event["device_id"]
        key = (user_id, device_id)
        commands = state["control_commands"].setdefault(key, deque())
        while commands and timestamp - commands[0] > CONTROL_COMMAND_WINDOW:
            commands.popleft()
        commands.append(timestamp)
        count = len(commands)
        threshold = CONTROL_COMMAND_THRESHOLD
        if role in ["ADMIN", "MANAGER"] and is_business_hours(timestamp):
            threshold = CONTROL_COMMAND_THRESHOLD_ADMIN
        if count > threshold:
            return True, {
                "type": "control_command_rate",
                "user_id": user_id,
                "device_id": device_id,
                "count": count,
            }
    return False, None


def check_power_consumption(event, state):
    if event["type"] == "sensor_reading" and event["reading_type"] == "power":
        device_id = event["device_id"]
        value = event["value"]
        if value <= 0:
            return True, {"type": "invalid_power_reading", "device_id": device_id, "value": value}
        historical_values = state["power_readings"].setdefault(device_id, [])
        if historical_values:
            avg = sum(historical_values) / len(historical_values)
            if value > 1.5 * avg:
                return True, {
                    "type": "high_power_reading",
                    "device_id": device_id,
                    "value": value,
                    "average": avg,
                }
        historical_values.append(value)
        if len(historical_values) > POWER_READING_HISTORY:
            historical_values.pop(0)
    return False, None


def check_unusual_device_access(event, state):
    if event["type"] == "control_command":
        user_id = event["user_id"]
        device_id = event["device_id"]
        common_devices = state["user_profiles"].setdefault(user_id, set())
        if device_id not in common_devices:
            return True, {
                "type": "unusual_device_access",
                "user_id": user_id,
                "device_id": device_id,
            }
    return False, None


def check_command_sequence(event, state):
    if event["type"] == "control_command":
        user_id = event["user_id"]
        command = event["command"]
        timestamp = event["timestamp"]
        recent_commands = state["user_commands"].setdefault(user_id, [])
        recent_commands = [
            (cmd, ts)
            for cmd, ts in recent_commands
            if timestamp - ts < datetime.timedelta(minutes=1)
        ]
        recent_commands.append((command, timestamp))
        state["user_commands"][user_id] = recent_commands
        for sequence, time_window in SUSPICIOUS_SEQUENCES:
            if len(recent_commands) >= len(sequence):
                last_cmds = [cmd for cmd, _ in recent_commands[-len(sequence) :]]
                if tuple(last_cmds) == sequence:
                    first_ts = recent_commands[-len(sequence)][1]
                    if timestamp - first_ts <= time_window:
                        return True, {
                            "type": "suspicious_sequence",
                            "user_id": user_id,
                            "sequence": list(sequence),
                        }
    return False, None


# List of detectors
detectors = [
    check_failed_login_rate,
    check_control_command_rate,
    check_power_consumption,
    check_unusual_device_access,
    check_command_sequence,
]


# Logging function
def log_event(event, anomalies):
    # Make a shallow copy of the event and convert timestamp to ISO format
    event_copy = event.copy()
    if isinstance(event_copy.get("timestamp"), datetime.datetime):
        event_copy["timestamp"] = event_copy["timestamp"].isoformat()
    log_entry = {
        "timestamp": event_copy["timestamp"],
        "event": event_copy,
        "anomalies": anomalies,
        "alert": len(anomalies) > 0,
    }
    with open("anomaly_log.json", "a") as f:
        f.write(json.dumps(log_entry) + "\n")


# Main processing function
def process_event(event):
    anomalies = []
    for detector in detectors:
        is_anomaly, anomaly_info = detector(event, state)
        if is_anomaly:
            anomalies.append(anomaly_info)
    log_event(event, anomalies)
    return anomalies


# Example usage with simulated events
if __name__ == "__main__":
    now = datetime.datetime.now()

    # --- Normal login attempts ---
    normal_login_events = [
        {"type": "login_attempt", "timestamp": now, "user_id": "user1", "success": True},
        {"type": "login_attempt", "timestamp": now + datetime.timedelta(seconds=10), "user_id": "user1", "success": False},
        {"type": "login_attempt", "timestamp": now + datetime.timedelta(seconds=20), "user_id": "user1", "success": False},
    ]

    # --- Abnormal: multiple failed login attempts ---
    abnormal_login_events = [
        {"type": "login_attempt", "timestamp": now + datetime.timedelta(seconds=i*5 + 65), "user_id": "user1", "success": False}
        for i in range(6)
    ]

    # --- Normal control commands ---
    normal_control_commands = [
        {"type": "control_command", "timestamp": now + datetime.timedelta(seconds=i * 5), "user_id": "admin1", "role": "ADMIN", "device_id": "light1", "command": "on"}
        for i in range(11)
    ] + [
        {"type": "control_command", "timestamp": now + datetime.timedelta(seconds=i * 5), "user_id": "user1", "role": "USER", "device_id": "light1", "command": "off"}
        for i in range(5)
    ]

    # --- Abnormal: excessive control commands within short time ---
    abnormal_control_commands = [
        {"type": "control_command", "timestamp": now + datetime.timedelta(seconds=i), "user_id": "user2", "role": "USER", "device_id": "light1", "command": "on"}
        for i in range(11)
    ]

    # --- Normal power readings ---
    normal_power_readings = [
        {"type": "sensor_reading", "timestamp": now + datetime.timedelta(seconds=i), "device_id": "thermostat1", "reading_type": "power", "value": 100 + i}
        for i in range(20)
    ]

    # --- Abnormal: high power reading ---
    abnormal_power_reading = [
        {"type": "sensor_reading", "timestamp": now + datetime.timedelta(seconds=30), "device_id": "thermostat1", "reading_type": "power", "value": 300.0}
    ]

    # --- Abnormal: zero power reading ---
    zero_power_reading = [
        {"type": "sensor_reading", "timestamp": now + datetime.timedelta(seconds=31), "device_id": "thermostat1", "reading_type": "power", "value": 0.0}
    ]

    # --- Abnormal: unusual device access ---
    abnormal_device_access = [
        {"type": "control_command", "timestamp": now + datetime.timedelta(seconds=40), "user_id": "user1", "role": "USER", "device_id": "camera1", "command": "view"},
    ]

    # --- Abnormal: suspicious command sequence ---
    suspicious_sequence = [
        {"type": "control_command", "timestamp": now + datetime.timedelta(seconds=50), "user_id": "user1", "role": "USER", "device_id": "alarm1", "command": "disable_alarm"},
        {"type": "control_command", "timestamp": now + datetime.timedelta(seconds=55), "user_id": "user1", "role": "USER", "device_id": "door1", "command": "unlock_door"},
    ]

    # Combine all events
    all_events = (
        normal_login_events +
        abnormal_login_events +
        normal_control_commands +
        abnormal_control_commands +
        normal_power_readings +
        abnormal_power_reading +
        zero_power_reading +
        abnormal_device_access +
        suspicious_sequence
    )

    # Process each event
    for event in all_events:
        anomalies = process_event(event)
        if anomalies:
            print(f"Anomalies detected: {anomalies}")
