import datetime
import json
from collections import deque

# Constants
BUSINESS_HOURS_START = 9
BUSINESS_HOURS_END = 17
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
    # Simulate some events
    events = [
        # Historical power readings for baseline
        {
            "type": "sensor_reading",
            "timestamp": datetime.datetime(2023, 10, 1, 8, 0, 0),
            "device_id": "appliance1",
            "reading_type": "power",
            "value": 100,
        },
        {
            "type": "sensor_reading",
            "timestamp": datetime.datetime(2023, 10, 1, 8, 30, 0),
            "device_id": "appliance1",
            "reading_type": "power",
            "value": 100,
        },
        {
            "type": "sensor_reading",
            "timestamp": datetime.datetime(2023, 10, 1, 9, 0, 0),
            "device_id": "appliance1",
            "reading_type": "power",
            "value": 100,
        },
        {
            "type": "sensor_reading",
            "timestamp": datetime.datetime(2023, 10, 1, 9, 30, 0),
            "device_id": "appliance1",
            "reading_type": "power",
            "value": 100,
        },
        # Normal operations
        {
            "type": "login_attempt",
            "timestamp": datetime.datetime(2023, 10, 1, 9, 0, 0),
            "user_id": "admin1",
            "success": True,
            "role": "ADMIN",
        },
        {
            "type": "control_command",
            "timestamp": datetime.datetime(2023, 10, 1, 9, 5, 0),
            "user_id": "admin1",
            "role": "ADMIN",
            "device_id": "light1",
            "command": "on",
        },
        {
            "type": "login_attempt",
            "timestamp": datetime.datetime(2023, 10, 1, 9, 10, 0),
            "user_id": "user1",
            "success": True,
            "role": "USER",
        },
        {
            "type": "control_command",
            "timestamp": datetime.datetime(2023, 10, 1, 9, 15, 0),
            "user_id": "user1",
            "role": "USER",
            "device_id": "thermostat1",
            "command": "set_temperature",
        },
        {
            "type": "control_command",
            "timestamp": datetime.datetime(2023, 10, 1, 9, 20, 0),
            "user_id": "user1",
            "role": "USER",
            "device_id": "light1",
            "command": "off",
        },
        {
            "type": "control_command",
            "timestamp": datetime.datetime(2023, 10, 1, 9, 25, 0),
            "user_id": "admin1",
            "role": "ADMIN",
            "device_id": "light1",
            "command": "off",
        },
        # Attack scenario: Multiple failed login attempts
        {
            "type": "login_attempt",
            "timestamp": datetime.datetime(2023, 10, 1, 10, 0, 0),
            "user_id": "user1",
            "success": False,
        },
        {
            "type": "login_attempt",
            "timestamp": datetime.datetime(2023, 10, 1, 10, 0, 10),
            "user_id": "user1",
            "success": False,
        },
        {
            "type": "login_attempt",
            "timestamp": datetime.datetime(2023, 10, 1, 10, 0, 20),
            "user_id": "user1",
            "success": False,
        },
        {
            "type": "login_attempt",
            "timestamp": datetime.datetime(2023, 10, 1, 10, 0, 30),
            "user_id": "user1",
            "success": False,
        },
        {
            "type": "login_attempt",
            "timestamp": datetime.datetime(2023, 10, 1, 10, 0, 40),
            "user_id": "user1",
            "success": False,
        },
        {
            "type": "login_attempt",
            "timestamp": datetime.datetime(2023, 10, 1, 10, 0, 50),
            "user_id": "user1",
            "success": False,
        },
        {
            "type": "login_attempt",
            "timestamp": datetime.datetime(2023, 10, 1, 10, 1, 0),
            "user_id": "user1",
            "success": True,
            "role": "USER",
        },
        # Attack scenario: Rapid control commands
        *[
            {
                "type": "control_command",
                "timestamp": datetime.datetime(2023, 10, 1, 10, 10, 0)
                + datetime.timedelta(seconds=i * 2),
                "user_id": "user1",
                "role": "USER",
                "device_id": "light1",
                "command": "on",
            }
            for i in range(15)
        ],
        # Attack scenario: Anomalous power readings
        {
            "type": "sensor_reading",
            "timestamp": datetime.datetime(2023, 10, 1, 10, 15, 0),
            "device_id": "appliance1",
            "reading_type": "power",
            "value": -50,
        },
        {
            "type": "sensor_reading",
            "timestamp": datetime.datetime(2023, 10, 1, 10, 16, 0),
            "device_id": "appliance1",
            "reading_type": "power",
            "value": 100,
        },
        {
            "type": "sensor_reading",
            "timestamp": datetime.datetime(2023, 10, 1, 10, 20, 0),
            "device_id": "appliance1",
            "reading_type": "power",
            "value": 160,
        },
        # Attack scenario: Unusual device access and suspicious command sequence
        {
            "type": "control_command",
            "timestamp": datetime.datetime(2023, 10, 1, 10, 25, 0),
            "user_id": "user1",
            "role": "USER",
            "device_id": "alarm1",
            "command": "disable_alarm",
        },
        {
            "type": "control_command",
            "timestamp": datetime.datetime(2023, 10, 1, 10, 25, 5),
            "user_id": "user1",
            "role": "USER",
            "device_id": "door1",
            "command": "unlock_door",
        },
    ]

    # Process each event
    for event in events:
        anomalies = process_event(event)
        if anomalies:
            print(f"Anomalies detected: {anomalies}")
