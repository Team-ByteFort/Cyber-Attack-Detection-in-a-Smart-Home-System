import logging
import time
from collections import defaultdict

# Configure logging
logging.basicConfig(
    filename="logs/toggle_spam.log",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


class ToggleSpamDetector:
    def __init__(self, max_commands=10, time_window=60):
        """
        Initialize the toggle spam detector.
        :param max_commands: Maximum allowed commands in time_window (default: 10)
        :param time_window: Time window in seconds for tracking commands (default: 60s)
        """
        self.max_commands = max_commands
        self.time_window = time_window
        # Store commands as {source_id: [(timestamp, event_name, user_role, user_id, context)]}
        self.commands = defaultdict(list)

    def log_control_command(self, event_name, user_role, user_id, source_id, timestamp, context):
        """
        Log a control command and check for abnormal frequency (toggle spam).
        :param event_name: Name of the event (e.g., 'toggle_device')
        :param user_role: Role of user (e.g., 'ADMIN', 'USER')
        :param user_id: Unique user identifier
        :param source_id: Source identifier (e.g., IP address, device ID)
        :param timestamp: Unix timestamp of the command
        :param context: Event-specific context (e.g., {'success': False, 'value': 120.5})
        :return: None
        """
        # Add the new command
        self.commands[source_id].append((timestamp, event_name, user_role, user_id, context))

        # Remove commands outside the time window
        self.commands[source_id] = [
            cmd for cmd in self.commands[source_id] if timestamp - cmd[0] <= self.time_window
        ]

        # Check if the number of commands exceeds the threshold
        if len(self.commands[source_id]) > self.max_commands:
            self._log_suspicious_activity(source_id, event_name, user_role, user_id, context)

    def _log_suspicious_activity(self, source_id, event_name, user_role, user_id, context):
        """
        Log suspicious activity to the configured logger.
        :param source_id: Source identifier (e.g., IP, device ID)
        :param event_name: Name of the event
        :param user_role: Role of user
        :param user_id: Unique user identifier
        :param context: Event-specific context
        """
        message = (
            f"Suspicious activity detected: "
            f"Abnormal frequency of control commands from source {source_id}. "
            f"Event: {event_name}, User ID: {user_id}, User Role: {user_role}, "
            f"Commands: {len(self.commands[source_id])} in last {self.time_window} seconds, "
            f"Context: {context}"
        )
        logging.warning(message)


# Example usage
def main():
    detector = ToggleSpamDetector(max_commands=3, time_window=30)  # 3 commands in 30 seconds

    # Simulate control commands
    current_time = time.time()
    test_commands = [
        (
            "toggle_device",
            "USER",
            "user123",
            "192.168.1.1",
            current_time,
            {"success": True, "value": "ON"},
        ),
        (
            "toggle_device",
            "USER",
            "user123",
            "192.168.1.1",
            current_time + 5,
            {"success": True, "value": "OFF"},
        ),
        (
            "toggle_device",
            "USER",
            "user123",
            "192.168.1.1",
            current_time + 10,
            {"success": True, "value": "ON"},
        ),
        (
            "toggle_device",
            "USER",
            "user123",
            "192.168.1.1",
            current_time + 15,
            {"success": True, "value": "OFF"},
        ),  # Triggers warning
        (
            "toggle_device",
            "ADMIN",
            "admin456",
            "device_789",
            current_time,
            {"success": False, "value": "ERROR"},
        ),
    ]

    for cmd in test_commands:
        detector.log_control_command(*cmd)
        time.sleep(0.1)  # Small delay for simulation


if __name__ == "__main__":
    main()
