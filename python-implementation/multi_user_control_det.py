class MultiUserControlDetector:
    """
    Detects anomalies when multiple users control the same device within a short time window.
    """

    def __init__(self, time_window=60):
        """
        Initialize the detector with a time window.

        Args:
            time_window (int): Time window in seconds to check for anomalies.
        """
        self.time_window = time_window
        self.last_control = {}  # device_id -> (timestamp, user_id)

    def detect(self, event_name, user_role, user_id, source_id, timestamp, context):
        """
        Check if the event indicates multiple users controlling the same device.

        Args:
            event_name (str): Name of the event.
            user_role (str): Role of the user.
            user_id (str): User identifier.
            source_id (str): Source identifier.
            timestamp (float): Unix timestamp of the event.
            context (dict): Additional context, expected to contain 'device_id' for 'toggle_device' events.

        Returns:
            bool: True if anomaly detected, False otherwise.
        """
        if event_name != "toggle_device":
            return False
        device_id = context.get("device_id")
        if not device_id:
            return False
        prev_control = self.last_control.get(device_id)
        self.last_control[device_id] = (timestamp, user_id)
        if prev_control:
            prev_time, prev_user = prev_control
            if prev_user != user_id and (timestamp - prev_time) < self.time_window:
                return True
        return False
