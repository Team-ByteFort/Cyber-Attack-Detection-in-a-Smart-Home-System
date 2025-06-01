from datetime import datetime


class OutsideActiveHoursDetector:
    """
    Detects anomalies based on events occurring outside specified active hours.
    """

    def __init__(self, start_hour=6, end_hour=23):
        """
        Initialize the detector with active hours.

        Args:
            start_hour (int): Starting hour of active period (0-23).
            end_hour (int): Ending hour of active period (0-23).
        """
        self.start_hour = start_hour
        self.end_hour = end_hour

    def detect(self, event_name, user_role, user_id, source_id, timestamp, context):
        """
        Check if the event timestamp is outside active hours.

        Args:
            event_name (str): Name of the event.
            user_role (str): Role of the user.
            user_id (str): User identifier.
            source_id (str): Source identifier.
            timestamp (float): Unix timestamp of the event.
            context (dict): Additional context.

        Returns:
            bool: True if anomaly detected, False otherwise.
        """
        dt = datetime.fromtimestamp(timestamp)
        hour = dt.hour
        if hour < self.start_hour or hour >= self.end_hour:
            return True
        else:
            return False
