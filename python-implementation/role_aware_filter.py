from datetime import datetime


class RoleAwareFilter:
    def __init__(self, ignore_roles_during_business_hours, is_business_hours_func=None):
        """
        Initialize the RoleAwareFilter.

        Args:
            ignore_roles_during_business_hours (list): List of roles to ignore during business hours.
            is_business_hours_func (function, optional): Function to determine if a timestamp is within business hours.
                If not provided, a default function is used.
        """
        self.ignore_roles = set(ignore_roles_during_business_hours)
        if is_business_hours_func is None:
            self.is_business_hours = self.default_is_business_hours
        else:
            self.is_business_hours = is_business_hours_func

    @staticmethod
    def default_is_business_hours(timestamp):
        """
        Default function to check if the given timestamp is within business hours.
        Business hours are 9 AM to 5 PM, Monday to Friday.

        Args:
            timestamp (float): Unix timestamp in seconds.

        Returns:
            bool: True if within business hours, False otherwise.
        """
        dt = datetime.fromtimestamp(timestamp)
        if dt.weekday() >= 5:  # Saturday or Sunday
            return False
        return 9 <= dt.hour <= 17

    def filter_event(self, event_name, user_role, user_id, source_id, timestamp, context):
        """
        Determine whether to process the event based on role and timestamp.

        Args:
            event_name (str): Name of the event.
            user_role (str): Role of the user.
            user_id (str): Unique identifier for the user.
            source_id (str): Identifier for the source (e.g., IP address or device ID).
            timestamp (float): Unix timestamp in seconds when the event occurred.
            context (dict): Additional event-specific information.

        Returns:
            bool: True if the event should be processed, False if it should be ignored.
        """
        if user_role in self.ignore_roles:
            return not self.is_business_hours(timestamp)
        else:
            return True

    def __call__(self, event_name, user_role, user_id, source_id, timestamp, context):
        """
        Make the instance callable to filter events directly.

        Args:
            event_name (str): Name of the event.
            user_role (str): Role of the user.
            user_id (str): Unique identifier for the user.
            source_id (str): Identifier for the source (e.g., IP address or device ID).
            timestamp (float): Unix timestamp in seconds when the event occurred.
            context (dict): Additional event-specific information.

        Returns:
            bool: True if the event should be processed, False if it should be ignored.
        """
        return self.filter_event(event_name, user_role, user_id, source_id, timestamp, context)
