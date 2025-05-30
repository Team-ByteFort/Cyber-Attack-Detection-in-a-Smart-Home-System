import logging
import time
from collections import defaultdict, deque

# Configure logging
logging.basicConfig(
    filename="logs/failed_logins.log",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def detect_failed_logins(
    event_name, user_role, user_id, source_id, timestamp, context, threshold=5, time_window=300
):
    """
    Detects and logs high number of failed login attempts within a short time.

    Parameters:
    - event_name (str): Name of the event (e.g., "login_attempt").
    - user_role (str): Role of the user (e.g., "ADMIN", "USER").
    - user_id (str): Unique identifier for the user.
    - source_id (str): Identifier for the source (e.g., IP address or device ID).
    - timestamp (float): Unix timestamp of the event.
    - context (dict): Additional event-specific data (e.g., {"success": false}).
    - threshold (int): Max allowed failed attempts before logging (default: 5).
    - time_window (int): Time window in seconds for tracking attempts (default: 300s).

    Returns:
    - None: Logs a warning if threshold is exceeded.
    """
    # Persistent storage for tracking failed attempts per user
    failed_attempts = defaultdict(lambda: deque())

    # Only process "login_attempt" events where success is False
    if event_name != "login_attempt" or context.get("success", True):
        return

    # Add the current failed attempt to the user's queue
    failed_attempts[user_id].append(timestamp)

    # Remove attempts outside the time window
    current_time = timestamp
    while failed_attempts[user_id] and (current_time - failed_attempts[user_id][0]) > time_window:
        failed_attempts[user_id].popleft()

    # Check if the number of failed attempts exceeds the threshold
    if len(failed_attempts[user_id]) >= threshold:
        logging.warning(
            f"High number of failed login attempts detected: "
            f"user_id={user_id}, role={user_role}, source_id={source_id}, "
            f"attempts={len(failed_attempts[user_id])}, time_window={time_window}s"
        )

        # Optional: Clear the queue after logging to avoid repeated alerts
        failed_attempts[user_id].clear()


# Example usage
if __name__ == "__main__":
    # Simulate failed login attempts
    current_time = time.time()
    test_events = [
        {
            "event_name": "login_attempt",
            "user_role": "USER",
            "user_id": "u123",
            "source_id": "192.168.1.1",
            "timestamp": current_time - 250,
            "context": {"success": False},
        },
        {
            "event_name": "login_attempt",
            "user_role": "USER",
            "user_id": "u123",
            "source_id": "192.168.1.1",
            "timestamp": current_time - 200,
            "context": {"success": False},
        },
        {
            "event_name": "login_attempt",
            "user_role": "USER",
            "user_id": "u123",
            "source_id": "192.168.1.1",
            "timestamp": current_time - 150,
            "context": {"success": False},
        },
        {
            "event_name": "login_attempt",
            "user_role": "USER",
            "user_id": "u123",
            "source_id": "192.168.1.1",
            "timestamp": current_time - 100,
            "context": {"success": False},
        },
        {
            "event_name": "login_attempt",
            "user_role": "USER",
            "user_id": "u123",
            "source_id": "192.168.1.1",
            "timestamp": current_time - 50,
            "context": {"success": False},
        },
    ]

    # Process events
    for event in test_events:
        detect_failed_logins(
            event["event_name"],
            event["user_role"],
            event["user_id"],
            event["source_id"],
            event["timestamp"],
            event["context"],
        )
