import logging
import statistics
import time
from collections import defaultdict, deque

# Configure logging
logging.basicConfig(
    filename="logs/pwr_consum_anom.log",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


# Persistent storage for power readings per device
power_readings = defaultdict(lambda: deque())


def detect_anomalous_power(
    event_name,
    user_role,
    user_id,
    source_id,
    timestamp,
    context,
    threshold_factor=1.5,
    time_window=86400,
    min_readings=5,
):
    """
    Detects and logs anomalous power consumption values in a smart home system.

    Parameters:
    - event_name (str): Name of the event (e.g., "power_reading").
    - user_role (str): Role of the user (e.g., "ADMIN", "USER").
    - user_id (str): Unique identifier for the user.
    - source_id (str): Identifier for the source (e.g., device ID).
    - timestamp (float): Unix timestamp of the event.
    - context (dict): Event-specific data (e.g., {"value": 120.5}).
    - threshold_factor (float): Factor of historical average to flag (default: 1.5 for 150%).
    - time_window (int): Time window in seconds for historical data (default: 86400s = 1 day).
    - min_readings (int): Minimum readings required for average (default: 5).

    Returns:
    - None: Logs a warning if anomalous power consumption is detected.
    """

    # Only process "power_reading" events
    if event_name != "power_reading":
        return

    # Extract power value from context
    power_value = context.get("value")
    if power_value is None:
        logging.warning(f"Missing power value in event: user_id={user_id}, source_id={source_id}")
        return

    # Check for invalid power values (negative or zero)
    if power_value <= 0:
        logging.warning(
            f"Invalid power reading detected: user_id={user_id}, role={user_role}, "
            f"source_id={source_id}, power_value={power_value}W (negative or zero)"
        )
        return

    # Add the current power reading to the device's queue
    power_readings[source_id].append((timestamp, power_value))

    # Remove readings outside the time window
    current_time = timestamp
    while (
        power_readings[source_id] and (current_time - power_readings[source_id][0][0]) > time_window
    ):
        power_readings[source_id].popleft()

    # Check if there are enough readings to compute a historical average
    if len(power_readings[source_id]) < min_readings:
        return  # Not enough data to detect anomalies

    # Calculate the historical average
    historical_values = [reading[1] for reading in power_readings[source_id]]
    avg_power = statistics.mean(historical_values)
    threshold = avg_power * threshold_factor

    # Check if the current reading is significantly out-of-range
    if power_value > threshold:
        logging.warning(
            f"Anomalous power consumption detected: user_id={user_id}, role={user_role}, "
            f"source_id={source_id}, power_value={power_value}W, "
            f"historical_avg={avg_power:.2f}W, threshold={threshold:.2f}W"
        )


# Example usage
if __name__ == "__main__":
    # Simulate power consumption events
    current_time = time.time()
    test_events = [
        {
            "event_name": "power_reading",
            "user_role": "USER",
            "user_id": "u123",
            "source_id": "device_001",
            "timestamp": current_time - 7200,
            "context": {"value": 100.0},
        },
        {
            "event_name": "power_reading",
            "user_role": "USER",
            "user_id": "u123",
            "source_id": "device_001",
            "timestamp": current_time - 5400,
            "context": {"value": 105.0},
        },
        {
            "event_name": "power_reading",
            "user_role": "USER",
            "user_id": "u123",
            "source_id": "device_001",
            "timestamp": current_time - 3600,
            "context": {"value": 98.0},
        },
        {
            "event_name": "power_reading",
            "user_role": "USER",
            "user_id": "u123",
            "source_id": "device_001",
            "timestamp": current_time - 1800,
            "context": {"value": 102.0},
        },
        {
            "event_name": "power_reading",
            "user_role": "USER",
            "user_id": "u123",
            "source_id": "device_001",
            "timestamp": current_time - 300,
            "context": {"value": 112.0},
        },
        {
            "event_name": "power_reading",
            "user_role": "USER",
            "user_id": "u123",
            "source_id": "device_001",
            "timestamp": current_time,
            "context": {"value": 200.0},
        },  # Anomalous reading (>150% of avg)
        {
            "event_name": "power_reading",
            "user_role": "USER",
            "user_id": "u123",
            "source_id": "device_002",
            "timestamp": current_time,
            "context": {"value": -10.0},
        },  # Invalid reading (negative)
    ]

    # Process events
    for event in test_events:
        detect_anomalous_power(
            event["event_name"],
            event["user_role"],
            event["user_id"],
            event["source_id"],
            event["timestamp"],
            event["context"],
        )
