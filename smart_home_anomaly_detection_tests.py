import unittest
from collections import deque
from datetime import datetime, timedelta

from smart_home_anomaly_detection import (
    check_command_sequence,
    check_control_command_rate,
    check_failed_login_rate,
    check_power_consumption,
    check_unusual_device_access,
)


# Unit Tests
class TestFailedLoginRate(unittest.TestCase):
    def setUp(self):
        self.state = {"failed_logins": {}}

    def test_normal(self):
        user_id = "user1"
        now = datetime.now()
        for i in range(5):
            self.state["failed_logins"].setdefault(user_id, deque()).append(
                now - timedelta(seconds=i * 10)
            )
        event = {"type": "login_attempt", "timestamp": now, "user_id": user_id, "success": True}
        self.assertFalse(check_failed_login_rate(event, self.state)[0])
        event = {
            "type": "login_attempt",
            "timestamp": now + timedelta(minutes=2),
            "user_id": user_id,
            "success": False,
        }
        self.assertFalse(check_failed_login_rate(event, self.state)[0])

    def test_anomalous(self):
        user_id = "user1"
        now = datetime.now()
        for i in range(5):
            self.state["failed_logins"].setdefault(user_id, deque()).append(
                now - timedelta(seconds=i * 10)
            )
        event = {"type": "login_attempt", "timestamp": now, "user_id": user_id, "success": False}
        self.assertTrue(check_failed_login_rate(event, self.state)[0])


class TestControlCommandRate(unittest.TestCase):
    def setUp(self):
        self.state = {"control_commands": {}}

    def test_normal_user(self):
        user_id = "user1"
        device_id = "light1"
        now = datetime(2023, 10, 1, 14, 0, 0)
        key = (user_id, device_id)
        self.state["control_commands"][key] = deque([now - timedelta(seconds=i) for i in range(9)])
        event = {
            "type": "control_command",
            "timestamp": now,
            "user_id": user_id,
            "device_id": device_id,
            "role": "USER",
        }
        self.assertFalse(check_control_command_rate(event, self.state)[0])

    def test_anomalous_user(self):
        user_id = "user1"
        device_id = "light1"
        now = datetime(2023, 10, 1, 14, 0, 0)
        key = (user_id, device_id)
        self.state["control_commands"][key] = deque([now - timedelta(seconds=i) for i in range(10)])
        event = {
            "type": "control_command",
            "timestamp": now,
            "user_id": user_id,
            "device_id": device_id,
            "role": "USER",
        }
        self.assertTrue(check_control_command_rate(event, self.state)[0])

    def test_normal_admin_business_hours(self):
        user_id = "admin1"
        device_id = "light1"
        now = datetime(2023, 10, 1, 10, 0, 0)
        key = (user_id, device_id)
        self.state["control_commands"][key] = deque([now - timedelta(seconds=i) for i in range(19)])
        event = {
            "type": "control_command",
            "timestamp": now,
            "user_id": user_id,
            "device_id": device_id,
            "role": "ADMIN",
        }
        self.assertFalse(check_control_command_rate(event, self.state)[0])

    def test_anomalous_admin_outside_business_hours(self):
        user_id = "admin1"
        device_id = "light1"
        now = datetime(2023, 10, 1, 20, 0, 0)
        key = (user_id, device_id)
        self.state["control_commands"][key] = deque([now - timedelta(seconds=i) for i in range(10)])
        event = {
            "type": "control_command",
            "timestamp": now,
            "user_id": user_id,
            "device_id": device_id,
            "role": "ADMIN",
        }
        self.assertTrue(check_control_command_rate(event, self.state)[0])


class TestPowerConsumption(unittest.TestCase):
    def setUp(self):
        self.state = {"power_readings": {}}

    def test_normal(self):
        device_id = "appliance1"
        self.state["power_readings"][device_id] = [100, 100, 100, 100, 100]
        event = {
            "type": "sensor_reading",
            "timestamp": datetime.now(),
            "device_id": device_id,
            "reading_type": "power",
            "value": 120,
        }
        self.assertFalse(check_power_consumption(event, self.state)[0])

    def test_anomalous_non_positive(self):
        device_id = "appliance1"
        event = {
            "type": "sensor_reading",
            "timestamp": datetime.now(),
            "device_id": device_id,
            "reading_type": "power",
            "value": 0,
        }
        self.assertTrue(check_power_consumption(event, self.state)[0])

    def test_anomalous_high_reading(self):
        device_id = "appliance1"
        self.state["power_readings"][device_id] = [100, 100, 100, 100, 100]
        event = {
            "type": "sensor_reading",
            "timestamp": datetime.now(),
            "device_id": device_id,
            "reading_type": "power",
            "value": 160,
        }
        self.assertTrue(check_power_consumption(event, self.state)[0])


class TestUnusualDeviceAccess(unittest.TestCase):
    def setUp(self):
        self.state = {"user_profiles": {"user1": {"light1", "thermostat1"}}}

    def test_normal(self):
        event = {
            "type": "control_command",
            "timestamp": datetime.now(),
            "user_id": "user1",
            "device_id": "light1",
        }
        self.assertFalse(check_unusual_device_access(event, self.state)[0])

    def test_anomalous(self):
        event = {
            "type": "control_command",
            "timestamp": datetime.now(),
            "user_id": "user1",
            "device_id": "camera1",
        }
        self.assertTrue(check_unusual_device_access(event, self.state)[0])


class TestCommandSequence(unittest.TestCase):
    def setUp(self):
        self.state = {"user_commands": {}}

    def test_normal(self):
        user_id = "user1"
        now = datetime.now()
        self.state["user_commands"][user_id] = [("some_command", now - timedelta(seconds=20))]
        event = {
            "type": "control_command",
            "timestamp": now,
            "user_id": user_id,
            "command": "disable_alarm",
        }
        self.assertFalse(check_command_sequence(event, self.state)[0])

    def test_anomalous(self):
        user_id = "user1"
        now = datetime.now()
        self.state["user_commands"][user_id] = [("disable_alarm", now - timedelta(seconds=5))]
        event = {
            "type": "control_command",
            "timestamp": now,
            "user_id": user_id,
            "command": "unlock_door",
        }
        self.assertTrue(check_command_sequence(event, self.state)[0])

    def test_anomalous_outside_window(self):
        user_id = "user1"
        now = datetime.now()
        self.state["user_commands"][user_id] = [("disable_alarm", now - timedelta(seconds=15))]
        event = {
            "type": "control_command",
            "timestamp": now,
            "user_id": user_id,
            "command": "unlock_door",
        }
        self.assertFalse(check_command_sequence(event, self.state)[0])


if __name__ == "__main__":
    unittest.main()
