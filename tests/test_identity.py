"""Test 3/9 — device identity stability (regression: v1 included the PID and
re-registered the same device on every launch)."""
import unittest
from unittest import mock

from tests import REPO_ROOT  # noqa: F401
from hashflow.core import get_device_id


class TestDeviceId(unittest.TestCase):
    def test_id_is_stable_across_calls(self):
        self.assertEqual(get_device_id(), get_device_id())

    def test_id_format(self):
        dev = get_device_id()
        self.assertEqual(len(dev), 12)
        self.assertRegex(dev, r"^[0-9a-f]{12}$")

    def test_pid_not_in_identity(self):
        """Two processes with different PIDs but same host/MAC get one ID."""
        with mock.patch("hashflow.core.platform.node", return_value="host-a"), \
             mock.patch("hashflow.core.uuid.getnode", return_value=123456789):
            with mock.patch("os.getpid", return_value=111):
                id_a = get_device_id()
            with mock.patch("os.getpid", return_value=999):
                id_b = get_device_id()
        self.assertEqual(id_a, id_b)

    def test_different_host_or_mac_gives_different_id(self):
        with mock.patch("hashflow.core.platform.node", return_value="host-a"), \
             mock.patch("hashflow.core.uuid.getnode", return_value=1):
            id_a = get_device_id()
        with mock.patch("hashflow.core.platform.node", return_value="host-b"), \
             mock.patch("hashflow.core.uuid.getnode", return_value=1):
            id_b = get_device_id()
        self.assertNotEqual(id_a, id_b)


if __name__ == "__main__":
    unittest.main()
