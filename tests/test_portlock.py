"""Окна портов: два держателя (в одном процессе или в разных) никогда не получают одно окно."""
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from stand import multiphone, portlock, storage  # noqa: E402
from stand.xray import port_shift  # noqa: E402

HOLDER = textwrap.dedent("""
    import sys, time
    sys.path.insert(0, sys.argv[1])
    from stand import portlock, storage
    storage.APP_DIR = sys.argv[2]
    index = portlock.acquire()
    print(index, flush=True)
    sys.stdin.readline()
""")


class PortLockTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old_dir = storage.APP_DIR
        storage.APP_DIR = self.tmp

    def tearDown(self):
        portlock.release_all(portlock.held())
        storage.APP_DIR = self.old_dir
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_same_process_gets_distinct_windows(self):
        first, second = portlock.acquire(), portlock.acquire()
        self.assertEqual((first, second), (0, 1))
        portlock.release(first)
        self.assertEqual(portlock.acquire(), 0)

    def test_other_process_window_is_skipped_and_freed_on_exit(self):
        proc = subprocess.Popen([sys.executable, "-c", HOLDER, ROOT, self.tmp], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), "0")
            mine = portlock.acquire()
            self.assertEqual(mine, 1)
            portlock.release(mine)
        finally:
            proc.stdin.close()
            proc.wait(10)
        self.assertEqual(portlock.acquire(), 0)

    def test_all_busy(self):
        taken = [portlock.acquire() for _ in range(portlock.WINDOWS)]
        self.assertNotIn(None, taken)
        self.assertIsNone(portlock.acquire())

    def test_lease_gives_phone_jobs_distinct_shifts(self):
        jobs = [multiphone.Job(None, 0, "ДЦ", [], {}), multiphone.Job("A", 0, "", [], {}),
                multiphone.Job("B", 0, "", [], {})]
        other = portlock.acquire()
        leased, held = multiphone.lease_port_windows(jobs)
        self.assertEqual([job.shift for job in leased], [0, port_shift(1), port_shift(2)])
        self.assertEqual(held, [1, 2])
        portlock.release_all(held)
        portlock.release(other)


if __name__ == "__main__":
    unittest.main()
