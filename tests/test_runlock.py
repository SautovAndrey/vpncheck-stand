"""Лок телефона: пока держит живой процесс - второй прогон его не займёт."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from stand import runlock, storage  # noqa: E402


class RunLockTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vpncheck-test-")
        self.old_dir, self.old_lock = storage.APP_DIR, runlock.LOCK_PATH
        storage.APP_DIR = self.tmp
        runlock.LOCK_PATH = os.path.join(self.tmp, "phone.lock")

    def tearDown(self):
        for serial in ("", "PHONE_A", "PHONE_B", "S1", "S2"):
            runlock.release(serial)
        storage.APP_DIR, runlock.LOCK_PATH = self.old_dir, self.old_lock
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_two_phones_lock_independently(self):
        self.assertTrue(runlock.acquire("PHONE_A"))
        with open(runlock.lock_path("PHONE_A"), "w", encoding="utf-8") as f:
            f.write(str(os.getppid()))
        self.assertFalse(runlock.acquire("PHONE_A"))
        self.assertTrue(runlock.acquire("PHONE_B"))
        self.assertEqual(runlock.holder("PHONE_A"), os.getppid())

    def test_serial_is_sanitized_for_filename(self):
        path = runlock.lock_path("192.168.1.5:5555")
        self.assertNotIn(":", os.path.basename(path))

    def test_acquire_and_release(self):
        self.assertTrue(runlock.acquire())
        self.assertEqual(runlock.holder(), 0)
        runlock.release()
        self.assertEqual(runlock._read_lock(runlock.LOCK_PATH), (0, None))
        self.assertTrue(runlock.acquire())

    def test_busy_when_other_alive(self):
        runlock.acquire()
        with open(runlock.LOCK_PATH, "w", encoding="utf-8") as f:
            f.write(str(os.getppid()))
        self.assertNotEqual(runlock.holder(), 0)
        self.assertFalse(runlock.acquire())

    def test_steals_stale_lock(self):
        with open(runlock.LOCK_PATH, "w", encoding="utf-8") as f:
            f.write("999999")
        self.assertEqual(runlock.holder(), 0)
        self.assertTrue(runlock.acquire())

    def test_second_run_in_same_process_is_refused(self):
        self.assertTrue(runlock.acquire("PHONE_A"))
        self.assertFalse(runlock.acquire("PHONE_A"))
        runlock.release("PHONE_A")
        self.assertTrue(runlock.acquire("PHONE_A"))

    def test_empty_lock_file_is_free(self):
        open(runlock.LOCK_PATH, "w").close()
        self.assertEqual(runlock.holder(), 0)
        self.assertTrue(runlock.acquire())

    def run_children(self, code, count):
        env = dict(os.environ, PYTHONPATH=ROOT)
        procs = [subprocess.Popen([sys.executable, "-c", code, self.tmp, str(time.time() + 3)],
                                  stdout=subprocess.PIPE, text=True, env=env) for _ in range(count)]
        return [proc.communicate(timeout=60)[0].strip() for proc in procs]

    def test_stale_lock_race_has_one_winner(self):
        code = ";".join(["import sys, time", "from stand import storage, runlock", "storage.APP_DIR = sys.argv[1]",
                         "start = float(sys.argv[2])", "time.sleep(max(0.0, start - time.time()))",
                         "print('WIN' if runlock.acquire('S1') else 'lose', flush=True)", "time.sleep(6)"])
        for _ in range(3):
            with open(runlock.lock_path("S1"), "w", encoding="utf-8") as f:
                f.write("999999 1")
            self.assertEqual(self.run_children(code, 5).count("WIN"), 1)

    def test_lock_of_finished_process_is_free(self):
        code = ";".join(["import sys", "from stand import storage, runlock", "storage.APP_DIR = sys.argv[1]",
                         "print(runlock.acquire('S2'), flush=True)"])
        self.assertEqual(self.run_children(code, 1), ["True"])
        self.assertEqual(runlock.holder("S2"), 0)
        self.assertTrue(runlock.acquire("S2"))
        runlock.release("S2")

    def test_new_format_file_without_os_lock_is_free(self):
        parent = os.getppid()
        started = runlock.process_started(parent)
        if started is None:
            self.skipTest("process start time is not available")
        for mark in (started, started + 12345):
            with open(runlock.lock_path("PHONE_A"), "w", encoding="utf-8") as f:
                f.write("%d %d" % (parent, mark))
            self.assertEqual(runlock.holder("PHONE_A"), 0)
            self.assertTrue(runlock.acquire("PHONE_A"))
            runlock.release("PHONE_A")

    def test_old_format_alive_pid_still_busy(self):
        with open(runlock.lock_path("PHONE_A"), "w", encoding="utf-8") as f:
            f.write(str(os.getppid()))
        self.assertEqual(runlock.holder("PHONE_A"), os.getppid())
        self.assertFalse(runlock.acquire("PHONE_A"))

    def test_own_lock_records_start_time(self):
        self.assertTrue(runlock.acquire("PHONE_B"))
        pid, started = runlock._read_lock(runlock.lock_path("PHONE_B"))
        self.assertEqual(pid, os.getpid())
        self.assertEqual(started, runlock.process_started(os.getpid()))


if __name__ == "__main__":
    unittest.main()
