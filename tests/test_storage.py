"""Файлы стенда пишутся атомарно: оборванная запись не оставляет пустых настроек и подключений."""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stand import dcprobe, storage  # noqa: E402


class StorageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vpncheck-test-")
        self.patch = mock.patch.multiple(storage, APP_DIR=self.tmp, RUNS_DIR=os.path.join(self.tmp, "runs"),
                                         SETTINGS_PATH=os.path.join(self.tmp, "settings.json"),
                                         CONNECTIONS_PATH=os.path.join(self.tmp, "connections.json"))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_failed_write_keeps_old_file(self):
        storage.save_settings({"batch": 5})
        with mock.patch.object(storage.json, "dump", side_effect=OSError("disk full")), \
                self.assertRaises(OSError):
            storage.save_settings({"batch": 6})
        self.assertEqual(storage.load_settings()["batch"], 5)
        self.assertEqual([n for n in os.listdir(self.tmp) if n.endswith(".tmp")], [])

    def test_runs_in_same_second_get_own_files(self):
        with mock.patch.object(storage.time, "strftime", return_value="2026-01-01_00-00-00"):
            paths = [storage.save_run({"n": i}) for i in range(3)]
        self.assertEqual(len(set(paths)), 3)
        for i, path in enumerate(paths):
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle), {"n": i})
        storage.update_run(paths[0], {"n": 9})
        with open(paths[0], encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), {"n": 9})

    def test_parallel_connection_updates_are_not_lost(self):
        storage.save_connections({"panels": {}, "probe": {"host": "h"}})

        def add(i):
            storage.update_connections(lambda data: data["panels"].__setitem__("p%d" % i, {"url": "u"}))

        threads = [threading.Thread(target=add, args=(i,)) for i in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        data = storage.load_connections()
        self.assertEqual(len(data["panels"]), 20)
        self.assertEqual(data["probe"]["host"], "h")

    def test_host_key_goes_through_locked_update(self):
        storage.save_connections({"panels": {"a": {"url": "u"}}, "probe": {"host": "h", "port": 22}})
        dcprobe.remember_host_key({"host": "h", "port": 22}, "ssh-ed25519 AAAA")
        data = storage.load_connections()
        self.assertEqual(data["probe"]["host_key"], "ssh-ed25519 AAAA")
        self.assertEqual(data["panels"], {"a": {"url": "u"}})

    @unittest.skipIf(os.name == "nt", "file permissions - POSIX only")
    def test_connections_private(self):
        storage.save_connections({"panels": {}, "probe": {}})
        self.assertEqual(os.stat(storage.CONNECTIONS_PATH).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
