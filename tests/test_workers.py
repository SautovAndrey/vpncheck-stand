"""Рабочий поток задачи: sys.exit из библиотеки (например vpncheck при ненайденном скваде)
должен превратиться в ошибку с текстом, а не уронить приложение."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from stand.ui.workers import Task  # noqa: E402

_app = QApplication.instance() or QApplication([])


class TaskTest(unittest.TestCase):
    def _capture(self, fn):
        task = Task(fn)
        errors, dones = [], []
        task.error.connect(errors.append)
        task.done.connect(dones.append)
        task.run()
        return errors, dones

    def test_systemexit_becomes_error(self):
        def boom():
            raise SystemExit("сквад Squad-Demo не найден")
        errors, dones = self._capture(boom)
        self.assertEqual(dones, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("не найден", errors[0])

    def test_exception_becomes_error(self):
        errors, dones = self._capture(lambda: (_ for _ in ()).throw(ValueError("плохо")))
        self.assertIn("плохо", errors[0])

    def test_success_delivers_result(self):
        errors, dones = self._capture(lambda: 42)
        self.assertEqual(dones, [42])
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
