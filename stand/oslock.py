"""Общая блокировка ОС для лок-файлов (portlock, runlock) и сведения о процессе-держателе.

Блокируется байт далеко за концом файла: сама блокировка снимается ОС, если процесс умер,
а текст файла (PID держателя) остаётся читаемым для сообщений «занято процессом N».
"""
import os
import sys

LOCK_OFFSET = 1 << 20


def lock(handle, offset=LOCK_OFFSET):
    """True - блокировку взяли, False - её держит кто-то другой (или файл недоступен)."""
    try:
        if sys.platform == "win32":
            import msvcrt
            handle.seek(offset)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def unlock(handle, offset=LOCK_OFFSET):
    try:
        if sys.platform == "win32":
            import msvcrt
            handle.seek(offset)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass


def process_info(pid):
    """(жив ли процесс, метка его старта или None). Метка одинакова для одного процесса и разная
    для процессов с тем же PID - по ней видно, что PID переиспользован."""
    if not isinstance(pid, int) or pid <= 0:
        return False, None
    if sys.platform == "win32":
        return _windows_info(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False, None
    except PermissionError:
        pass
    except OSError:
        return False, None
    try:
        with open("/proc/%d/stat" % pid, encoding="ascii", errors="replace") as handle:
            return True, int(handle.read().rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return True, None


def _windows_info(pid):
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return ctypes.get_last_error() == 5, None
    try:
        code = ctypes.c_ulong()
        alive = (not kernel32.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code))
                 or code.value == 259)
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel32.GetProcessTimes(ctypes.c_void_p(handle), *[ctypes.byref(item) for item in times]):
            return alive, None
        return alive, (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
