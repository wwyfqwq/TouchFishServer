import errno
import json
import logging
import os
import tempfile
import threading
import time
from contextlib import contextmanager


_thread_locks = {}
_thread_locks_guard = threading.Lock()


def _thread_lock(path):
    absolute_path = os.path.abspath(path)
    with _thread_locks_guard:
        return _thread_locks.setdefault(absolute_path, threading.Lock())


def _lock_windows(file, msvcrt):
    file.seek(0)
    while True:
        try:
            # Windows supports locking a byte range past EOF.
            msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
            return
        except OSError as error:
            winerror = getattr(error, "winerror", None)
            if winerror is not None:
                contention = winerror in (32, 33)
            else:
                contention = error.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK)
            if not contention:
                raise
            time.sleep(0.01)


@contextmanager
def file_lock(path):
    lock_path = os.path.abspath(path) + ".lock"
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    with _thread_lock(path), open(lock_path, "a+b") as lock_file:
        if os.name == "nt":
            import msvcrt
            _lock_windows(lock_file, msvcrt)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


@contextmanager
def atomic_output(path, mode, **kwargs):
    """Publish a complete owner-only file in the destination directory."""
    absolute_path = os.path.abspath(path)
    directory = os.path.dirname(absolute_path)
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".tf-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, mode, **kwargs) as file:
            yield file
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_path, absolute_path)
    finally:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


def restrict_private_file(file):
    if os.name == "posix":
        mode = os.fstat(file.fileno()).st_mode
        if mode & 0o077:
            try:
                os.fchmod(file.fileno(), mode & 0o700)
            except OSError as error:
                if error.errno not in (errno.EROFS, errno.EPERM, errno.EACCES):
                    raise
                # Administrators may provision a group-readable file via a read-only
                # volume. Keep using its supplied permissions and report what happened.
                logging.getLogger(__name__).warning(
                    "Private key permissions are externally managed for %s (mode %03o)",
                    file.name, mode & 0o777)



def _write_unlocked(path, value):
    with atomic_output(path, "w", encoding="utf-8") as file:
        json.dump(value, file, ensure_ascii=False)


def read_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def write_json(path, value):
    with file_lock(path):
        _write_unlocked(path, value)


_MISSING = object()


def update_json(path, mutator, default=_MISSING):
    with file_lock(path):
        try:
            value = read_json(path)
        except FileNotFoundError:
            if default is _MISSING:
                raise
            value = default() if callable(default) else default
        result = mutator(value)
        _write_unlocked(path, value)
        return result
