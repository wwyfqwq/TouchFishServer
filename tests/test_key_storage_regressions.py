from concurrent.futures import ProcessPoolExecutor
import os
from pathlib import Path
import multiprocessing

import pytest

import crypto
import jwt_tool
from json_store import atomic_output


def test_concurrent_signing_key_initialization(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context("spawn")) as jobs:
        keys = list(jobs.map(jwt_tool.load_secret, [7001] * 12))
    assert len(set(keys)) == 1
    assert len(keys[0]) == 64
    path = Path(jwt_tool.secret_path(7001))
    assert path.read_text() == keys[0]
    if os.name == "posix":
        assert path.stat().st_mode & 0o077 == 0
        path.chmod(0o644)
        assert jwt_tool.load_secret(7001) == keys[0]
        assert path.stat().st_mode & 0o077 == 0


def test_key_writes_are_private_and_failed_replacements_preserve_key(tmp_path):
    private, _, pem, _, _ = crypto.generate_rsa_keys()
    path = tmp_path / "pri.pem"
    with atomic_output(path, "wb") as output:
        output.write(pem)
    with pytest.raises(ValueError), atomic_output(path, "wb") as output:
        output.write(b"partial")
        raise ValueError("write interrupted")
    if os.name == "posix":
        assert path.stat().st_mode & 0o077 == 0
        path.chmod(0o644)
    assert crypto.load_pri(path).private_numbers() == private.private_numbers()
    if os.name == "posix":
        assert path.stat().st_mode & 0o077 == 0


def test_already_provisioned_readonly_secrets_need_no_writes(tmp_path, monkeypatch):
    import jwt_keys

    monkeypatch.chdir(tmp_path)
    path = Path(jwt_tool.secret_path(7001))
    path.parent.mkdir(parents=True)
    path.write_text("provisioned")
    path.chmod(0o400)
    if os.name == "posix":
        path.parent.chmod(0o500)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(jwt_tool, "file_lock", lambda _: pytest.fail("unexpected lock-file write"))
            assert jwt_tool.load_secret(7001) == "provisioned"
            store = jwt_keys.KeyStore(path.parent)
            assert store.jwks() == []
            assert not Path(store.directory).exists()
    finally:
        path.parent.chmod(0o700)
        path.chmod(0o600)

    first, first_id = store.signing_key("ES256")
    second_id = store.rotate("ES256")
    assert first_id != second_id
    assert store.public_keys("ES256", first_id)[0][1].public_numbers() == first.public_key().public_numbers()
    assert store.signing_key("ES256")[1] == second_id


def test_windows_lock_retries_only_contention(tmp_path, monkeypatch):
    import errno
    from unittest.mock import Mock
    import json_store

    crt = Mock()
    crt.locking.side_effect = [PermissionError(errno.EACCES, "already locked"), None]
    sleep = Mock()
    monkeypatch.setattr(json_store.time, "sleep", sleep)
    with (tmp_path / "lock").open("wb") as file:
        json_store._lock_windows(file, crt)
        sleep.assert_called_once()
        crt.locking.side_effect = OSError(errno.EINVAL, "unsupported locking")
        with pytest.raises(OSError, match="unsupported locking"):
            json_store._lock_windows(file, crt)
        sleep.assert_called_once()


def test_instance_bootstrap_retries_and_preserves_existing_data(tmp_path, monkeypatch):
    import main
    from json_store import read_json
    from db.user import UserDb
    from argon2 import PasswordHasher

    monkeypatch.chdir(tmp_path)

    def answers(*values):
        iterator = iter(values)
        monkeypatch.setattr("builtins.input", lambda _prompt: next(iterator))
        monkeypatch.setattr(main.getpass, "getpass", lambda _prompt: next(iterator))

    instance = Path("res/7001")
    manifest = Path("server_config.json")
    answers("7001", "7002", "x", "private")
    with pytest.raises(ValueError, match="root"):
        main.create_new_server()
    assert not manifest.exists()
    assert not instance.exists()
    answers("7001", "7002", "owner", "private", "n")
    main.create_new_server()
    assert read_json(manifest) == {"0": ["7001", "7002"]}
    secret = instance / "secret"
    prior_keys = [(secret / name).read_bytes() for name in ("pri.pem", "pub.pem")]
    assert crypto.load_pri(secret / "pri.pem").public_key().public_numbers() == crypto.load_pub(secret / "pub.pem").public_numbers()
    with UserDb(PasswordHasher(), str(instance / "db/user.db"), 7001, 7002) as users:
        row = users.username_query("owner")[0]
        assert row[4] == "root" and users.verify_user(row[0], "private")
    answers("7001", "7003")
    with pytest.raises(ValueError, match="端口"):
        main.create_new_server()
    assert [(secret / name).read_bytes() for name in ("pri.pem", "pub.pem")] == prior_keys
    assert read_json(manifest) == {"0": ["7001", "7002"]}
    unregistered = Path("res/7003")
    unregistered.mkdir()
    (unregistered / "keep").write_text("existing data")
    answers("7003", "7004")
    with pytest.raises(ValueError, match="实例目录"):
        main.create_new_server()
    assert (unregistered / "keep").read_text() == "existing data"


def test_concurrent_initial_root_is_created_once(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from argon2 import PasswordHasher
    from db.user import UserDb

    hasher = PasswordHasher(time_cost=1, memory_cost=32, parallelism=1)
    path = str(tmp_path / "users.db")
    with UserDb(hasher, path, 0, 0) as users:
        users.create_user_table()
        gate = Barrier(2, timeout=5)

        def create(name):
            with UserDb(hasher, path, 0, 0) as separate:
                gate.wait()
                return separate.user_create(name, "test-password", 1, stat="root", only_if_empty=True)

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(create, ("root-one", "root-two")))
        assert sorted(results) == [False, True]
        assert users.query("SELECT uid, stat FROM users") == [(0, "root")]


def _first_asymmetric_key(directory):
    import jwt_keys

    return jwt_keys.KeyStore(directory).signing_key("ES256")[1]


def test_concurrent_first_asymmetric_key_is_shared(tmp_path):
    with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context("spawn")) as jobs:
        keys = list(jobs.map(_first_asymmetric_key, [tmp_path] * 12))
    assert len(set(keys)) == 1
    assert len(list((tmp_path / "jwt_keys").glob("*.pem"))) == 1


@pytest.mark.parametrize("contents", [
    None, "{unfinished", "[]", '{"db_backend":"mysql"}',
    '{"db_backend":"postgresql","db_user":"test"}', '{"db_backend":"unknown"}',
])
def test_instance_configuration_fails_before_opening_storage(tmp_path, monkeypatch, contents):
    import main
    from json_store import write_json

    monkeypatch.chdir(tmp_path)
    write_json("server_config.json", {"0": ["7001", "7002"]})
    instance = Path("res/7001")
    instance.mkdir(parents=True)
    if contents is not None:
        (instance / "config.json").write_text(contents)
    monkeypatch.setattr(main, "normalize_working_directory", lambda: None)
    monkeypatch.setattr(main.db, "UserDb", lambda *args, **kwargs: pytest.fail("unexpected database"))
    monkeypatch.setattr(main, "load_pub", lambda *_: pytest.fail("unexpected key access"))
    with pytest.raises((ValueError, FileNotFoundError)):
        main.main(main.parse_args(["--use-config", "0", "--start-api"]))
    assert not (instance / "db").exists()


def test_remote_database_can_explicitly_use_empty_password():
    import main

    assert main._database_settings({})[1] is None
    for backend, port in (("mysql", 3306), ("postgresql", 5432)):
        dialect, dsn = main._database_settings({"db_backend": backend, "db_user": "test", "db_password": ""})
        assert dsn == {"host": "localhost", "port": port, "user": "test", "password": "", "database": "touchfish_v5"}
