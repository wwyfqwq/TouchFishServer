import json

import pytest

import main


def test_missing_explicit_config_fails_without_creating_another(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "normalize_working_directory", lambda: None)
    monkeypatch.setattr(
        main, "create_new_server", lambda: pytest.fail("Unexpected interactive setup"),
    )
    with pytest.raises(ValueError, match="配置 9 不存在"):
        main.main(main.parse_args(["--use-config", "9", "--start-api"]))


def test_invalid_config_file_is_not_replaced(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "normalize_working_directory", lambda: None)
    monkeypatch.setattr(
        main, "create_new_server", lambda: pytest.fail("Unexpected interactive setup"),
    )
    manifest = tmp_path / "server_config.json"
    manifest.write_text("{unfinished", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        main.main(main.parse_args(["--start-api"]))
    assert manifest.read_text(encoding="utf-8") == "{unfinished"
