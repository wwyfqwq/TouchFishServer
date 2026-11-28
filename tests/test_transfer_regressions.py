import base64
import errno
from io import BytesIO
from pathlib import Path
import time
from types import SimpleNamespace

from PIL import Image
import pytest

import avatar
from db.file import FileDb
import file
import oss_store
import web


PORT = 7001


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file.init(PORT)
    Path(f"res/{PORT}/config.json").write_text("{}", encoding="utf-8")
    database = FileDb("res/7001/file/file.db", PORT)
    try:
        yield database
    finally:
        database.conn.close()


def upload_part(store, data, *, index, total, session=None, expected=None,
                validate_upload=None):
    return file.chunked_upload_file(
        PORT, 12, "report.txt", index, total, base64.b64encode(data).decode(),
        session, store, expected, validate_upload,
    )


def test_chunked_upload_keeps_original_checksum_and_replays_final_result(store):
    expected = file.sha256(b"hello world")
    started = upload_part(store, b"hello ", index=0, total=2, expected=expected)
    session = started["file_id"]
    result = upload_part(store, b"world", index=1, total=2, session=session)

    assert result == {"success": True, "file_hash": expected, "verified": True}
    assert Path(file.file_path(PORT, expected)).read_bytes() == b"hello world"
    assert upload_part(store, b"world", index=1, total=2, session=session) == result


def test_first_chunk_replay_reuses_client_session_id(store):
    session = "a" * 64
    result = {"success": True, "file_id": session}
    for _ in range(6):
        assert upload_part(store, b"first", index=0, total=2, session=session) == result
    assert store.list_chunk_parts(session) == {0: 5}


def test_expiry_cleanup_preserves_recreated_chunk_session(store, monkeypatch):
    session = "b" * 64
    upload_part(store, b"old part", index=0, total=2, session=session)

    def expire_then_retry(_max_age):
        store.delete_chunk_task(session)
        assert upload_part(store, b"new part", index=0, total=2, session=session)["success"]
        return [session]

    monkeypatch.setattr(store, "expire_stale_chunk_tasks", expire_then_retry)
    file.sweep_stale_chunk_uploads(PORT, store)
    assert Path(file._chunk_path(PORT, session, 0)).read_bytes() == b"new part"


def test_upload_can_publish_from_a_separate_temp_filesystem(store, monkeypatch):
    original_replace = file.os.replace

    def replace(source, destination):
        if Path(source).parent == Path(file.tmp_dir(PORT)):
            raise OSError(errno.EXDEV, "different filesystems")
        return original_replace(source, destination)

    monkeypatch.setattr(file.os, "replace", replace)
    hashes = file.upload_file(PORT, 12, b"uploaded file", "report.txt", store)
    assert Path(file.file_path(PORT, hashes)).read_bytes() == b"uploaded file"
    assert list(Path(file.tmp_dir(PORT)).iterdir()) == []
    assert list(Path(file.file_path(PORT, hashes)).parent.glob(".tmp_*")) == []


def test_chunked_upload_checks_quota_before_creating_ownership(store):
    hashes = file.sha256(b"new content")
    checks = []

    def reject(file_hash, size):
        assert not store.has_active_user_file(12, file_hash)
        checks.append((file_hash, size))
        return "Storage quota exceeded"

    started = upload_part(store, b"new ", index=0, total=2, expected=hashes)
    session = started["file_id"]
    result = upload_part(
        store, b"content", index=1, total=2, session=session, validate_upload=reject,
    )

    assert result == {"success": False, "error": "Storage quota exceeded"}
    assert checks == [(hashes, 11)]
    assert not store.file_exists(hashes)
    assert not Path(file.file_path(PORT, hashes)).exists()
    assert store.get_chunk_task(session) is None
    assert not list(Path(file.tmp_dir(PORT)).iterdir())


def test_small_chunks_can_exceed_twenty_parts_and_size_limit_is_cumulative(store, monkeypatch):
    monkeypatch.setattr(file, "MAX_TOTAL_SIZE", 21)
    session = None
    for index in range(20):
        result = upload_part(store, b"x", index=index, total=21, session=session)
        session = result["file_id"]

    assert upload_part(store, b"xx", index=20, total=21, session=session)["error"] == "File too large"
    result = upload_part(store, b"x", index=20, total=21, session=session)
    assert result["file_hash"] == file.sha256(b"x" * 21)


def test_oss_download_can_retry_after_a_partial_write(tmp_path, monkeypatch):
    class FakeBucket:
        fail = True

        def object_exists(self, key):
            return True

        def get_object_to_file(self, key, path):
            Path(path).write_bytes(b"partial" if self.fail else b"complete")
            if self.fail:
                raise OSError("connection closed")

    bucket = FakeBucket()
    monkeypatch.setattr(oss_store, "is_oss_enabled", lambda *_: True)
    monkeypatch.setattr(oss_store, "_get_bucket", lambda *_: bucket)
    target = str(tmp_path / "blob")

    assert not oss_store.download_from_oss(PORT, "file", "hash", target, cfg={})
    assert not list(tmp_path.iterdir())
    bucket.fail = False
    assert oss_store.download_from_oss(PORT, "file", "hash", target, cfg={})
    assert Path(target).read_bytes() == b"complete"


def test_reference_reconciliation_retires_only_old_missing_messages(store):
    hashes = file.sha256(b"blob")
    store.register_upload(12, hashes, "report.txt", 1.0, 4)
    for kind, source in (("message", "1"), ("message", "2"), ("message", "3"), ("sticker", "4")):
        assert store.add_reference(hashes, kind, source, 12)
    store.execute("UPDATE file_references SET last_referenced_at = 1 WHERE source_id <> '3'")

    store.reconcile_references(
        [(hashes, "message", 2, 12)], stale_message_reference_cutoff=time.time() - 3600,
    )

    rows = store.query("SELECT source_type, source_id FROM file_references")
    assert set(rows) == {("message", "2"), ("message", "3"), ("sticker", "4")}
    assert not store.query("SELECT hash FROM file_gc")


def test_oss_proxy_removes_local_copy_when_response_closes(store, monkeypatch, tmp_path):
    payload = b"proxied file"
    hashes = file.sha256(payload)
    store.register_upload(12, hashes, "report.txt", 1.0, len(payload))
    target = tmp_path / "oss-test.file"

    def download(_port, _kind, _hashes, path):
        Path(path).write_bytes(payload)
        return True

    monkeypatch.setattr(oss_store, "is_oss_enabled", lambda *_: True)
    monkeypatch.setattr(oss_store, "get_download_mode", lambda *_: "proxy")
    monkeypatch.setattr(oss_store, "temp_download_path", lambda *_: str(target))
    monkeypatch.setattr(oss_store, "download_from_oss", download)
    app = web.main(
        PORT, 7002, None, None, None, None, None, store,
        None, None, SimpleNamespace(), None, jwt_secret=b"test", jwt_key_store=object(),
    )
    response = app.test_client().get(f"/file/get_file/{hashes}", buffered=False)
    try:
        assert response.status_code == 200
        assert response.data == payload
        assert target.exists()
    finally:
        response.close()
    assert not target.exists()

    # An upload can succeed with only a local copy while OSS is unavailable.
    local = Path(file.file_path(PORT, hashes))
    local.write_bytes(payload)
    monkeypatch.setattr(oss_store, "get_download_mode", lambda *_: "redirect")
    response = app.test_client().get(f"/file/get_file/{hashes}", buffered=True)
    assert response.status_code == 200
    assert response.data == payload
    assert local.exists()


def test_default_avatar_rejects_invalid_image_and_preserves_asset(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    avatar.init(PORT)
    logo = Path(avatar.default_avatar_path(PORT, "logo"))
    previous = logo.read_bytes()

    assert not avatar.upload_default_avatar(PORT, base64.b64encode(b"not an image"), "logo")
    assert logo.read_bytes() == previous

    output = BytesIO()
    Image.new("RGB", (1, 1)).save(output, format="PNG")
    assert avatar.upload_default_avatar(PORT, base64.b64encode(output.getvalue()), "logo")
    assert logo.read_bytes() == output.getvalue()


def test_concurrent_sticker_quota_checks_and_retries(store):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from db.sticker import StickerDb, StickerQuotaExceeded

    path = "res/7001/file/sticker-test.db"
    owners = [StickerDb(path, PORT) for _ in range(2)]
    together = Barrier(2)

    def upload(index):
        together.wait(timeout=5)
        payload = b"sticker" + bytes([index])
        try:
            key = file.upload_sticker(PORT, 12, payload, "tile.png", owners[index], quota=len(payload))
        except StickerQuotaExceeded:
            assert not Path(file.sticker_path(PORT, file.sha256(payload))).exists()
            return None
        return key, payload

    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(upload, range(2)))
        committed = [r for r in results if r]
        assert len(committed) == 1
        key, payload = committed[0]
        assert owners[0].get_user_sticker_used(12) == len(payload)
        assert file.upload_sticker(PORT, 12, payload, "again.png", owners[0], quota=len(payload)) == key
        assert Path(file.sticker_path(PORT, key)).read_bytes() == payload
    finally:
        for db in owners:
            db.conn.close()


def test_sticker_detection_checks_contents_and_bounds_inflation(monkeypatch):
    import gzip
    import file_types

    monkeypatch.setattr(file_types, "MAX_STICKER_DOCUMENT_BYTES", 256)
    document = b'{"v":"5","layers":[]}'
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"/>'
    assert file_types.is_sticker_type(gzip.compress(document), "animation.tgs")
    assert file_types.is_sticker_type(gzip.compress(svg), "shape.svgz")
    assert file_types.is_sticker_type(svg, "tile.svg")
    assert not file_types.is_sticker_type(gzip.compress(document + b" " * 256), "animation.tgs")
    assert not file_types.is_sticker_type(b"plain text", "photo.png")
    for builder in (file.file_path, file.sticker_path, file.thumb_path):
        with pytest.raises(ValueError, match="Invalid file hash"):
            builder(PORT, "unrelated text")


def test_orphan_snapshot_skips_a_reregistered_blob(store, monkeypatch):
    digest = file.sha256(b"restored")
    store.register_upload(12, digest, "tile.png", time.time(), size=8)
    store.upsert_media_dimensions(digest, 1, 1)
    monkeypatch.setattr(store, "list_orphan_media", lambda _: [digest])
    assert file.sweep_orphan_media(PORT, store) == 0
    assert store.get_media(digest)["width"] == 1


def test_sticker_retry_publishes_bytes_after_another_writer_rolls_back(store, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from db.sticker import StickerDb

    with StickerDb("res/7001/file/two-writers.db", PORT) as stickers:
        registered = stickers.register_upload
        published = Event()
        retrying = Event()
        content = b"concurrent-publication"

        def fail_first(uid, *args, **kwargs):
            if uid == 11:
                kwargs["prepare_blob"]()
                published.set()
                assert retrying.wait(5)
                raise RuntimeError("temporary registration failure")
            return registered(uid, *args, **kwargs)

        monkeypatch.setattr(stickers, "register_upload", fail_first)

        def retry():
            assert published.wait(5)
            retrying.set()
            return file.upload_sticker(PORT, 12, content, "tile.png", stickers)

        with ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(file.upload_sticker, PORT, 11, content, "tile.png", stickers)
            second = workers.submit(retry)
            with pytest.raises(RuntimeError, match="registration failure"):
                first.result(timeout=10)
            key = second.result(timeout=10)
        assert Path(file.sticker_path(PORT, key)).read_bytes() == content
        assert stickers.has_active_user_sticker(12, key)
