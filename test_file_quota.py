import base64
import os
import tempfile
import unittest
from pathlib import Path

import file
from db.file import FileDb


class ChunkQuotaTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(temp.name)
        Path("res/1/file").mkdir(parents=True)
        self.db = FileDb("res/1/file/file.db", 1)
        self.addCleanup(self.db.conn.close)
        self.db.create_file_db()

    def part(self, index, total, data, file_id=None, *, limit=10, quota=10):
        return file.chunked_upload_file(
            1, 1, "test.txt", index, total, base64.b64encode(data), file_id, self.db,
            max_file_size=limit, storage_quota=quota,
        )

    def test_file_limit_counts_all_chunks_before_writing(self):
        task = self.part(0, 2, b"abc", limit=4)["file_id"]
        self.assertEqual(self.part(1, 2, b"de", task, limit=4)["error"], "File too large")
        self.assertEqual(self.db.list_chunk_parts(task), {0: 3})
        self.assertEqual(len(list(Path("res/1/tmp").iterdir())), 1)
        self.assertTrue(self.part(1, 2, b"d", task, limit=4)["success"])
        self.assertEqual(self.db.get_user_storage_used(1), 4)
        self.assertEqual(self.db.get_user_reserved_storage(1), 0)

    def test_pending_and_committed_bytes_share_one_budget(self):
        self.assertTrue(self.part(0, 1, b"12", quota=7)["success"])
        task = self.part(0, 3, b"345", quota=7)["file_id"]
        self.assertEqual(self.part(0, 2, b"678", quota=7)["error"], "Storage quota exceeded")
        self.assertTrue(self.part(1, 3, b"6", task, quota=7)["success"])
        self.assertTrue(self.part(1, 3, b"7", task, quota=7)["success"])
        self.assertTrue(self.part(2, 3, b"8", task, quota=7)["success"])
        self.assertEqual(self.db.get_user_storage_used(1), 7)
        self.assertEqual(self.db.get_user_reserved_storage(1), 0)
