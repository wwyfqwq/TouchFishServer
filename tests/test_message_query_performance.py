import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from db.dialect import MySQLDialect, PostgreSQLDialect
from db.messages import FileReferenceUnavailable, MessagesDb


class QueryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / "messages.db")
        self.db = MessagesDb(self.path, 0)
        self.addCleanup(self.db.conn.close)

    def test_private_previews_respect_participants_and_moderator_events(self):
        db = self.db
        first = db.add_message(2, 3, "first")
        db.add_message(3, 2, "reply")
        db.add_message(2, 7, "other")
        db.add_message(2, 2, "self")
        db.add_message(45, 2, "group", group_id=19)
        db.recall_message(first["mid"], deleted_by=45)
        self.assertEqual([(r["partner_uid"], r["last_content"], r["last_seq"])
                          for r in db.get_chat_list(2)], [(7, "other", 1), (3, "reply", 3)])
        self.assertEqual(db.get_chat_list(3)[0]["last_seq"], 4)
        self.assertEqual(db.get_chat_list(45), [])
        with self.assertRaises(FileReferenceUnavailable):
            db.add_message(2, 9, "file", file_hash="test-hash",
                           add_file_reference=lambda *args: False)
        self.assertEqual(db.query("SELECT room_key FROM direct_rooms WHERE high_uid = 9"), [])

    def test_legacy_directory_upgrade_and_subsequent_old_writer(self):
        self.db.add_message(2, 3, "existing")
        for table in ("direct_rooms", "direct_room_backfill"):
            self.db.execute("DROP TABLE " + table)
        with MessagesDb(self.path, 0) as db:
            self.assertEqual(db.get_chat_list(3)[0]["last_content"], "existing")
            db.execute("""
                INSERT INTO messages(sender_uid, receiver_uid, content, send_time, room_key, room_seq)
                VALUES(4, 5, 'old binary', 21, 'U4U5', 1)
            """)
        with MessagesDb(self.path, 0) as db:
            self.assertEqual(db.get_chat_list(5)[0]["last_content"], "old binary")
            self.assertEqual(db.add_message(5, 4, "new binary")["room_seq"], 2)

    def test_unread_watermark_and_mention_levels_across_batches(self):
        db = self.db
        keys = [f"G{i}" for i in range(620)]
        # Make unbounded lists exceed the artificial host parameter budget.
        db.conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 512)
        for gid in (12, 510, 619):
            db.add_message(1, 0, "before", group_id=gid)
        db.init_read_watermarks(2, keys + keys)
        self.assertIsNone(db.get_read_state(2, "G4"))
        for gid in (12, 510, 619):
            old = db.add_message(3, 0, "recalled", group_id=gid, mentioned_uids=[2])
            db.recall_message(old["mid"], 3)
            db.add_message(3, 0, "new", group_id=gid)
            db.add_message(3, 0, "mention", group_id=gid, mentioned_uids=[2])
        db.init_read_watermarks(2, keys)
        self.assertEqual(db.bulk_unread_counts(2, keys, {"G510": 1, "G619": 2}),
                         {"G12": 2, "G510": 1})
        self.assertEqual(db.bulk_unread_counts(27, ["G12"]), {"G12": 3})
        preview = db.get_group_last_messages(range(620))
        self.assertEqual(set(preview), {12, 510, 619})
        self.assertEqual((preview[510]["content"], preview[510]["last_seq"]), ("mention", 6))
        for user in (2, 501, 1049):
            db.update_room_preference(user, "G12", notify_level=1)
        self.assertEqual(set(db.get_room_preference_map(range(1050), "G12")), {2, 501, 1049})

    def test_known_watermark_and_caught_up_count_skip_old_rows(self):
        db = self.db
        db.update("""
            INSERT INTO messages(sender_uid, receiver_uid, group_id, content, send_time, room_key, room_seq)
            VALUES(14, 0, 10, 'message', 0, 'G10', ?)
        """, [(seq,) for seq in range(1, 2001)])
        db.init_read_watermarks(29, ["G10"])
        steps = 0
        def step():
            nonlocal steps
            steps += 1
            return 0
        db.conn.set_progress_handler(step, 1)
        try:
            db.init_read_watermarks(29, ["G10"])
            self.assertEqual(db.bulk_unread_counts(29, ["G10"]), {})
            self.assertEqual(db.get_group_last_messages([10])[10]["last_seq"], 2000)
        finally:
            db.conn.set_progress_handler(None, 0)
        # Generous margin above the three indexed probes, below a single history scan.
        self.assertLess(steps, 1500)

    def test_steady_send_uses_three_statements_and_preserves_genuine_receipt(self):
        db = self.db
        first = db.add_message(2, 3, "first")
        db.update_read_state(2, "U2U3", 1, first["mid"])
        seen = []
        db.conn.set_trace_callback(seen.append)
        try:
            second = db.add_message(2, 3, "second")
        finally:
            db.conn.set_trace_callback(None)
        statements = [sql for sql in seen if sql.strip().split()[0] not in {"BEGIN", "COMMIT"}]
        self.assertEqual(len(statements), 3 if db.dialect.supports_returning else 4)
        self.assertEqual(db.get_read_state(2, "U2U3")["last_read_mid"], first["mid"])
        self.assertTrue(db.update_read_state(2, "U2U3", 2, second["mid"]))
        self.assertTrue(db.update_read_state(2, "U2U3", 1, first["mid"]))
        self.assertFalse(db.update_read_state(2, "U2U3", 1, 0))
        self.assertEqual(db.get_read_state(2, "U2U3")["last_read_mid"], second["mid"])

    def test_receipts_are_monotone_across_independent_database_instances(self):
        with MessagesDb(self.path, 0) as other:
            instances = (self.db, other)
            with ThreadPoolExecutor(max_workers=6) as pool:
                receipts = [pool.submit(instances[i % 2].update_read_state, 8, "G7", seq, seq)
                            for i, seq in enumerate([1, 83, 4, 29, 50, 82, 100, 3] * 4)]
                self.assertTrue(all(result.result() for result in receipts))
            state = other.get_read_state(8, "G7")
            self.assertEqual((state["last_read_seq"], state["last_read_mid"]), (100, 100))

    def test_schema_change_invalidates_prepared_translation(self):
        mysql = MySQLDialect()
        original = "SELECT id FROM groups"
        self.assertEqual(mysql.prepare_sql(original)[0], original)
        mysql.prepare_sql("CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY)")
        self.assertIn("`groups`", mysql.prepare_sql(original)[0])
        mysql._upsert_row_alias = False
        early_mysql = mysql.translate_sql(
            "INSERT INTO activity(uid, seq) VALUES (?, ?) ON CONFLICT(uid) DO UPDATE SET seq = excluded.seq")
        self.assertIn("ON DUPLICATE KEY UPDATE seq = VALUES(seq)", early_mysql)
        postgres = PostgreSQLDialect()
        upsert = "INSERT OR REPLACE INTO activity(uid, seq, stamp) VALUES (?, ?, ?)"
        self.assertIn("ON CONFLICT (uid)", postgres.prepare_sql(upsert)[0])
        postgres.prepare_sql("CREATE TABLE activity(uid INTEGER, seq INTEGER, stamp INTEGER, PRIMARY KEY(uid, seq))")
        self.assertIn("ON CONFLICT (uid, seq)", postgres.prepare_sql(upsert)[0])
