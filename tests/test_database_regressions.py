import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest.mock import Mock, patch

from db.dialect import CursorProxy, MySQLDialect, PostgreSQLDialect
from db.forum import ForumDb
from db.group import GroupDb
from db.messages import MessagesDb
from db.notifications import NotificationsDb


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def test_forum_ids_continue_after_deleting_current_max_and_reopening(self):
        path = str(self.directory / "forum.db")
        with ForumDb(path, 0, 0) as forums:
            forums.create_forum_table()
            forum = forums.create_forum("Board", 2, "")
            other = forums.create_forum("Other", 2, "")
            post = forums.send_post(forum, 2, "Sample", "A", ["file-hash"])
            self.assertEqual((forum, other, post), (0, 1, 0))
            self.assertTrue(forums.pin_post(forum, post))
            self.assertIsNotNone(forums.add_comment(forum, post, 2, "Comment"))
            self.assertEqual(forums.delete_post(forum, post), ["file-hash"])
            self.assertEqual(forums.delete_post(forum, post), [])
            self.assertIsNone(forums.get_pinned_pid(forum))
            self.assertIsNone(forums.add_comment(forum, post, 2, "Late comment"))
            self.assertEqual(forums.query_forum_fid(forum)[0][5], 0)
            forums.delete_forum(other)
            self.assertIs(forums.send_post(other, 2, "Missing board", "A"), False)

        with ForumDb(path, 0, 0) as reopened:
            reopened.create_forum_table()
            self.assertGreater(reopened.create_forum("Replacement", 2, ""), other)
            self.assertGreater(reopened.send_post(forum, 2, "New post", "B"), post)

    def test_forum_migration_keeps_live_ids_and_clears_dangling_pins(self):
        with ForumDb(str(self.directory / "forum.db"), 0, 0) as forums:
            forums.create_forum_table()
            forums.execute("DROP TABLE forum_id_counters")
            forums.execute("INSERT INTO forums (fid, forumname, creater, post_num, pinned_pid) VALUES (12, 'Old board', 3, 1, 42)")
            forums.execute("INSERT INTO contents (fid, pid, title, creater) VALUES (12, 36, 'Old post', 4)")

            forums.create_forum_table()
            self.assertIsNone(forums.get_pinned_pid(12))
            self.assertEqual(forums.create_forum("New board", 3, ""), 13)
            self.assertEqual(forums.send_post(12, 4, "New post", "A"), 37)
            self.assertTrue(forums.pin_post(12, 36))
            forums.clean_user_content(4)
            self.assertIsNone(forums.get_pinned_pid(12))

    def test_group_migration_retains_legacy_high_water_mark(self):
        path = str(self.directory / "groups.db")
        read_config = lambda: {"groups_limit": 1}
        with GroupDb(path, 0, config_reader=read_config) as old_groups:
            old_groups.execute("DROP TABLE group_id_counter")
            old_groups.execute("INSERT INTO group_id_sequence (id) VALUES (21)")
            old_groups.execute("INSERT INTO groups (gid, creater) VALUES (9, 2)")

        with GroupDb(path, 0, config_reader=read_config) as groups:
            self.assertEqual(groups.create_group(2, "At limit", "", ""), 0)
            group = groups.create_group(3, "New group", "", "")
            self.assertEqual(group, 22)
            self.assertTrue(groups.delete_group(group))

        with GroupDb(path, 0, config_reader=read_config) as reopened:
            self.assertEqual(reopened.create_group(3, "Another group", "", ""), 23)

    def test_quotes_distinguish_group_message_from_private_message(self):
        with MessagesDb(str(self.directory / "messages.db"), 0) as messages:
            group_message = messages.add_message(3, 0, "Group", group_id=1)
            private_message = messages.add_message(3, 0, "Direct")
            self.assertTrue(messages.verify_quote(group_message["mid"], group_id=1))
            self.assertFalse(messages.verify_quote(group_message["mid"], 3, 0))
            self.assertTrue(messages.verify_quote(private_message["mid"], 0, 3))

    def test_mentions_and_messages_commit_together(self):
        with MessagesDb(str(self.directory / "messages.db"), 0) as messages:
            messages.execute("""
                CREATE TRIGGER reject_mentions BEFORE INSERT ON message_mentions
                BEGIN SELECT RAISE(ABORT, 'mention write failed'); END
            """)
            with self.assertRaises(sqlite3.IntegrityError):
                messages.add_message(3, 4, "Mention", mentioned_uids=[4])
            self.assertEqual(messages.query_sync("U3U4"), [])
            messages.execute("DROP TRIGGER reject_mentions")
            message = messages.add_message(3, 4, "Mention", mentioned_uids=[4, 4])
            self.assertEqual(message["room_seq"], 1)
            self.assertEqual(messages.query_sync("U3U4")[0]["mentioned_uids"], [4])

    def test_room_sequence_resumes_from_existing_messages_and_spans_connections(self):
        path = str(self.directory / "messages.db")
        with MessagesDb(path, 0) as legacy:
            first = legacy.add_message(3, 4, "Existing message")
            legacy.execute("DROP TABLE room_sequences")

        with MessagesDb(path, 0) as left, MessagesDb(path, 0) as right:
            with ThreadPoolExecutor(max_workers=2) as pool:
                sends = [pool.submit(db.add_message, uid, peer, "Turn")
                         for db, uid, peer in ((left, 3, 4), (right, 4, 3))]
                self.assertEqual(sorted(send.result()["room_seq"] for send in sends), [2, 3])
            self.assertEqual(right.recall_message(first["mid"], 3), 4)
            self.assertEqual(left.add_message(4, 3, "After recall")["room_seq"], 6)

    def test_upgrade_advances_counters_past_writes_from_older_release(self):
        path = str(self.directory / "legacy-writes.db")
        with MessagesDb(path, 0) as messages:
            messages.add_message(2, 3, "New release")
            messages.execute("""
                INSERT INTO messages (sender_uid, receiver_uid, content, send_time, room_key, room_seq)
                VALUES (2, 3, 'Older release', 123, 'U2U3', 2)
            """)
        with MessagesDb(path, 0) as messages:
            self.assertEqual(messages.add_message(2, 3, "Upgraded again")["room_seq"], 3)

        with ForumDb(path, 0, 0) as forums:
            forums.create_forum_table()
            forums.execute("INSERT INTO forums (fid, forumname, creater, post_num) VALUES (10, 'Older board', 2, 1)")
            forums.execute("INSERT INTO contents (fid, pid, title, creater) VALUES (10, 100, 'Older post', 2)")
            forums.create_forum_table()
            self.assertEqual(forums.create_forum("New board", 2, ""), 11)
            self.assertEqual(forums.send_post(10, 2, "New post", "Body"), 101)

        with GroupDb(path, 0, config_reader=dict) as groups:
            groups.execute("INSERT INTO group_id_sequence (id) VALUES (45)")
        with GroupDb(path, 0, config_reader=dict) as groups:
            self.assertEqual(groups.create_group(2, "New group", "", ""), 46)

    def test_room_preference_patches_preserve_fields_from_other_devices(self):
        path = str(self.directory / "messages.db")
        original_query = MessagesDb.query
        both_devices_loaded = Barrier(2, timeout=3)

        def query_and_wait(db, sql, params=None):
            rows = original_query(db, sql, params)
            if sql.startswith("SELECT is_pinned, notify_level, alias, description"):
                both_devices_loaded.wait()
            return rows

        with MessagesDb(path, 0) as left, MessagesDb(path, 0) as right:
            with patch.object(MessagesDb, "query", query_and_wait):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    change_alias = pool.submit(left.update_room_preference, 1, "U2", alias="Buddy")
                    change_seen = pool.submit(right.update_room_preference, 1, "U2", notify_level=1)
                    self.assertTrue(change_alias.result())
                    self.assertTrue(change_seen.result())
            self.assertEqual(left.get_room_preference(1, "U2"), {
                "alias": "Buddy", "notify_level": 1, "is_pinned": False, "description": "",
            })

    def test_mysql_search_escape_preserves_following_placeholders(self):
        dialect = MySQLDialect()
        translated = dialect.translate_sql("SELECT name FROM groups WHERE name LIKE ? ESCAPE '\\' LIMIT ?")
        self.assertEqual(translated, "SELECT name FROM groups WHERE name LIKE %s ESCAPE '\\\\' LIMIT %s")

    def test_cursor_normalizes_tuple_result_for_paginated_queries(self):
        real_cursor = Mock()
        real_cursor.fetchall.return_value = ((2,), (1,))
        rows = CursorProxy(real_cursor, MySQLDialect(), None).fetchall()
        rows.reverse()
        self.assertEqual(rows, [(1,), (2,)])

    def test_legacy_notifications_do_not_reappear_as_unread(self):
        path = str(self.directory / "notifications.db")
        connection = sqlite3.connect(path)
        try:
            connection.execute("CREATE TABLE U8 (time_stamp REAL, info TEXT)")
            connection.execute("INSERT INTO U8 VALUES (?, ?)", (100, json.dumps({"event": "legacy.notice"})))
            connection.commit()
        finally:
            connection.close()

        with NotificationsDb(path, 0) as notifications:
            row, = notifications.query_all_events(8)
            self.assertEqual(row[2], 100)
            self.assertEqual(notifications.unread_count(8), 0)

    def test_postgresql_translates_multiline_insert_ignore_without_losing_values(self):
        dialect = PostgreSQLDialect()
        translated = dialect.translate_sql("""
            INSERT OR IGNORE INTO subscriptions (uid, pack_id)
            VALUES (?, ?);
        """)
        self.assertEqual(
            " ".join(translated.split()),
            "INSERT INTO subscriptions (uid, pack_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
        )


if __name__ == "__main__":
    unittest.main()
