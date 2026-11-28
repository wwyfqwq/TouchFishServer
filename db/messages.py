from db.dialect import MySQLDialect, PostgreSQLDialect
from db.tool import Db
import json
import time


class FileReferenceUnavailable(Exception):
    """The backing file disappeared before its message could be stored."""


class MessagesDb(Db):
    # 事件行：content 为版本化 JSON 信封，随消息流同步
    # 占 room_seq
    EVENT_CONTENT_TYPE = "event"
    EVENT_VERSION = 1

    def __init__(self, path: str, port_api: int, dialect=None):
        super().__init__(path, port_api, -1, dialect=dialect)
        self._implicit_watermark = self._watermark_upsert(genuine=False)
        self._explicit_watermark = self._watermark_upsert(genuine=True)
        self._create_table()
        self._migrate()
        self._create_indexes()
        self._refresh_room_sequences()
        self._backfill_direct_rooms()

    @staticmethod
    def room_key_of(sender_uid: int, receiver_uid: int, group_id=None) -> str:
        """
        房间的规范化 key
        私聊为排序后的 UminUmax
        群聊为 Ggid
        """
        if group_id is not None:
            return "G{}".format(group_id)
        lo, hi = (sender_uid, receiver_uid) if sender_uid < receiver_uid \
            else (receiver_uid, sender_uid)
        return "U{}U{}".format(lo, hi)

    @classmethod
    def build_event_content(cls, kind: str, **fields) -> str:
        payload = {"v": cls.EVENT_VERSION, "kind": kind}
        payload.update(fields)
        return json.dumps(payload, ensure_ascii=False)

    @staticmethod
    def parse_event_content(content: str):
        try:
            payload = json.loads(content) if content else None
        except (TypeError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    def _create_table(self):
        self.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                mid INTEGER PRIMARY KEY AUTOINCREMENT,
                client_mid TEXT,
                sender_uid INTEGER NOT NULL,
                receiver_uid INTEGER NOT NULL,
                group_id INTEGER,
                content TEXT NOT NULL,
                content_type TEXT NOT NULL DEFAULT 'plain',
                file_hash TEXT,
                send_time REAL NOT NULL,
                quote INTEGER NOT NULL DEFAULT -1,
                deleted INTEGER NOT NULL DEFAULT 0,
                deleted_at REAL,
                deleted_by INTEGER,
                file_name TEXT,
                forwarded INTEGER NOT NULL DEFAULT -1,
                duration INTEGER,
                room_key TEXT,
                room_seq INTEGER
            )
        """)
        self.execute("""
            CREATE TABLE IF NOT EXISTS room_sequences (
                room_key TEXT PRIMARY KEY,
                last_seq INTEGER NOT NULL
            )
        """)
        self.execute("""
            CREATE TABLE IF NOT EXISTS direct_rooms (
                room_key TEXT PRIMARY KEY,
                low_uid INTEGER NOT NULL,
                high_uid INTEGER NOT NULL
            )
        """)
        self.execute("""
            CREATE TABLE IF NOT EXISTS direct_room_backfill (
                id INTEGER PRIMARY KEY,
                last_mid INTEGER NOT NULL
            )
        """)
        self.execute("""
            CREATE TABLE IF NOT EXISTS room_preferences (
                uid INTEGER NOT NULL,
                room_id TEXT NOT NULL,
                is_pinned INTEGER NOT NULL DEFAULT 0,
                notify_level INTEGER NOT NULL DEFAULT 0,
                alias TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                updated_at REAL NOT NULL,
                PRIMARY KEY (uid, room_id)
            )
        """)
        for col in ("alias", "description"):
            try:
                self.execute(
                    "ALTER TABLE room_preferences ADD COLUMN {} TEXT NOT NULL DEFAULT ''".format(col)
                )
            except Exception:
                pass
        self.execute("""
            CREATE TABLE IF NOT EXISTS message_mentions (
                mid INTEGER NOT NULL,
                uid INTEGER NOT NULL,
                PRIMARY KEY (mid, uid)
            )
        """)
        self.execute("""
            CREATE TABLE IF NOT EXISTS group_pinned_messages (
                pin_id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                pinned_by_uid INTEGER NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(message_id, group_id)
            )
        """)
        self.execute("""
            CREATE TABLE IF NOT EXISTS room_read_state (
                uid INTEGER NOT NULL,
                room_key TEXT NOT NULL,
                last_read_seq INTEGER NOT NULL DEFAULT 0,
                last_read_mid INTEGER NOT NULL DEFAULT 0,
                updated_at REAL NOT NULL,
                PRIMARY KEY (uid, room_key)
            )
        """)

    def _migrate(self):
        """尝试修复db"""
        for col, typ in [("group_id", "INTEGER"), ("client_mid", "TEXT"),
                         ("deleted_at", "REAL"), ("deleted_by", "INTEGER"),
                           ("file_name", "TEXT"),
                           ("forwarded", "INTEGER NOT NULL DEFAULT -1"),
                           ("duration", "INTEGER"),
                           ("room_key", "TEXT"), ("room_seq", "INTEGER")]:
            try:
                self.execute("ALTER TABLE messages ADD COLUMN {} {}".format(col, typ))
            except Exception:
                pass
        self._backfill_room_sequences()

    def _backfill_room_sequences(self):
        """为旧数据回填 room_key / room_seq
        """
        with self.lock:
            def operation():
                rows = self.cursor.execute(
                    "SELECT mid, sender_uid, receiver_uid, group_id "
                    "FROM messages WHERE room_seq IS NULL ORDER BY mid ASC"
                ).fetchall()
                if not rows:
                    self.conn.commit()
                    return
                existing = self.cursor.execute(
                    "SELECT room_key, MAX(room_seq) FROM messages "
                    "WHERE room_seq IS NOT NULL AND room_key IS NOT NULL "
                    "GROUP BY room_key"
                ).fetchall()
                seq_by_room = {
                    key: int(value) for key, value in existing
                    if key is not None and value is not None
                }
                updates = []
                for mid, sender, receiver, gid in rows:
                    key = self.room_key_of(sender, receiver, gid)
                    seq_by_room[key] = seq_by_room.get(key, 0) + 1
                    updates.append((key, seq_by_room[key], mid))
                self.cursor.executemany(
                    "UPDATE messages SET room_key = ?, room_seq = ? WHERE mid = ?",
                    updates,
                )
                self.conn.commit()
                print("[INFO] DATABASE 回填了 {} 条消息的 room_key/room_seq".format(len(updates)))
            self._execute_with_retry(operation)

    def _create_indexes(self):
        try:
            self.execute("DROP INDEX IF EXISTS idx_messages_client_mid")
        except Exception:
            pass
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_direct_rooms_low ON direct_rooms(low_uid)",
            "CREATE INDEX IF NOT EXISTS idx_direct_rooms_high ON direct_rooms(high_uid)",
            """CREATE INDEX IF NOT EXISTS idx_messages_conversation
               ON messages(sender_uid, receiver_uid, send_time DESC)""",
            """CREATE INDEX IF NOT EXISTS idx_messages_receiver
               ON messages(receiver_uid, send_time DESC)""",
            """CREATE INDEX IF NOT EXISTS idx_messages_group
               ON messages(group_id, send_time DESC)""",
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_sender_client_mid
               ON messages(sender_uid, client_mid) WHERE client_mid IS NOT NULL""",
            """CREATE INDEX IF NOT EXISTS idx_messages_room_seq
               ON messages(room_key, room_seq)""",
            """CREATE INDEX IF NOT EXISTS idx_messages_room_mid
               ON messages(room_key, mid DESC)""",
            """CREATE INDEX IF NOT EXISTS idx_messages_file_hash
               ON messages(file_hash)""",
            """CREATE INDEX IF NOT EXISTS idx_group_pinned_group
               ON group_pinned_messages(group_id)""",
            """CREATE INDEX IF NOT EXISTS idx_room_read_state_room_seq
               ON room_read_state(room_key, last_read_seq)""",
            """DROP INDEX IF EXISTS idx_room_read_state_room""",
        ]
        for idx_sql in indexes:
            try:
                self.execute(idx_sql)
            except Exception:
                pass

    def add_message(self, sender_uid: int, receiver_uid: int, content: str,
                     content_type: str = 'plain', file_hash: str = None,
                      quote: int = -1, group_id: int = None,
                       client_mid: str = None, file_name: str = None,
                        forwarded: int = -1, duration: int = None,
                     mentioned_uids=(), add_file_reference=None,
                     remove_file_reference=None) -> dict:
        send_time = time.time()
        mentioned_uids = {int(uid) for uid in mentioned_uids}
        _IntegrityError = self.dialect.IntegrityError
        with self.lock:
            def operation():
                room_key = self.room_key_of(sender_uid, receiver_uid, group_id)
                reference_added = False
                try:
                    room_seq = self._allocate_room_sequences_locked(room_key)
                    mid = self._insert_message_locked(
                        """INSERT INTO messages
                           (client_mid, sender_uid, receiver_uid, group_id, content, content_type,
                             file_hash, send_time, quote, file_name, forwarded, duration, room_key, room_seq)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (client_mid, sender_uid, receiver_uid, group_id, content, content_type,
                          file_hash, send_time, quote, file_name, forwarded, duration, room_key, room_seq),
                    )
                    if mentioned_uids:
                        self.cursor.executemany(
                            "INSERT INTO message_mentions (mid, uid) VALUES (?, ?)",
                            [(mid, uid) for uid in mentioned_uids],
                        )
                    # 发送即已读
                    self._advance_read_watermark_locked(
                        sender_uid, room_key, room_seq, mid, genuine=False)
                    # Attach the file before exposing the message in history or acknowledging it.
                    if add_file_reference is not None:
                        if not add_file_reference(file_hash, "message", mid, sender_uid):
                            raise FileReferenceUnavailable(file_hash)
                        reference_added = True
                    self.conn.commit()
                    return mid, room_seq, False
                except _IntegrityError:
                    self.conn.rollback()
                    if reference_added and remove_file_reference is not None:
                        try:
                            remove_file_reference(file_hash, "message", mid)
                        except Exception:
                            pass
                    if client_mid is not None:
                        self.cursor.execute(
                            "SELECT mid FROM messages WHERE sender_uid = ? AND client_mid = ?",
                            (sender_uid, client_mid),
                        )
                        existing = self.cursor.fetchone()
                        self.conn.commit()
                        if existing:
                            return existing[0], None, True
                    raise
                except Exception:
                    self.conn.rollback()
                    if reference_added and remove_file_reference is not None:
                        try:
                            remove_file_reference(file_hash, "message", mid)
                        except Exception:
                            pass
                    raise

            mid, room_seq, duplicate = self._execute_with_retry(operation)

        if duplicate:
            return {"mid": mid, "duplicate": True}
        return {
            "mid": mid,
            "client_mid": client_mid,
            "sender_uid": sender_uid,
            "receiver_uid": receiver_uid,
            "group_id": group_id,
            "content": content,
            "content_type": content_type,
            "file_hash": file_hash,
            "send_time": send_time,
            "quote": quote,
            "deleted": 0,
            "deleted_at": None,
            "deleted_by": None,
            "file_name": file_name,
            "forwarded": forwarded,
            "duration": duration,
            "room_key": self.room_key_of(sender_uid, receiver_uid, group_id),
            "room_seq": room_seq,
        }

    @staticmethod
    def _direct_room_row(room_key):
        if not room_key or not room_key.startswith("U"):
            return None
        try:
            low, high = map(int, room_key[1:].split("U"))
        except ValueError:
            return None
        return (room_key, low, high) if low < high else None

    _INSERT_DIRECT_ROOM = (
        "INSERT OR IGNORE INTO direct_rooms(room_key, low_uid, high_uid) VALUES (?, ?, ?)"
    )

    def _backfill_direct_rooms(self):
        # Older releases can add rooms while this release is offline. On restart
        # inspect only mids written since the previous checkpoint.
        with self.lock:
            def operation():
                previous = self.cursor.execute(
                    "SELECT last_mid FROM direct_room_backfill WHERE id = 1"
                ).fetchone()
                last = previous[0] if previous else 0
                newest = self.cursor.execute("SELECT MAX(mid) FROM messages").fetchone()[0]
                if newest is None or last >= newest:
                    self.conn.commit()
                    return
                while last < newest:
                    page = self.cursor.execute(
                        "SELECT mid, room_key FROM messages "
                        "WHERE mid > ? AND mid <= ? ORDER BY mid LIMIT 4096",
                        (last, newest),
                    ).fetchall()
                    keys = {key for _, key in page}
                    rows = [row for key in keys if (row := self._direct_room_row(key))]
                    if rows:
                        self.cursor.executemany(self._INSERT_DIRECT_ROOM, rows)
                    last = page[-1][0] if page else newest
                    self.cursor.execute(
                        "INSERT OR IGNORE INTO direct_room_backfill(id, last_mid) VALUES (1, 0)"
                    )
                    self.cursor.execute(
                        "UPDATE direct_room_backfill SET last_mid = ? WHERE id = 1 AND last_mid < ?",
                        (last, last),
                    )
                    self.conn.commit()
            self._execute_with_retry(operation)

    def _insert_message_locked(self, sql, params):
        if isinstance(self.dialect, PostgreSQLDialect):
            return self.cursor.execute(sql + " RETURNING mid", params).fetchone()[0]
        self.cursor.execute(sql, params)
        return self.cursor.lastrowid

    def _advance_room_sequence_locked(self, room_key, count):
        params = (count, room_key)
        if isinstance(self.dialect, MySQLDialect):
            # MySQL returns LAST_INSERT_ID(expr) in the UPDATE response.
            self.cursor.execute(
                "UPDATE room_sequences SET last_seq = LAST_INSERT_ID(last_seq + ?) WHERE room_key = ?",
                params)
            return self.cursor.lastrowid if self.cursor.rowcount else None
        advance = "UPDATE room_sequences SET last_seq = last_seq + ? WHERE room_key = ?"
        if self.dialect.supports_returning:
            row = self.cursor.execute(advance + " RETURNING last_seq", params).fetchone()
        else:
            # Older embedded SQLite builds predate DML RETURNING.
            self.cursor.execute(advance, params)
            if not self.cursor.rowcount:
                return None
            row = self.cursor.execute(
                "SELECT last_seq FROM room_sequences WHERE room_key = ?", (room_key,)
            ).fetchone()
        return row[0] if row else None

    def _allocate_room_sequences_locked(self, room_key, count=1):
        """Reserve consecutive sequence numbers in the same transaction as the write."""
        last = self._advance_room_sequence_locked(room_key, count)
        if last is None:
            room = self._direct_room_row(room_key)
            if room is not None:
                self.cursor.execute(self._INSERT_DIRECT_ROOM, room)
            self.cursor.execute(
                "INSERT OR IGNORE INTO room_sequences (room_key, last_seq) "
                "SELECT ?, COALESCE(MAX(room_seq), 0) FROM messages WHERE room_key = ?",
                (room_key, room_key),
            )
            last = self._advance_room_sequence_locked(room_key, count)
        return last - count + 1

    def _refresh_room_sequences(self):
        # A server downgraded to a version without counters may have written newer rows.
        self.execute("""
            UPDATE room_sequences
               SET last_seq = (SELECT MAX(room_seq) FROM messages
                                WHERE messages.room_key = room_sequences.room_key)
             WHERE EXISTS (SELECT 1 FROM messages
                            WHERE messages.room_key = room_sequences.room_key
                              AND messages.room_seq > room_sequences.last_seq)
        """)

    def query_history(self, uid: int, target_uid: int,
                      before_mid: int = 0, limit: int = 50,
                      group_id: int = None) -> list:
        """返回历史消息，按 mid 倒序排列。

        """
        room_key = self.room_key_of(uid, target_uid, group_id)
        where = "room_key = ? AND content_type != 'event'"
        params = [room_key]

        if before_mid > 0:
            where += " AND mid < ?"
            params.append(before_mid)

        sql = """SELECT mid, client_mid, sender_uid, receiver_uid, group_id,
                         content, content_type, file_hash, send_time, quote, deleted,
                          deleted_at, deleted_by, file_name, forwarded, duration, room_key, room_seq
                  FROM messages WHERE {} ORDER BY mid DESC LIMIT ?""".format(where)
        params.append(limit)
        return self.query(sql, tuple(params))

    def search_room_messages(self, uid: int, target_uid: int, keyword: str,
                             before_mid: int = 0, limit: int = 20,
                             group_id: int = None) -> list:
        """
        在单个房间内按关键词搜索历史消息
        """
        if not isinstance(keyword, str) or not keyword:
            return []
        room_key = self.room_key_of(uid, target_uid, group_id)
        where = ("room_key = ? AND content_type = 'plain' AND deleted = 0"
                 " AND instr(lower(content), ?) > 0")
        params = [room_key, keyword.lower()]
        if before_mid and before_mid > 0:
            where += " AND mid < ?"
            params.append(int(before_mid))
        params.append(max(1, int(limit)))
        return self.query(
            "{} WHERE {} ORDER BY mid DESC LIMIT ?".format(self._SELECT_ALL, where),
            tuple(params),
        )

    def query_sync(self, room_key: str, after_seq: int = 0,
                   after_mid: int = 0, limit: int = 100,
                   include_events: bool = True) -> list:
        """按房间增量同步：优先按 room_seq，其次按 mid
        升序返回
        """
        if after_seq < 0:
            after_seq = 0
        if after_mid < 0:
            after_mid = 0
        event_filter = "" if include_events else " AND content_type != 'event'"
        if after_seq > 0:
            rows = self.query(
                "{} WHERE room_key = ? AND room_seq > ?{} "
                "ORDER BY room_seq ASC LIMIT ?".format(self._SELECT_ALL, event_filter),
                (room_key, after_seq, limit),
            )
        elif after_mid > 0:
            rows = self.query(
                "{} WHERE room_key = ? AND mid > ?{} "
                "ORDER BY mid ASC LIMIT ?".format(self._SELECT_ALL, event_filter),
                (room_key, after_mid, limit),
            )
        else:
            rows = self.query(
                "{} WHERE room_key = ?{} "
                "ORDER BY room_seq ASC LIMIT ?".format(self._SELECT_ALL, event_filter),
                (room_key, limit),
            )
        return self.serialize_rows(rows)

    def sync_cursor_for_mid(self, room_key: str, mid: int):
        """返回房间内 mid 的 (room_seq, deleted)"""
        rows = self.query(
            "SELECT room_seq, deleted FROM messages WHERE room_key = ? AND mid = ?",
            (room_key, mid),
        )
        return (rows[0][0], bool(rows[0][1])) if rows else None

    def sync_after_seq_for_mid(self, room_key: str, mid: int):
        """将旧客户端的 mid 游标转换为房间序号"""
        cursor = self.sync_cursor_for_mid(room_key, mid)
        if cursor is None or cursor[0] is None:
            return None
        # recall_message moves the old mid to a new sequence; include that tombstone.
        return max(cursor[0] - 1, 0) if cursor[1] else cursor[0]

    def query_missing_sequences(self, room_key: str, sequences: list,
                                include_events: bool = True) -> list:
        """按具体房间序号取消息，升序返回"""
        sequences = sorted({int(s) for s in sequences if s is not None})
        if not sequences:
            return []
        placeholders = ",".join("?" * len(sequences))
        event_filter = "" if include_events else " AND content_type != 'event'"
        rows = self.query(
            "{} WHERE room_key = ? AND room_seq IN ({}){} "
            "ORDER BY room_seq ASC".format(self._SELECT_ALL, placeholders, event_filter),
            tuple([room_key] + sequences),
        )
        return self.serialize_rows(rows)

    def current_room_seq(self, room_key: str) -> int:
        rows = self.query(
            "SELECT MAX(room_seq) FROM messages WHERE room_key = ?", (room_key,)
        )
        return rows[0][0] if rows and rows[0][0] is not None else 0

    _COLUMNS = ["mid", "client_mid", "sender_uid", "receiver_uid", "group_id",
                  "content", "content_type", "file_hash", "send_time", "quote", "deleted",
                  "deleted_at", "deleted_by", "file_name", "forwarded", "duration",
                  "room_key", "room_seq"]

    _SELECT_ALL = ("SELECT mid, client_mid, sender_uid, receiver_uid, group_id,"
                   " content, content_type, file_hash, send_time, quote, deleted,"
                   " deleted_at, deleted_by, file_name, forwarded, duration,"
                   " room_key, room_seq"
                   " FROM messages")

    @staticmethod
    def _redact_recalled(record: dict) -> dict:
        if record.get("deleted"):
            record["content"] = None
            record["file_hash"] = None
        return record

    @staticmethod
    def _quote_preview(record: dict) -> dict:
        preview = {
            "mid": record["mid"],
            "sender_uid": record["sender_uid"],
            "content_type": record["content_type"],
            "content": record["content"][:240] if record["content"] is not None else None,
            "file_hash": record["file_hash"],
            "file_name": record.get("file_name"),
            "duration": record.get("duration"),
            "deleted": bool(record["deleted"]),
            "deleted_at": record["deleted_at"],
        }
        return MessagesDb._redact_recalled(preview)

    @staticmethod
    def _redirect_entry(record: dict) -> dict:
        """单条消息的转发快照"""
        return {
            "mid": record["mid"],
            "sender_uid": record["sender_uid"],
            "content": record["content"],
            "content_type": record["content_type"],
            "file_hash": record["file_hash"],
            "file_name": record.get("file_name"),
            "duration": record.get("duration"),
            "send_time": record["send_time"],
        }

    @staticmethod
    def _redirect_room_snapshot(room_key: str, group_name: str) -> dict:
        if room_key.startswith("G"):
            return {"type": "group", "id": room_key, "name": group_name}
        return {"type": "private", "id": room_key, "name": ""}

    def build_redirect_snapshot(self, sender_uid: int, mids: list,
                                group_name: str = "") -> dict:
        """按时间序冻结所选消息为合并转发
        """
        records = self.get_messages_by_mids(mids)
        ordered = sorted(
            (records[int(m)] for m in mids if int(m) in records),
            key=lambda r: (r["send_time"], r["mid"]),
        )
        room_key = ordered[0]["room_key"] if ordered else ""
        entries = [self._redirect_entry(r) for r in ordered]
        return {
            "version": 2 if len(entries) > 1 else 1,
            "kind": "history_segment" if len(entries) > 1 else "single",
            "source_room": self._redirect_room_snapshot(room_key, group_name),
            "source_room_id": room_key,
            "message_count": len(entries),
            "redirected_by": sender_uid,
            "messages": entries,
        }

    @staticmethod
    def parse_redirect(content: str):
        import json as _json
        try:
            return _json.loads(content) if content else None
        except Exception:
            return None

    @staticmethod
    def _same_conversation(message: dict, quoted: dict) -> bool:
        if message.get("group_id") is not None or quoted.get("group_id") is not None:
            return (message.get("group_id") is not None
                    and message.get("group_id") == quoted.get("group_id"))
        return {message["sender_uid"], message["receiver_uid"]} == {
            quoted["sender_uid"], quoted["receiver_uid"]
        }

    def serialize_rows(self, rows) -> list:
        records = [dict(zip(self._COLUMNS, r)) for r in rows]
        if not records:
            return records
        mids = [record["mid"] for record in records]
        placeholders = ",".join("?" * len(mids))
        mention_rows = self.query(
            "SELECT mid, uid FROM message_mentions WHERE mid IN ({})".format(placeholders),
            tuple(mids),
        )
        mentions = {}
        for mid, uid in mention_rows:
            mentions.setdefault(mid, []).append(uid)
        for record in records:
            record["mentioned_uids"] = mentions.get(record["mid"], [])
        quote_mids = sorted({
            mid for record in records
            for mid in (record["quote"], record["forwarded"]) if mid >= 0
        })
        quote_map = {}
        if quote_mids:
            placeholders = ",".join("?" * len(quote_mids))
            quote_rows = self.query(
                """SELECT mid, client_mid, sender_uid, receiver_uid, group_id,
                          content, content_type, file_hash, send_time, quote, deleted,
                           deleted_at, deleted_by, file_name, forwarded, duration, room_key, room_seq
                   FROM messages WHERE mid IN ({})""".format(placeholders),
                tuple(quote_mids),
            )
            for row in quote_rows:
                quote_record = dict(zip(self._COLUMNS, row))
                quote_map[quote_record["mid"]] = quote_record
        for record in records:
            quoted = quote_map.get(record["quote"])
            record["quote_preview"] = (
                self._quote_preview(quoted)
                if quoted and self._same_conversation(record, quoted) else None
            )
            forwarded = quote_map.get(record["forwarded"])
            record["forward_preview"] = (
                self._quote_preview(forwarded)
                if forwarded and self._same_conversation(record, forwarded) else None
            )
            self._redact_recalled(record)
        return records

    def get_quote_preview(self, mid: int, message=None):
        rows = self.query(
            """SELECT mid, client_mid, sender_uid, receiver_uid, group_id,
                      content, content_type, file_hash, send_time, quote, deleted,
                        deleted_at, deleted_by, file_name, forwarded, duration, room_key, room_seq
                      FROM messages WHERE mid = ?""",
            (mid,),
        )
        if not rows:
            return None
        quoted = dict(zip(self._COLUMNS, rows[0]))
        if message is not None and not self._same_conversation(message, quoted):
            return None
        return self._quote_preview(quoted)

    def get_chat_list(self, uid: int) -> list:
        """返回与每个用户的最新单聊消息
        群聊由 API 接口单独合并
        """
        rows = self.query(
            """SELECT
                 CASE WHEN m.sender_uid = ? THEN m.receiver_uid ELSE m.sender_uid END AS partner_uid,
                 m.mid, m.client_mid, m.sender_uid, m.content, m.content_type, m.send_time,
                 m.deleted, m.deleted_at, m.file_name,
                 (SELECT e.room_seq FROM messages e
                   WHERE e.room_key = d.room_key AND e.group_id IS NULL AND e.sender_uid != e.receiver_uid
                     AND (e.sender_uid = ? OR e.receiver_uid = ?)
                   ORDER BY e.room_seq DESC LIMIT 1)
               FROM direct_rooms d
               JOIN messages m ON m.mid = (
                 SELECT v.mid FROM messages v
                  WHERE v.room_key = d.room_key AND v.group_id IS NULL AND v.content_type != 'event'
                    AND v.sender_uid != v.receiver_uid AND (v.sender_uid = ? OR v.receiver_uid = ?)
                  ORDER BY v.mid DESC LIMIT 1
               )
               WHERE d.low_uid = ? OR d.high_uid = ?
               ORDER BY m.mid DESC""",
            (uid, uid, uid, uid, uid, uid, uid),
        )
        return [
            {
                "partner_uid": r[0],
                "group_id": None,
                "last_mid": r[1],
                "last_client_mid": r[2],
                "last_sender_uid": r[3],
                "last_content": None if r[7] else r[4],
                "last_content_type": r[5],
                "last_time": r[6],
                "last_deleted": bool(r[7]),
                "last_deleted_at": r[8],
                "last_file_name": r[9],
                "last_seq": r[10],
            }
            for r in rows
        ]

    @staticmethod
    def _requested_rooms(room_keys):
        # A small driver table lets each room seek into (room_key, room_seq)
        # or (room_key, mid). Keep below SQLite's compound SELECT limit.
        keys = list(dict.fromkeys(room_keys))
        for start in range(0, len(keys), 256):
            batch = tuple(keys[start:start + 256])
            cte = "WITH requested(room_key) AS ({}) ".format(
                " UNION ALL ".join(["SELECT ?"] * len(batch)))
            yield cte, batch

    def get_group_last_messages(self, group_ids: list) -> dict:
        """批量获取多个群聊的最新消息，事件参与房间序号但不作为预览。"""
        rows = []
        for cte, keys in self._requested_rooms("G{}".format(gid) for gid in (group_ids or ())):
            rows.extend(self.query(
                cte + """SELECT m.mid, m.sender_uid, m.content, m.content_type,
                         m.send_time, m.group_id, m.deleted, m.deleted_at, m.file_name,
                         (SELECT MAX(room_seq) FROM messages WHERE room_key = r.room_key)
                    FROM requested r
                    JOIN messages m ON m.mid = (
                       SELECT mid FROM messages WHERE room_key = r.room_key
                         AND content_type != 'event' ORDER BY mid DESC LIMIT 1
                    )""",
                keys,
            ))
        return {
            r[5]: {
                "mid": r[0], "sender_uid": r[1], "content": None if r[6] else r[2],
                "content_type": r[3], "send_time": r[4], "deleted": bool(r[6]),
                "deleted_at": r[7],
                "file_name": r[8],
                "last_seq": r[9],
            }
            for r in rows
        }

    def verify_quote(self, quote_mid: int, sender_uid: int = 0,
                     target_uid: int = 0, group_id: int = None) -> bool:
        """
        引用的目标消息是否可被当前会话引用
        """
        rows = self.query(
            "SELECT sender_uid, receiver_uid, group_id, content_type "
            "FROM messages WHERE mid = ?",
            (quote_mid,)
        )
        if not rows:
            return False
        r = rows[0]
        if r[3] == 'event':  # 事件行不是用户内容
            return False
        if group_id is not None:
            return r[2] == group_id
        return r[2] is None and {r[0], r[1]} == {sender_uid, target_uid}

    def get_messages_by_mids(self, mids: list) -> dict:
        """按 mid 批量取消息"""
        mids = [int(m) for m in mids]
        if not mids:
            return {}
        placeholders = ",".join("?" * len(mids))
        rows = self.query(
            """SELECT mid, client_mid, sender_uid, receiver_uid, group_id,
                       content, content_type, file_hash, send_time, quote, deleted,
                        deleted_at, deleted_by, file_name, forwarded, duration, room_key, room_seq
                      FROM messages WHERE mid IN ({})""".format(placeholders),
            tuple(mids),
        )
        return {row[0]: dict(zip(self._COLUMNS, row)) for row in rows}

    def get_message(self, mid: int, include_recalled_original=False):
        rows = self.query(
            """SELECT mid, client_mid, sender_uid, receiver_uid, group_id,
                       content, content_type, file_hash, send_time, quote, deleted,
                        deleted_at, deleted_by, file_name, forwarded, duration, room_key, room_seq
                      FROM messages WHERE mid = ?""",
            (mid,),
        )
        if not rows:
            return None
        record = dict(zip(self._COLUMNS, rows[0]))
        if not include_recalled_original:
            self._redact_recalled(record)
        return record

    def recalled_mids(self, mids) -> set:
        """
        给定 mid 中已撤回
        """
        targets = [int(m) for m in (mids or []) if m is not None]
        if not targets:
            return set()
        recalled = set()
        for start in range(0, len(targets), 400):
            chunk = targets[start:start + 400]
            placeholders = ",".join("?" * len(chunk))
            rows = self.query(
                "SELECT mid FROM messages WHERE mid IN ({}) AND deleted = 1".format(
                    placeholders),
                tuple(chunk),
            )
            recalled.update(row[0] for row in rows)
        return recalled

    def request_matches(self, mid : int, sender_uid : int, receiver_uid : int,
                        content : str, content_type : str, file_hash=None,
                         quote : int = -1, group_id=None, forwarded : int = -1,
                         duration=None) -> bool:
        message = self.get_message(mid, include_recalled_original=True)
        if message is None:
            return False
        return (
            message["sender_uid"] == sender_uid
            and message["receiver_uid"] == receiver_uid
            and message["group_id"] == group_id
            and message["content"] == content
            and message["content_type"] == content_type
            and message["file_hash"] == file_hash
            and message["quote"] == quote
            and message["forwarded"] == forwarded
            and (duration is None or message.get("duration") == duration)
        )

    def get_by_client_mid(self, sender_uid : int, client_mid : str):
        if client_mid is None:
            return None
        rows = self.query(
            self._SELECT_ALL + " WHERE sender_uid = ? AND client_mid = ?",
            (sender_uid, client_mid),
        )
        return self._redact_recalled(dict(zip(self._COLUMNS, rows[0]))) if rows else None

    def recall_message(self, mid: int, deleted_by: int, emit_event: bool = True) -> int:
        """撤回消息
        """
        with self.lock:
            def operation():
                row = self.cursor.execute(
                    "SELECT room_key, receiver_uid, group_id FROM messages "
                    "WHERE mid = ? AND deleted = 0 AND content_type != ?",
                    (mid, self.EVENT_CONTENT_TYPE),
                ).fetchone()
                if not row:
                    self.conn.commit()
                    return 0
                room_key, receiver_uid, group_id = row
                room_seq = self._allocate_room_sequences_locked(room_key, 2 if emit_event else 1)
                self.cursor.execute(
                    """UPDATE messages SET deleted = 1, deleted_at = ?, deleted_by = ?,
                       room_seq = ? WHERE mid = ? AND deleted = 0""",
                    (time.time(), deleted_by, room_seq, mid),
                )
                if self.cursor.rowcount == 0:
                    self.conn.rollback()
                    return 0
                if emit_event:
                    event_mid = self._insert_message_locked(
                        """INSERT INTO messages
                           (client_mid, sender_uid, receiver_uid, group_id, content, content_type,
                             file_hash, send_time, quote, file_name, forwarded, duration, room_key, room_seq)
                            VALUES (NULL, ?, ?, ?, ?, ?, NULL, ?, -1, NULL, -1, NULL, ?, ?)""",
                        (deleted_by, receiver_uid, group_id,
                         self.build_event_content("message.recalled", target_mid=mid),
                         self.EVENT_CONTENT_TYPE, time.time(), room_key, room_seq + 1),
                    )
                    # 同上：撤回产生的墓碑只是抬水位，不算「读过别人的消息」
                    self._advance_read_watermark_locked(
                        deleted_by, room_key, room_seq + 1, event_mid, genuine=False)
                self.conn.commit()
                return room_seq
            return self._execute_with_retry(operation)

    def delete_message(self, mid: int) -> bool:
        return self.recall_message(mid, 0) > 0

    def purge_user_state(self, uid: int) -> bool:
        """
        删除某用户的会话状态
        消息本身不删
        """
        uid = int(uid)
        with self.lock:
            def operation():
                self.cursor.execute(
                    "DELETE FROM room_read_state WHERE uid = ?", (uid,))
                self.cursor.execute(
                    "DELETE FROM room_preferences WHERE uid = ?", (uid,))
                self.cursor.execute(
                    "DELETE FROM message_mentions WHERE uid = ?", (uid,))
                self.conn.commit()
                return True
            return self._execute_with_retry(operation)

    def count_file_references(self, file_hash: str) -> int:
        rows = self.query(
            "SELECT COUNT(*) FROM messages WHERE file_hash = ?",
            (file_hash,),
        )
        return rows[0][0] if rows else 0

    def get_file_reference_rows(self):
        return [
            (row[0], "message", row[1], row[2])
            for row in self.query(
                """SELECT file_hash, mid, sender_uid FROM messages
                   WHERE file_hash IS NOT NULL AND deleted = 0"""
            )
        ]

    def get_room_preferences(self, uid: int) -> dict:
        rows = self.query(
            "SELECT room_id, is_pinned, notify_level, alias, description "
            "FROM room_preferences WHERE uid = ?",
            (uid,),
        )
        return {
            row[0]: {
                "is_pinned": bool(row[1]),
                "notify_level": int(row[2]),
                "alias": row[3] or "",
                "description": row[4] or "",
            }
            for row in rows
        }

    def get_room_preference_map(self, uids, room_id: str) -> dict:
        """批量获取多个用户对同一房间的通知偏好"""
        uids = list({int(uid) for uid in uids})
        preferences = {}
        for start in range(0, len(uids), 500):
            batch = uids[start:start + 500]
            placeholders = ",".join("?" * len(batch))
            rows = self.query(
                "SELECT uid, is_pinned, notify_level FROM room_preferences "
                "WHERE uid IN ({}) AND room_id = ?".format(placeholders),
                tuple(batch) + (room_id,),
            )
            for uid, pinned, level in rows:
                preferences[uid] = {"is_pinned": bool(pinned), "notify_level": int(level)}
        return preferences

    def get_room_preference(self, uid: int, room_id: str) -> dict:
        rows = self.query(
            "SELECT is_pinned, notify_level, alias, description "
            "FROM room_preferences WHERE uid = ? AND room_id = ?",
            (uid, room_id),
        )
        if not rows:
            return {"is_pinned": False, "notify_level": 0, "alias": "", "description": ""}
        return {
            "is_pinned": bool(rows[0][0]),
            "notify_level": int(rows[0][1]),
            "alias": rows[0][2] or "",
            "description": rows[0][3] or "",
        }

    def update_room_preference(self, uid: int, room_id: str,
                               is_pinned=None, notify_level=None,
                               alias=None, description=None) -> bool:
        level = int(notify_level) if notify_level is not None else 0
        if level not in (0, 1, 2):
            return False
        columns = {
            "is_pinned": is_pinned,
            "notify_level": notify_level,
            "alias": alias,
            "description": description,
            "updated_at": True,
        }
        assignments = ", ".join(
            f"{column} = excluded.{column}" for column, value in columns.items()
            if value is not None
        )
        self.execute(
            """INSERT INTO room_preferences(uid, room_id, is_pinned, notify_level, alias, description, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(uid, room_id) DO UPDATE SET {}""".format(assignments),
            (uid, room_id, int(bool(is_pinned)), level, str(alias) if alias is not None else "",
             str(description) if description is not None else "", time.time()),
        )
        return True

    def _watermark_upsert(self, genuine):
        newer = "excluded.last_read_seq > room_read_state.last_read_seq"
        changed = newer
        if genuine:
            changed += " OR excluded.last_read_mid > room_read_state.last_read_mid"
        # MySQL evaluates column assignments left-to-right. Test the old values
        # for the timestamp and mid before assigning the new sequence.
        assignments = [
            f"updated_at = CASE WHEN {changed} THEN excluded.updated_at ELSE room_read_state.updated_at END"
        ]
        if genuine:
            assignments.append(
                f"last_read_mid = CASE WHEN {changed} THEN excluded.last_read_mid ELSE room_read_state.last_read_mid END")
        assignments.append(
            f"last_read_seq = CASE WHEN {newer} THEN excluded.last_read_seq ELSE room_read_state.last_read_seq END")
        sql = ("INSERT INTO room_read_state(uid, room_key, last_read_seq, last_read_mid, updated_at) "
               "VALUES (?, ?, ?, ?, ?) ON CONFLICT(uid, room_key) DO UPDATE SET " + ", ".join(assignments))
        if not isinstance(self.dialect, MySQLDialect):
            # Keep rowcount zero when both the sequence and genuine mid are stale.
            sql += " WHERE " + changed
        return sql

    def _advance_read_watermark_locked(self, uid: int, room_key: str,
                                       seq: int, mid: int,
                                       genuine: bool = True) -> bool:
        """Sequence comparisons and updates run atomically across server processes."""
        if not seq or seq <= 0:
            return False
        self.cursor.execute(
            self._explicit_watermark if genuine else self._implicit_watermark,
            (uid, room_key, seq, mid if genuine else 0, time.time()),
        )
        # A genuine receipt with a valid mid is acknowledged on retry as well.
        return self.cursor.rowcount > 0 or (genuine and int(mid or 0) > 0)

    def update_read_state(self, uid: int, room_key: str, last_seq: int,
                          last_mid: int) -> bool:
        """客户端上报已读（WS message.read）时调用。返回是否前进。"""
        with self.lock:
            def operation():
                advanced = self._advance_read_watermark_locked(
                    uid, room_key, last_seq, last_mid)
                self.conn.commit()
                return advanced
            return self._execute_with_retry(operation)

    def get_read_state(self, uid: int, room_key: str):
        """读取已读状态"""
        rows = self.query(
            "SELECT s.last_read_seq, s.last_read_mid, m.room_seq, m.deleted "
            "FROM room_read_state s "
            "LEFT JOIN messages m ON m.mid = s.last_read_mid "
            "WHERE s.uid = ? AND s.room_key = ?",
            (uid, room_key),
        )
        if not rows:
            return None
        last_read_seq, last_read_mid, genuine_seq, deleted = rows[0]
        # 撤回会把 mid 挪到序列末尾
        if genuine_seq is None or deleted:
            genuine_seq = 0
        return {
            "last_read_seq": last_read_seq,
            "last_read_mid": last_read_mid,
            "genuine_seq": int(genuine_seq or 0),
        }

    def read_states_for_room(self, room_key: str, min_seq: int):
        """房间内读到 >= min_seq的成员列表

        和私聊不一样是刻意的设计
        """
        rows = self.query(
            "SELECT s.uid, m.room_seq, s.last_read_mid "
            "FROM room_read_state s "
            "JOIN messages m ON m.mid = s.last_read_mid AND m.room_key = s.room_key "
            "WHERE s.room_key = ? AND m.room_seq >= ?",
            (room_key, int(min_seq)),
        )
        return [
            {"uid": int(r[0]), "last_read_seq": int(r[1]), "last_read_mid": int(r[2])}
            for r in rows
        ]

    def init_read_watermarks(self, uid: int, room_keys) -> None:
        """为已有消息且尚无已读水位的房间建立初始水位。"""
        now = time.time()
        for cte, keys in self._requested_rooms(k for k in room_keys if k):
            rows = self.query(
                cte + """SELECT r.room_key,
                          (SELECT MAX(room_seq) FROM messages WHERE room_key = r.room_key)
                     FROM requested r WHERE NOT EXISTS (
                       SELECT 1 FROM room_read_state WHERE uid = ? AND room_key = r.room_key
                     )""",
                keys + (uid,),
            )
            values = [(uid, key, seq, 0, now) for key, seq in rows if seq is not None]
            if values:
                self.update(
                    "INSERT OR IGNORE INTO room_read_state"
                    "(uid, room_key, last_read_seq, last_read_mid, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    values,
                )

    def _count_unread(self, uid: int, keys, mentions_only: bool = False) -> dict:
        """按房间从已读水位开始扫描。静音房间在调用方跳过。"""
        mention_filter = (
            "AND EXISTS (SELECT 1 FROM message_mentions mm WHERE mm.mid = m.mid AND mm.uid = ?)"
            if mentions_only else ""
        )
        counts = {}
        for cte, batch in self._requested_rooms(keys):
            rows = self.query(
                cte + """SELECT r.room_key, (
                        SELECT COUNT(*) FROM messages m
                         WHERE m.room_key = r.room_key AND m.room_seq > COALESCE(s.last_read_seq, 0)
                           AND m.sender_uid != ? AND m.content_type != 'event' AND m.deleted = 0
                           {}
                    ) FROM requested r LEFT JOIN room_read_state s
                        ON s.room_key = r.room_key AND s.uid = ?""".format(mention_filter),
                batch + ((uid, uid, uid) if mentions_only else (uid, uid)),
            )
            counts.update((key, int(count)) for key, count in rows if count)
        return counts

    def bulk_unread_counts(self, uid: int, room_keys, notify_level_map=None) -> dict:
        """批量计算各房间未读条数
        """
        keys = [k for k in set(room_keys) if k]
        if not keys:
            return {}
        notify_level_map = notify_level_map or {}
        level0 = [k for k in keys if int(notify_level_map.get(k, 0)) == 0]
        level1 = [k for k in keys if int(notify_level_map.get(k, 0)) == 1]
        counts = {}
        if level0:
            counts.update(self._count_unread(uid, level0))
        if level1:
            counts.update(self._count_unread(uid, level1, mentions_only=True))
        return counts

    def pin_message(self, message_id: int, group_id: int, pinned_by_uid: int) -> int:
        with self.lock:
            self.cursor.execute(
                """INSERT OR IGNORE INTO group_pinned_messages
                   (message_id, group_id, pinned_by_uid, created_at)
                   VALUES (?, ?, ?, ?)""",
                (message_id, group_id, pinned_by_uid, time.time()),
            )
            pin_id = self.cursor.lastrowid
            self.conn.commit()
            return pin_id

    def unpin_message(self, pin_id: int, group_id: int) -> bool:
        with self.lock:
            self.cursor.execute(
                "DELETE FROM group_pinned_messages WHERE pin_id = ? AND group_id = ?",
                (pin_id, group_id),
            )
            self.conn.commit()
            return self.cursor.rowcount > 0

    def unpin_message_by_mid(self, message_id: int, group_id: int) -> bool:
        with self.lock:
            self.cursor.execute(
                "DELETE FROM group_pinned_messages WHERE message_id = ? AND group_id = ?",
                (message_id, group_id),
            )
            self.conn.commit()
            return self.cursor.rowcount > 0

    def get_pinned_messages(self, group_id: int) -> list:
        return self.query(
            """SELECT pin_id, message_id, group_id, pinned_by_uid, created_at
               FROM group_pinned_messages
               WHERE group_id = ?
               ORDER BY created_at ASC""",
            (group_id,),
        )

    def is_message_pinned(self, message_id: int, group_id: int) -> bool:
        rows = self.query(
            "SELECT 1 FROM group_pinned_messages WHERE message_id = ? AND group_id = ?",
            (message_id, group_id),
        )
        return len(rows) > 0

    def get_pin_by_message(self, message_id: int, group_id: int):
        rows = self.query(
            """SELECT pin_id, message_id, group_id, pinned_by_uid, created_at
               FROM group_pinned_messages
               WHERE message_id = ? AND group_id = ?""",
            (message_id, group_id),
        )
        if not rows:
            return None
        record = rows[0]
        return {
            "pin_id": record[0],
            "message_id": record[1],
            "group_id": record[2],
            "pinned_by_uid": record[3],
            "created_at": record[4],
        }

# wyf dl tql
