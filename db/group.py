from db.tool import Db
import json
import time


GROUP_MEMBERS_MIGRATION = "group_members_v1"
JOIN_POLICY_MIGRATION = "group_join_policy_v1"

# 加入策略：
# - open          允许自由加入：任何人可直接加入
# - approval      允许审批加入：任何人可申请，管理员审批
# - invite        仅允许邀请：任一成员可邀请，被邀请者直接入群
# - admin_invite  仅允许管理员邀请：只有群主/管理员能邀请
JOIN_POLICIES = ("open", "approval", "invite", "admin_invite")
DEFAULT_JOIN_POLICY = "approval"


JOIN_POLICY_COMPAT = {
    "open": (1, 0),
    "approval": (1, 1),
    "invite": (0, 0),
    "admin_invite": (0, 1),
}


def policy_compat_columns(policy):
    """兼容值"""
    return JOIN_POLICY_COMPAT.get(policy, JOIN_POLICY_COMPAT[DEFAULT_JOIN_POLICY])


def legacy_policy(allow_direct_join, require_review):
    """旧库迁移"""
    if allow_direct_join:
        return "open" if not require_review else "approval"
    return "invite" if not require_review else "admin_invite"


class GroupDb(Db):
    def __init__(self, path: str, port_api: int, config_reader=None, dialect=None):
        super().__init__(path, port_api, -1, dialect=dialect)
        self._config_reader = config_reader or self._default_config_reader
        self.create_group_table()

    def _default_config_reader(self):
        with open("res/{}/config.json".format(self.api_pt), "r+") as f:
            return json.load(f)

    def create_group_table(self):
        """
        essence 是精华，初始值为 []，存储 mid 时间戳
        """
        self.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                gid INTEGER UNIQUE NOT NULL,
                creater INTEGER NOT NULL,
                groupname TEXT,
                members TEXT,
                admins TEXT,
                enter_hint TEXT,
                introduction TEXT,
                allow_direct_join INTEGER NOT NULL DEFAULT 0,
                require_review INTEGER NOT NULL DEFAULT 1,
                essence TEXT,
                public_messages INTEGER NOT NULL DEFAULT 0,
                searchable INTEGER NOT NULL DEFAULT 1,
                join_policy TEXT NOT NULL DEFAULT 'approval'
            )
        """)
        self.execute("""
            CREATE TABLE IF NOT EXISTS join_requests (
                rid INTEGER PRIMARY KEY AUTOINCREMENT,
                gid INTEGER NOT NULL,
                uid INTEGER NOT NULL,
                inviter_uid INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                request_time REAL NOT NULL,
                message TEXT NOT NULL DEFAULT ''
            )
        """)
        self.execute("""
            CREATE TABLE IF NOT EXISTS group_id_sequence (
                id INTEGER PRIMARY KEY AUTOINCREMENT
            )
        """)
        self.execute("""
            CREATE TABLE IF NOT EXISTS group_id_counter (
                id INTEGER PRIMARY KEY,
                next_gid INTEGER NOT NULL
            )
        """)
        # Preserve IDs consumed by older versions, including deleted groups.
        next_gid = self.query("""
            SELECT MAX(last_id) + 1 FROM (
                SELECT COALESCE(MAX(gid), 0) AS last_id FROM groups
                UNION ALL SELECT COALESCE(MAX(id), 0) FROM group_id_sequence
            ) AS existing_ids
        """)[0][0]
        self.execute("INSERT OR IGNORE INTO group_id_counter (id, next_gid) VALUES (1, ?)",
                     (next_gid,))
        self.execute("UPDATE group_id_counter SET next_gid = ? WHERE id = 1 AND next_gid < ?",
                     (next_gid, next_gid))
        self._migrate()

    def _parse_essence(self, raw) -> list:
        if not raw:
            return []
        try:
            result = json.loads(raw)
            return result if isinstance(result, list) else []
        except (ValueError, TypeError):
            return []

    def add_essence(self, gid, mid):
        with self.lock:
            def _add_essence():
                self.cursor.execute("SELECT essence FROM groups WHERE gid = ?", (gid,))
                row = self.cursor.fetchone()
                if not row:
                    self.conn.commit()
                    return False
                essence_list = self._parse_essence(row[0])
                if mid in essence_list:
                    self.conn.commit()
                    return False
                essence_list.append(mid)
                essence_list.sort(reverse=True)
                self.cursor.execute("UPDATE groups SET essence = ? WHERE gid = ?", (json.dumps(essence_list), gid))
                self.conn.commit()
                return True
            return self._execute_with_retry(_add_essence)

    def remove_essence(self, gid, mid):
        with self.lock:
            def _remove_essence():
                self.cursor.execute("SELECT essence FROM groups WHERE gid = ?", (gid,))
                row = self.cursor.fetchone()
                if not row:
                    self.conn.commit()
                    return False
                essence_list = self._parse_essence(row[0])
                if mid not in essence_list:
                    self.conn.commit()
                    return False
                essence_list.remove(mid)
                self.cursor.execute("UPDATE groups SET essence = ? WHERE gid = ?", (json.dumps(essence_list), gid))
                self.conn.commit()
                return True
            return self._execute_with_retry(_remove_essence)

    def query_essence(self, gid):
        row = self.query("SELECT essence FROM groups WHERE gid = ?", (gid,))
        if not row:
            return []
        return self._parse_essence(row[0][0])

    def remove_essence_many(self, gid, mids) -> set:
        """批量遗精"""
        targets = {int(m) for m in (mids or []) if m is not None}
        if not targets:
            return set()

        with self.lock:
            def _remove_many():
                self.cursor.execute("SELECT essence FROM groups WHERE gid = ?", (gid,))
                row = self.cursor.fetchone()
                if not row:
                    self.conn.commit()
                    return set()
                essence_list = self._parse_essence(row[0])
                kept = [m for m in essence_list if m not in targets]
                if len(kept) == len(essence_list):
                    self.conn.commit()
                    return set()
                removed = set(essence_list) - set(kept)
                self.cursor.execute("UPDATE groups SET essence = ? WHERE gid = ?", (json.dumps(kept), gid))
                self.conn.commit()
                return removed
            return self._execute_with_retry(_remove_many)

    def _migrate(self):
        try:
            self.execute("ALTER TABLE groups ADD COLUMN allow_direct_join INTEGER NOT NULL DEFAULT 0")
        except Exception:
            pass
        try:
            self.execute("ALTER TABLE groups ADD COLUMN require_review INTEGER NOT NULL DEFAULT 1")
        except Exception:
            pass
        try:
            self.execute("ALTER TABLE groups ADD COLUMN essence TEXT DEFAULT '[]'")
        except Exception:
            pass
        try:
            self.execute("ALTER TABLE groups ADD COLUMN essence_enabled INTEGER NOT NULL DEFAULT 1")
        except Exception:
            pass
        try:
            self.execute("ALTER TABLE groups ADD COLUMN public_messages INTEGER NOT NULL DEFAULT 0")
        except Exception:
            pass
        try:
            self.execute("ALTER TABLE join_requests ADD COLUMN message TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass
        try:
            self.execute("ALTER TABLE groups ADD COLUMN searchable INTEGER NOT NULL DEFAULT 1")
        except Exception:
            pass
        try:
            self.execute(
                "ALTER TABLE groups ADD COLUMN join_policy TEXT NOT NULL DEFAULT '{}'".format(
                    DEFAULT_JOIN_POLICY
                )
            )
        except Exception:
            pass
        self.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                gid INTEGER NOT NULL,
                uid INTEGER NOT NULL,
                role INTEGER NOT NULL DEFAULT 0 CHECK(role IN (0, 1, 2)),
                join_time REAL NOT NULL,
                PRIMARY KEY (gid, uid)
            )
        """)
        self.execute("CREATE INDEX IF NOT EXISTS idx_group_members_uid ON group_members(uid, gid)")
        self.execute(
            "CREATE INDEX IF NOT EXISTS idx_join_requests_gid_status "
            "ON join_requests(gid, status, request_time)")
        self.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                name TEXT PRIMARY KEY,
                applied_at REAL NOT NULL
            )
        """)
        self._migrate_legacy_members()
        # 依赖 schema_migrations 表
        self._migrate_join_policy()

    def _migrate_join_policy(self):
        with self.lock:
            def operation():
                self.cursor.execute(
                    "SELECT 1 FROM schema_migrations WHERE name = ?",
                    (JOIN_POLICY_MIGRATION,),
                )
                if self.cursor.fetchone() is not None:
                    self.conn.commit()
                    return False
                self.cursor.execute(
                    "SELECT gid, allow_direct_join, require_review FROM groups"
                )
                updates = []
                for gid, allow_direct_join, require_review in self.cursor.fetchall():
                    policy = legacy_policy(
                        bool(allow_direct_join), bool(require_review)
                    )
                    allow, review = policy_compat_columns(policy)
                    updates.append((policy, allow, review, gid))
                if updates:
                    self.cursor.executemany(
                        "UPDATE groups SET join_policy = ?, allow_direct_join = ?,"
                        " require_review = ? WHERE gid = ?",
                        updates,
                    )
                self.cursor.execute(
                    "INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)",
                    (JOIN_POLICY_MIGRATION, time.time()),
                )
                self.conn.commit()
                return True

            return self._execute_with_retry(operation)

    def _migrate_legacy_members(self):
        with self.lock:
            def operation():
                self.cursor.execute(
                    "SELECT 1 FROM schema_migrations WHERE name = ?",
                    (GROUP_MEMBERS_MIGRATION,),
                )
                if self.cursor.fetchone() is not None:
                    self.conn.commit()
                    return False

                self.cursor.execute("SELECT gid, creater, members, admins FROM groups")
                for gid, creater, members_raw, admins_raw in self.cursor.fetchall():
                    try:
                        members = {int(uid) for uid in json.loads(members_raw or "[]")}
                    except (TypeError, ValueError):
                        members = set()
                    try:
                        admins = {int(uid) for uid in json.loads(admins_raw or "[]")}
                    except (TypeError, ValueError):
                        admins = set()

                    creater = int(creater)
                    all_members = members | admins | {creater}
                    for member_uid in all_members:
                        role = 2 if member_uid == creater else (1 if member_uid in admins else 0)
                        self.cursor.execute(
                            "INSERT OR REPLACE INTO group_members (gid, uid, role, join_time) VALUES (?, ?, ?, ?)",
                            (gid, member_uid, role, 0),
                        )

                self.cursor.execute(
                    "INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)",
                    (GROUP_MEMBERS_MIGRATION, time.time()),
                )
                self.conn.commit()
                return True

            return self._execute_with_retry(operation)

    def _hydrate_group_rows(self, rows):
        if not rows:
            return []
        gids = [row[0] for row in rows]
        placeholders = ",".join("?" * len(gids))
        params = tuple(gids)

        member_rows = self.query(
            f"SELECT gid, uid FROM group_members WHERE gid IN ({placeholders}) ORDER BY gid, join_time ASC, uid ASC",
            params,
        )
        member_map = {}
        for gid, uid in member_rows:
            member_map.setdefault(gid, []).append(uid)

        admin_rows = self.query(
            f"SELECT gid, uid FROM group_members WHERE gid IN ({placeholders}) AND role = 1 ORDER BY gid, join_time ASC, uid ASC",
            params,
        )
        admin_map = {}
        for gid, uid in admin_rows:
            admin_map.setdefault(gid, []).append(uid)

        hydrated = []
        for row in rows:
            gid = row[0]
            r = list(row)
            r[3] = json.dumps(member_map.get(gid, []))
            r[4] = json.dumps(admin_map.get(gid, []))
            hydrated.append(tuple(r))
        return hydrated

    def query_gid(self, gid: int):
        rows = self.query("SELECT * FROM groups WHERE gid = ?", (gid,))
        return self._hydrate_group_rows(rows)

    def query_creater(self, uid: int):
        rows = self.query("SELECT * FROM groups WHERE creater = ?", (uid,))
        return self._hydrate_group_rows(rows)

    def groupname_search(self, groupname: str):
        """[deprecated] 群名搜索。
        """
        if not isinstance(groupname, str):
            return []
        escaped = (
            groupname.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        rows = self.query(
            "SELECT * FROM groups WHERE groupname LIKE ? ESCAPE '\\' "
            "ORDER BY gid ASC LIMIT 50",
            ('%' + escaped + '%',),
        )
        results = []
        for row in rows:
            r = list(row)
            r[3] = "[]"
            r[4] = "[]"
            results.append(r)
        return results

    _PUBLIC_SELECT = """SELECT g.gid, g.groupname, g.introduction,
                      (SELECT COUNT(*) FROM group_members gm WHERE gm.gid = g.gid) AS member_count,
                      g.allow_direct_join, g.require_review, g.public_messages,
                      g.searchable, g.join_policy
               FROM groups g"""

    @staticmethod
    def _public_dict(row) -> dict:
        policy = row[8] or DEFAULT_JOIN_POLICY
        return {
            "gid": row[0],
            "groupname": row[1],
            "introduction": row[2] or "",
            "member_count": row[3],
            "allow_direct_join": bool(row[4]),
            "require_review": bool(row[5]),
            "public_messages": bool(row[6]),
            "searchable": bool(row[7]) if row[7] is not None else True,
            "join_policy": policy,
        }

    def lookup_by_gid(self, gid):
        if isinstance(gid, bool):
            # True 会被 int() 转成 1，误命中 gid=1
            return None
        try:
            gid = int(gid)
        except (TypeError, ValueError):
            return None
        rows = self.query(
            self._PUBLIC_SELECT + " WHERE g.gid = ? AND g.searchable = 1", (gid,)
        )
        return self._public_dict(rows[0]) if rows else None

    def search_public(self, keyword: str, limit: int = 20, offset: int = 0):
        """按群名搜索，仅返回公开字段

        返回 (groups, has_more)
        """
        escaped = (
            keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        prefix = escaped + "%"
        contains = "%" + escaped + "%"
        rows = self.query(
            self._PUBLIC_SELECT + """
               WHERE g.searchable = 1 AND g.groupname LIKE ? ESCAPE '\\'
               ORDER BY CASE WHEN g.groupname LIKE ? ESCAPE '\\' THEN 0 ELSE 1 END,
                        g.gid ASC
               LIMIT ? OFFSET ?""",
            (contains, prefix, limit + 1, offset),
        )
        has_more = len(rows) > limit
        groups = [self._public_dict(r) for r in rows[:limit]]
        return groups, has_more

    def get_member_uids(self, gid: int) -> list:
        rows = self.query(
            "SELECT uid FROM group_members WHERE gid = ? ORDER BY join_time ASC, uid ASC",
            (gid,),
        )
        return [row[0] for row in rows]

    def get_member_uids_for_sender(self, gid: int, sender_uid: int) -> list:
        """Take one snapshot of authorized recipients; fanout needs no join-time sort."""
        rows = self.query(
            """SELECT target.uid FROM groups g
               JOIN group_members actor ON actor.gid = g.gid AND actor.uid = ?
               JOIN group_members target ON target.gid = g.gid
               WHERE g.gid = ?""",
            (sender_uid, gid),
        )
        return [row[0] for row in rows]

    def get_admin_uids(self, gid: int) -> list:
        rows = self.query(
            "SELECT uid FROM group_members WHERE gid = ? AND role = 1 ORDER BY join_time ASC, uid ASC",
            (gid,),
        )
        return [row[0] for row in rows]

    def get_preview_members(self, gid: int, limit: int = 10) -> list:
        """预展示成员：所有者/管理员优先，返回 [(uid, role)]，最多 limit"""
        rows = self.query(
            """SELECT uid, role FROM group_members WHERE gid = ?
               ORDER BY (CASE role WHEN 2 THEN 0 WHEN 1 THEN 1 ELSE 2 END),
                        join_time ASC, uid ASC
               LIMIT ?""",
            (gid, limit),
        )
        return [(row[0], row[1]) for row in rows]

    def count_members(self, gid: int) -> int:
        rows = self.query(
            "SELECT COUNT(*) FROM group_members WHERE gid = ?",
            (gid,),
        )
        return rows[0][0] if rows else 0

    def is_admin(self, gid: int, uid: int) -> int:
        """0=member or non-member, 1=admin, 2=owner."""
        rows = self.query(
            "SELECT role FROM group_members WHERE gid = ? AND uid = ?",
            (gid, uid),
        )
        return rows[0][0] if rows else 0

    def is_member(self, gid: int, uid: int) -> bool:
        rows = self.query(
            "SELECT 1 FROM group_members WHERE gid = ? AND uid = ?",
            (gid, uid),
        )
        return bool(rows)

    def get_group_settings(self, gid: int) -> dict:
        row = self.query(
            """SELECT gid, creater, groupname, enter_hint, introduction,
                      allow_direct_join, require_review, essence_enabled, public_messages,
                      searchable, join_policy
               FROM groups WHERE gid = ?""",
            (gid,),
        )
        if not row:
            return {}
        r = row[0]
        return {
            "gid": r[0], "creater": r[1], "groupname": r[2],
            "enter_hint": r[3], "introduction": r[4],
            "allow_direct_join": bool(r[5]), "require_review": bool(r[6]),
            "essence_enabled": bool(r[7]) if r[7] is not None else True,
            "public_messages": bool(r[8]) if r[8] is not None else False,
            "searchable": bool(r[9]) if r[9] is not None else True,
            "join_policy": r[10] or DEFAULT_JOIN_POLICY,
        }

    def get_essence_enabled(self, gid: int) -> bool:
        row = self.query("SELECT essence_enabled FROM groups WHERE gid = ?", (gid,))
        if not row:
            return True
        val = row[0][0]
        return bool(val) if val is not None else True

    def get_user_group_rows(self, uid: int) -> list:
        rows = self.query(
            """SELECT g.* FROM groups g
               INNER JOIN group_members gm ON gm.gid = g.gid
               WHERE gm.uid = ? ORDER BY g.gid ASC""",
            (uid,),
        )
        return self._hydrate_group_rows(rows)

    def get_user_groups(self, uid: int) -> list:
        return [
            {"gid": row[0], "groupname": row[2]}
            for row in self.get_user_group_rows(uid)
        ]

    def create_group(self, creater: int, groupname: str, enter_hint: str,
                     introduction: str, allow_direct_join=None,
                     require_review=None, join_policy: str = None,
                     searchable: bool = True) -> int:
        cfg = self._config_reader()
        limit = cfg.get("groups_limit", 30)
        if join_policy not in JOIN_POLICIES:
            if allow_direct_join is None and require_review is None:
                join_policy = DEFAULT_JOIN_POLICY
            else:
                join_policy = legacy_policy(
                    bool(allow_direct_join), bool(require_review)
                )
        allow_direct_join, require_review = policy_compat_columns(join_policy)

        with self.lock:
            def operation():
                self.cursor.execute("UPDATE group_id_counter SET next_gid = next_gid + 1 WHERE id = 1")
                self.cursor.execute("SELECT COUNT(*) FROM groups WHERE creater = ?", (creater,))
                if limit != -1 and self.cursor.fetchone()[0] >= limit:
                    self.conn.rollback()
                    return 0
                self.cursor.execute("SELECT next_gid FROM group_id_counter WHERE id = 1")
                gid = self.cursor.fetchone()[0] - 1
                self.cursor.execute(
                    """INSERT INTO groups (gid, creater, groupname,
                       enter_hint, introduction, allow_direct_join, require_review,
                       essence, join_policy, searchable)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (gid, creater, groupname, enter_hint, introduction,
                     int(allow_direct_join), int(require_review), "[]",
                     join_policy, int(bool(searchable))),
                )
                self.cursor.execute(
                    "INSERT INTO group_members (gid, uid, role, join_time) VALUES (?, ?, 2, ?)",
                    (gid, creater, time.time()),
                )
                self.conn.commit()
                return gid

            return self._execute_with_retry(operation)

    def delete_group(self, gid: int):
        with self.lock:
            def operation():
                self.cursor.execute("DELETE FROM join_requests WHERE gid = ?", (gid,))
                self.cursor.execute("DELETE FROM group_members WHERE gid = ?", (gid,))
                self.cursor.execute("DELETE FROM groups WHERE gid = ?", (gid,))
                deleted = self.cursor.rowcount > 0
                self.conn.commit()
                return deleted

            return self._execute_with_retry(operation)

    def add_member(self, gid: int, new_member: int) -> bool:
        cfg = self._config_reader()
        limit = cfg.get("single_group_max_people", 200)
        with self.lock:
            def operation():
                self.cursor.execute("SELECT 1 FROM groups WHERE gid = ?", (gid,))
                if self.cursor.fetchone() is None:
                    self.conn.commit()
                    return False
                self.cursor.execute(
                    "SELECT 1 FROM group_members WHERE gid = ? AND uid = ?",
                    (gid, new_member),
                )
                if self.cursor.fetchone() is not None:
                    self.conn.commit()
                    return False
                self.cursor.execute("SELECT COUNT(*) FROM group_members WHERE gid = ?", (gid,))
                if limit != -1 and self.cursor.fetchone()[0] >= limit:
                    self.conn.commit()
                    return False
                self.cursor.execute(
                    "INSERT INTO group_members (gid, uid, role, join_time) VALUES (?, ?, 0, ?)",
                    (gid, new_member, time.time()),
                )
                self.conn.commit()
                return True

            return self._execute_with_retry(operation)

    def remove_member(self, gid: int, member: int) -> bool:
        with self.lock:
            def operation():
                self.cursor.execute(
                    "DELETE FROM group_members WHERE gid = ? AND uid = ? AND role < 2",
                    (gid, member),
                )
                removed = self.cursor.rowcount > 0
                self.conn.commit()
                return removed

            return self._execute_with_retry(operation)

    def add_admin(self, gid: int, uid: int) -> bool:
        with self.lock:
            def operation():
                self.cursor.execute(
                    "UPDATE group_members SET role = 1 WHERE gid = ? AND uid = ? AND role = 0",
                    (gid, uid),
                )
                changed = self.cursor.rowcount > 0
                self.conn.commit()
                return changed

            return self._execute_with_retry(operation)

    def remove_admin(self, gid: int, uid: int) -> bool:
        with self.lock:
            def operation():
                self.cursor.execute(
                    "UPDATE group_members SET role = 0 WHERE gid = ? AND uid = ? AND role = 1",
                    (gid, uid),
                )
                changed = self.cursor.rowcount > 0
                self.conn.commit()
                return changed

            return self._execute_with_retry(operation)

    def transfer_owner(self, gid: int, old_owner: int, new_owner: int) -> bool:
        with self.lock:
            def operation():
                self.cursor.execute("SELECT creater FROM groups WHERE gid = ?", (gid,))
                group = self.cursor.fetchone()
                if not group or group[0] != old_owner:
                    self.conn.commit()
                    return False
                self.cursor.execute(
                    "SELECT role FROM group_members WHERE gid = ? AND uid = ?",
                    (gid, new_owner),
                )
                if self.cursor.fetchone() is None:
                    self.conn.commit()
                    return False
                self.cursor.execute(
                    "UPDATE group_members SET role = 1 WHERE gid = ? AND uid = ?",
                    (gid, old_owner),
                )
                self.cursor.execute(
                    "UPDATE group_members SET role = 2 WHERE gid = ? AND uid = ?",
                    (gid, new_owner),
                )
                self.cursor.execute("UPDATE groups SET creater = ? WHERE gid = ?", (new_owner, gid))
                self.conn.commit()
                return True

            return self._execute_with_retry(operation)

    def update_settings(self, gid: int, **kwargs) -> bool:
        allowed = {"groupname", "enter_hint", "introduction",
                   "allow_direct_join", "require_review", "essence_enabled",
                   "public_messages", "searchable", "join_policy"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        if "join_policy" in updates:
            policy = updates["join_policy"]
            if policy not in JOIN_POLICIES:
                return False
            allow, review = policy_compat_columns(policy)
            updates["allow_direct_join"] = allow
            updates["require_review"] = review
        if "allow_direct_join" in updates:
            updates["allow_direct_join"] = int(updates["allow_direct_join"])
        if "require_review" in updates:
            updates["require_review"] = int(updates["require_review"])
        if "essence_enabled" in updates:
            updates["essence_enabled"] = int(updates["essence_enabled"])
        if "public_messages" in updates:
            updates["public_messages"] = int(updates["public_messages"])
        if "searchable" in updates:
            updates["searchable"] = int(updates["searchable"])
        set_clause = ", ".join("{} = ?".format(k) for k in updates)
        self.execute(
            "UPDATE groups SET {} WHERE gid = ?".format(set_clause),
            tuple(updates.values()) + (gid,),
        )
        return True

    def request_join(self, gid: int, uid: int, inviter_uid: int = 0,
                     message: str = '') -> int:
        """创建入群申请；已有 pending 时只更新最新留言与时间（保留原 rid，不新增行）。"""
        with self.lock:
            def operation():
                self.cursor.execute(
                    "SELECT rid FROM join_requests WHERE gid = ? AND uid = ? AND status = 'pending'",
                    (gid, uid),
                )
                existing = self.cursor.fetchone()
                if existing:
                    self.cursor.execute(
                        "UPDATE join_requests SET message = ?, request_time = ? WHERE rid = ?",
                        (message, time.time(), existing[0]),
                    )
                    self.conn.commit()
                    return existing[0]
                self.cursor.execute(
                    """INSERT INTO join_requests (gid, uid, inviter_uid, status, request_time, message)
                       VALUES (?, ?, ?, 'pending', ?, ?)""",
                    (gid, uid, inviter_uid, time.time(), message),
                )
                rid = self.cursor.lastrowid
                self.conn.commit()
                return rid

            return self._execute_with_retry(operation)

    def get_join_requests(self, gid: int, status: str = 'pending') -> list:
        rows = self.query(
            """SELECT rid, gid, uid, inviter_uid, status, request_time, message
               FROM join_requests WHERE gid = ? AND status = ? ORDER BY request_time DESC""",
            (gid, status),
        )
        return [
            {"rid": r[0], "gid": r[1], "uid": r[2], "inviter_uid": r[3],
             "status": r[4], "request_time": r[5], "message": r[6] or ""}
            for r in rows
        ]

    def handle_join_request(self, rid: int, approved: bool) -> bool:
        cfg = self._config_reader()
        limit = cfg.get("single_group_max_people", 200)
        with self.lock:
            def operation():
                self.cursor.execute(
                    "SELECT gid, uid, status FROM join_requests WHERE rid = ?",
                    (rid,),
                )
                request = self.cursor.fetchone()
                if not request or request[2] != 'pending':
                    self.conn.commit()
                    return False
                gid, uid = request[0], request[1]
                if not approved:
                    self.cursor.execute(
                        "UPDATE join_requests SET status = 'rejected' WHERE rid = ?",
                        (rid,),
                    )
                    self.conn.commit()
                    return True

                self.cursor.execute("SELECT 1 FROM groups WHERE gid = ?", (gid,))
                if self.cursor.fetchone() is None:
                    self.conn.commit()
                    return False
                self.cursor.execute(
                    "SELECT 1 FROM group_members WHERE gid = ? AND uid = ?",
                    (gid, uid),
                )
                if self.cursor.fetchone() is not None:
                    self.conn.commit()
                    return False
                self.cursor.execute("SELECT COUNT(*) FROM group_members WHERE gid = ?", (gid,))
                if limit != -1 and self.cursor.fetchone()[0] >= limit:
                    self.conn.commit()
                    return False
                self.cursor.execute(
                    "INSERT INTO group_members (gid, uid, role, join_time) VALUES (?, ?, 0, ?)",
                    (gid, uid, time.time()),
                )
                self.cursor.execute(
                    "UPDATE join_requests SET status = 'approved' WHERE rid = ?",
                    (rid,),
                )
                self.conn.commit()
                return True

            return self._execute_with_retry(operation)

    def remove_user_membership(self, uid: int):
        with self.lock:
            def operation():
                self.cursor.execute("SELECT gid FROM groups WHERE creater = ?", (uid,))
                deleted_gids = [row[0] for row in self.cursor.fetchall()]
                for gid in deleted_gids:
                    self.cursor.execute("DELETE FROM join_requests WHERE gid = ?", (gid,))
                    self.cursor.execute("DELETE FROM group_members WHERE gid = ?", (gid,))
                    self.cursor.execute("DELETE FROM groups WHERE gid = ?", (gid,))
                self.cursor.execute(
                    "DELETE FROM join_requests WHERE uid = ? OR inviter_uid = ?",
                    (uid, uid),
                )
                self.cursor.execute("DELETE FROM group_members WHERE uid = ?", (uid,))
                self.conn.commit()
                return deleted_gids

            return self._execute_with_retry(operation)
