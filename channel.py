import websockets
import contextvars
import functools
from websockets.asyncio.server import ServerConnection
from websockets.exceptions import InvalidMessage
import time
import db
import json
import crypto
import asyncio
import base64
import os
import threading
import logging
import math
from collections import defaultdict, deque
from mention_utils import resolve_mentioned_uids, should_alert, alert_from_preference
from config_utils import get_features
import jwt_tool
import jwt_keys

async def to_thread(func, *args, **kwargs):
    loop = asyncio.get_running_loop()
    ctx = contextvars.copy_context()
    func_call = functools.partial(ctx.run, func, *args, **kwargs)
    return await loop.run_in_executor(None, func_call)


class _InvalidHandshakeFilter(logging.Filter):
    def filter(self, record):
        exception = record.exc_info[1] if record.exc_info else None
        return not (
            record.getMessage() == "opening handshake failed"
            and isinstance(exception, InvalidMessage)
        )


def _metadata_with_name(metadata, file_name):
    if not metadata or not file_name:
        return metadata
    result = dict(metadata)
    result["file_name"] = file_name
    result["filename"] = file_name
    result.pop("mime_type", None)
    result["file_type"] = result.get("file_type") or "unknown"
    result["extension"] = os.path.splitext(file_name)[1].lower()
    return result


def _parse_room_target(room_id):
    if not isinstance(room_id, str) or room_id[:1] not in ("U", "G"):
        return None
    try:
        target_id = int(room_id[1:])
    except ValueError:
        return None
    if not 0 <= target_id < 2**63:
        return None
    return room_id[0], target_id


def can_access_room(user_cursor, group_cursor, uid: int, room_id: str) -> bool:
    target = _parse_room_target(room_id)
    if target is None:
        return False
    kind, target_id = target
    if kind == 'U':
        return user_cursor.is_friend(uid, target_id)
    return group_cursor.is_member(target_id, uid)


def _parse_quote(content):
    raw_quote = content.get("quote", -1)
    if isinstance(raw_quote, bool) or not isinstance(raw_quote, (int, str)):
        return None
    try:
        quote = int(raw_quote)
    except ValueError:
        return None
    return quote if -1 <= quote < 2**63 else None

def content_block(punishments_cursor, uid: int, user_stat):
    """内容写 WS（ban you!）
    """
    if user_stat == "pending":
        return "pending_activation"
    if user_stat == "banned":
        return "account_banned"
    if punishments_cursor is None:
        return None
    active = punishments_cursor.active_restriction(uid)
    if active is None:
        return None
    kind = active[2]
    if kind == "ban_full":
        # 完全封禁
        return "account_banned"
    if kind == "ban":
        # 只读封禁
        return "account_readonly"
    if kind == "mute":
        return "account_muted"
    return None


def _encode_frame(message):
    # backslashreplace preserves lone UTF-16 surrogates accepted by JSON decoders.
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8", errors="backslashreplace")


class _Outbox:
    """One ordered, bounded backlog shared by producer threads and one WS writer."""

    def __init__(self, websocket, item_limit, byte_limit):
        self.websocket = websocket
        self.item_limit = item_limit
        self.byte_limit = byte_limit
        self.frames = deque()
        self.queued_bytes = 0
        self.ready = asyncio.Event()
        self.waiting = False
        self.closed = False
        self.lock = threading.Lock()

    def put(self, frame):
        """Return the loop action needed for this transition, if any."""
        with self.lock:
            if self.closed:
                return None
            # An otherwise idle connection can still deliver one large legacy frame.
            if len(self.frames) >= self.item_limit or (
                    self.frames and self.queued_bytes + len(frame) > self.byte_limit):
                self.closed = True
                self.frames.clear()
                self.queued_bytes = 0
                return "close"
            self.frames.append(frame)
            self.queued_bytes += len(frame)
            if self.waiting:
                self.waiting = False
                return "wake"
        return None

    def stop(self):
        with self.lock:
            self.closed = True
            self.frames.clear()
            self.queued_bytes = 0

    async def get(self):
        while True:
            with self.lock:
                if self.frames:
                    frame = self.frames.popleft()
                    self.queued_bytes -= len(frame)
                    return frame
                if self.closed:
                    return None
                self.ready.clear()
                self.waiting = True
            await self.ready.wait()


class InstantConnect():
    # 单个连接队列上限
    SEND_QUEUE_LIMIT = 256
    SEND_QUEUE_BYTES = 2 * 1024 * 1024

    def __init__(self, port_api, port_tcp, notification_cursor, user_cursor, messages_cursor,
                 group_cursor, file_cursor=None, jwt_secret=None, jwt_key_store=None,
                 punishments_cursor=None):
        self.port_api = port_api
        self.port_tcp = port_tcp
        self.notification_cursor = notification_cursor
        self.connected_clients = dict()
        self.connected_clients[-1] = set()
        self.clients_belonged = dict()
        self.clients_token = dict()
        self.clients_session = dict()
        self.send_queue = dict()
        self.user_cursor = user_cursor
        self.group_cursor = group_cursor
        self.messages_cursor = messages_cursor
        self.file_cursor = file_cursor
        self.punishments_cursor = punishments_cursor
        self.jwt_secret = jwt_tool.load_secret(port_api) if jwt_secret is None else jwt_secret
        self.jwt_key_store = (
            jwt_keys.KeyStore("res/{}/secret".format(port_api))
            if jwt_key_store is None else jwt_key_store
        )
        self.legacy_auth_enabled = True
        self.external_issuers = []
        self._load_config()
        self.aes_key = dict()
        self.pri_key = crypto.load_pri("res/{}/secret/pri.pem".format(port_api))
        self.loop = None
        self._ws_lock = threading.Lock()
        self._ws_timestamps = defaultdict(deque)
        self._ws_typing_timestamps = defaultdict(deque)
        self._ws_read_timestamps = defaultdict(deque)
        self._read_receipt_window = 1.5
        self._read_receipt_last = dict()
        self._read_receipt_pending = dict()
        self._read_receipt_timers = dict()
        self._read_receipt_lock = threading.Lock()
        self._presence_grace = 5.0
        self._presence_state = dict()
        self._presence_timers = dict()
        # 扇出失败（DB 抖动）后的补发：uid -> (on/offline, 已尝试次数)
        self._presence_retry = dict()
        self._presence_retry_timers = dict()
        self._presence_retry_delay = 10.0
        self._presence_retry_limit = 3
        self._presence_lock = threading.Lock()
        self._clients_lock = threading.Lock()
        self._auth_revision = 0
        # 每连接最近一次上行帧时间
        self._client_last_inbound = dict()
        self._reconcile_interval = 300.0
        self._last_presence_reconcile = 0.0
        self._auth_lock = threading.Lock()
        self._auth_timestamps = defaultdict(deque)
        self._auth_semaphore = asyncio.Semaphore(2)
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        def _loop():
            while True:
                time.sleep(300)
                try:
                    self._cleanup_rate_timestamps()
                except Exception:
                    pass
                try:
                    self._cleanup_read_receipts()
                except Exception:
                    pass
                try:
                    self._sweep_idle_connections()
                except Exception as e:
                    print("[WARN] 清理 WS 连接失败: {}".format(e))
                try:
                    self._reconcile_presence()
                except Exception as e:
                    print("[WARN] 在线状态失败: {}".format(e))
        t = threading.Thread(target=_loop, daemon=True, name="tfv5-ws-rate-gc")
        t.start()

    def _touch_client_activity(self, websocket):
        """记录该连接最近一次上行帧时间（仅事件循环线程
        """
        if websocket in self._client_last_inbound:
            self._client_last_inbound[websocket] = time.monotonic()
        else:
            with self._clients_lock:
                if websocket in self.clients_belonged:
                    self._client_last_inbound[websocket] = time.monotonic()

    def _sweep_idle_connections(self):
        """关闭长时间没有任何上行数据的已登录连接
        """
        if self.loop is None or self._ws_idle_limit <= 0:
            return
        cutoff = time.monotonic() - self._ws_idle_limit
        with self._clients_lock:
            stale = [
                (websocket, ts) for websocket, ts in self._client_last_inbound.items()
                if ts < cutoff and self.clients_belonged.get(websocket, -1) != -1
            ]
        for websocket, observed_activity in stale:
            asyncio.run_coroutine_threadsafe(
                self._close_idle_connection(websocket, observed_activity), self.loop)

    async def _close_idle_connection(self, websocket, observed_activity):
        with self._clients_lock:
            if self._client_last_inbound.get(websocket) != observed_activity:
                return
            idle_limit = self._ws_idle_limit
            if idle_limit <= 0 or time.monotonic() - observed_activity < idle_limit:
                return
            uid = self.clients_belonged.get(websocket)
        print("[INFO] WS 连接 {}s 无上行数据，主动断开(uid={})".format(
            int(idle_limit), uid))
        await websocket.close(code=1001)

    def _reconcile_presence(self):
        """周期性对齐"""
        if self.loop is None or not self._presence_enabled():
            return
        now = time.monotonic()
        if now - self._last_presence_reconcile < self._reconcile_interval:
            return
        self._last_presence_reconcile = now

        with self._presence_lock:
            flagged = [uid for uid, flag in self._presence_state.items() if flag]
        for uid in flagged:
            if self.filter_online([uid]):
                continue
            targets = self._presence_targets(uid)
            if targets is None:
                continue
            if self._deliver_offline(uid, targets):
                print("[INFO] 在线状态：uid={} 已无连接，设置 offline".format(uid))

        with self._clients_lock:
            connected = [
                uid for uid, wss in self.connected_clients.items()
                if uid != -1 and wss
            ]
        for uid in connected:
            if self._presence_state.get(uid):
                continue
            try:
                self._mark_online(uid)
            except Exception:
                pass

    def _cleanup_read_receipts(self):
        """回收已读回执节流状态：(读取者, 房间) 键随私聊对象/会话数无上限增长。

        时间戳用 time.monotonic()（与 _read_receipt_last 同源），阈值远大于
        合并窗口，不会误删仍在节流中的键。
        """
        cutoff = time.monotonic() - max(self._read_receipt_window * 8, 120.0)
        with self._read_receipt_lock:
            for key in [k for k, (ts, _) in self._read_receipt_last.items() if ts < cutoff]:
                del self._read_receipt_last[key]
            # 定时器仍在的键由 _fire 收尾；没有定时器又没有时间戳的是卡死的残留
            for key in [k for k in self._read_receipt_pending
                        if k not in self._read_receipt_timers
                        and k not in self._read_receipt_last]:
                del self._read_receipt_pending[key]

    def _cleanup_rate_timestamps(self):
        cutoff = time.monotonic() - 120
        with self._ws_lock:
            for d in (self._ws_timestamps, self._ws_typing_timestamps,
                      self._ws_read_timestamps):
                expired = [k for k, v in d.items() if not v or v[-1] < cutoff]
                for k in expired:
                    del d[k]
        with self._auth_lock:
            expired = [k for k, v in self._auth_timestamps.items() if not v or v[-1] < cutoff]
            for k in expired:
                del self._auth_timestamps[k]

    def _check_ws_auth_rate(self, remote_address, limit: int = 5, window: float = 60.0) -> bool:
        ip = remote_address[0] if isinstance(remote_address, tuple) else str(remote_address)
        with self._auth_lock:
            return self._take_rate_slot(self._auth_timestamps[ip], limit, window)

    @staticmethod
    def _take_rate_slot(timestamps, limit, window):
        now = time.monotonic()
        cutoff = now - window
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        if len(timestamps) >= limit:
            return False
        timestamps.append(now)
        return True

    async def _auth_work(self, func, *args, timeout=10.0):
        """Keep the permit until the actual worker exits, even after a disconnected caller."""
        def worker_done(task):
            self._auth_semaphore.release()
            if not task.cancelled():
                task.exception()

        async def run():
            await self._auth_semaphore.acquire()
            worker = asyncio.create_task(to_thread(func, *args))
            worker.add_done_callback(worker_done)
            return await asyncio.shield(worker)

        return await asyncio.wait_for(run(), timeout=timeout)

    def _allows_login(self, uid, status):
        return (status not in ("pending", "banned") and
                (self.punishments_cursor is None or self.punishments_cursor.active_ban(uid) is None))

    def _verify_ws_password(self, uid, password):
        if not self.legacy_auth_enabled or not self.user_cursor.verify_user(uid, password):
            return None
        rows = self.user_cursor.uid_query(uid)
        if not rows or not self._allows_login(uid, rows[0][4]):
            return None
        return uid, None, None, None, None

    def _verify_ws_token(self, token: str):
        """
        校验词元（bushi）
        返回 (uid, jti, sid, auth_version, exp) 或 None。
        """
        def _check():
            # 本服签发 token：HS* 用 jwt_secret，非对称用密钥环（按 kid 选钥）
            payload = jwt_tool.verify_local_token(
                self.jwt_secret, token, self.jwt_key_store
            )
            if payload is not None:
                try:
                    uid = int(payload.get("sub"))
                except (TypeError, ValueError):
                    return None
                jti = payload.get("jti")
                sid = payload.get("sid")
                if not sid:
                    return None
                row = self.user_cursor.resolve_session_identity(uid, jti, sid)
                if row is None or not self._allows_login(uid, row[0]):
                    return None
                if int(row[1]) != int(payload.get("av", -1)):
                    return None
                return (uid, jti, sid, int(row[1]), payload.get("exp"))

            # 外部签发 token：与 HTTP 旧版直接接受路径保持一致（sub 必须是本地 uid 且 av 匹配）。
            # 推荐仍先走 /auth/external/login 换成本地会话 token 再连 WS。
            if not self.external_issuers:
                return None
            payload = jwt_tool.verify_external_token(token, self.external_issuers)
            if payload is None:
                return None
            try:
                uid = int(payload.get("sub"))
            except (TypeError, ValueError):
                return None
            rows = self.user_cursor.uid_query(uid)
            if not rows or not self._allows_login(uid, rows[0][4]):
                return None
            auth_version = self.user_cursor.get_auth_version(uid)
            if int(payload.get("av", -1)) != int(auth_version):
                return None
            return (uid, payload.get("jti"), payload.get("sid"), int(auth_version), payload.get("exp"))
        return self._auth_work(_check)

    def _check_ws_rate(self, uid: int, max_per_second: int = 10, bucket: str = "msg") -> bool:
        buckets = (self._ws_typing_timestamps if bucket == "typing"
                   else self._ws_read_timestamps if bucket == "read" else self._ws_timestamps)
        with self._ws_lock:
            return self._take_rate_slot(buckets[uid], max_per_second, 1.0)

    def _load_config(self, cfg=None):
        if cfg is None:
            cfg_path = os.path.join("res", str(self.port_api), "config.json")
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            except Exception:
                cfg = {}
        self.max_message_length = cfg.get("max_message_length", 10000)
        self.legacy_auth_enabled = bool(cfg.get("legacy_auth_enabled", True))
        raw_issuers = cfg.get("jwt_external_issuers")
        self.external_issuers = raw_issuers if isinstance(raw_issuers, list) else []
        try:
            idle = float(cfg.get("ws_idle_timeout", 300))
        except (TypeError, ValueError):
            idle = 300.0
        self._ws_idle_limit = max(idle, 0.0) if math.isfinite(idle) else 300.0
        self.features = get_features(cfg)
        rtc_cfg = cfg.get("rtc", {})
        self.rtc_turn_enabled = bool(rtc_cfg.get("turn_enabled", False)) if isinstance(rtc_cfg, dict) else False
        self.rtc_ice_servers = rtc_cfg.get("ice_servers", []) if isinstance(rtc_cfg, dict) else []

    def refresh_config(self) -> bool:
        """重新从磁盘加载配置，返回是否成功
        """
        cfg_path = os.path.join("res", str(self.port_api), "config.json")
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            print("[WARN] 重新加载配置失败，保留原值: {}".format(e))
            return False
        self._load_config(cfg)
        return True

    def encrypt_response(self, req : dict, websocket):
        return self._encrypt_frame(_encode_frame(req), websocket).decode("ascii")

    def _encrypt_frame(self, frame, websocket):
        iv, content = crypto.aes_encrypt(frame, self.aes_key[websocket])
        # Both values are base64 and need no further JSON escaping.
        return b"".join((b'{"iv":"', base64.b64encode(iv), b'","content":"',
                         base64.b64encode(content), b'"}'))

    def _group_recipients(self, gid, uid):
        members = self.group_cursor.get_member_uids_for_sender(gid, uid)
        if members:
            return members, None
        exists = self.group_cursor.get_group_settings(gid)
        return [], "not_group_member" if exists else "group_not_found"

    def _verify_quote(self, quote_mid: int, kind: str, target_id: int, sender_uid: int) -> bool:
        if kind == 'G':
            return (self.group_cursor.is_member(target_id, sender_uid)
                    and self.messages_cursor.verify_quote(quote_mid, group_id=target_id))
        return self.messages_cursor.verify_quote(quote_mid, sender_uid, target_id)

    def _cleanup_client(self, websocket):
        last_uid = None
        with self._clients_lock:
            uid = self.clients_belonged.pop(websocket, -1)
            self.clients_token.pop(websocket, None)
            self.clients_session.pop(websocket, None)
            self._client_last_inbound.pop(websocket, None)
            if uid in self.connected_clients and websocket in self.connected_clients[uid]:
                self.connected_clients[uid].remove(websocket)
                if uid != -1 and not self.connected_clients[uid]:
                    del self.connected_clients[uid]
                    last_uid = uid
            elif websocket in self.connected_clients[-1]:
                self.connected_clients[-1].remove(websocket)
            outbox = self.send_queue.pop(websocket, None)
            if outbox is not None:
                outbox.stop()
            self.aes_key.pop(websocket, None)
        # 最后一个连接掉线时启动下线宽限（不在此加锁块内，避免与 filter_online 死锁）
        if last_uid is not None:
            self._schedule_offline(last_uid)
        return last_uid

    def _outboxes_by_uid(self, uids, exclude_websocket=None):
        with self._clients_lock:
            return {
                uid: [self.send_queue[ws] for ws in sockets if ws is not exclude_websocket]
                for uid in uids if (sockets := self.connected_clients.get(uid)) and uid != -1
            }

    @staticmethod
    async def _close_slow(websocket):
        try:
            await websocket.close(code=1013)
        except Exception:
            pass

    def _wake_senders(self, wake, close, offset=0):
        # Leave room for other ready sockets and timers on very large broadcasts.
        end = offset + 256
        for outbox in wake[offset:end]:
            outbox.ready.set()
        for outbox in close[offset:end]:
            self.loop.create_task(self._close_slow(outbox.websocket))
        if end < len(wake) or end < len(close):
            self.loop.call_soon(self._wake_senders, wake, close, end)

    def _dispatch(self, groups):
        """Admit frames before scheduling loop work, including for HTTP producers."""
        if self.loop is None:
            return
        wake, close = [], []
        try:
            for outboxes, message in groups:
                if not outboxes:
                    continue
                frame = _encode_frame(message)
                for outbox in outboxes:
                    action = outbox.put(frame)
                    if action == "wake":
                        wake.append(outbox)
                    elif action == "close":
                        close.append(outbox)
        finally:
            if wake or close:
                self.loop.call_soon_threadsafe(self._wake_senders, wake, close)

    def _queue_message(self, websocket, message):
        with self._clients_lock:
            outbox = self.send_queue.get(websocket)
        if outbox is not None:
            self._dispatch([([outbox], message)])

    def _broadcast_raw(self, uids, message, exclude_websocket=None):
        recipients = self._outboxes_by_uid(uids, exclude_websocket)
        if recipients:
            outboxes = [box for boxes in recipients.values() for box in boxes]
            self._dispatch([(outboxes, message)])

    def _queue_ack(self, websocket, client_mid=None, status="sent", mid=None, error=None):
        if client_mid is None or self.loop is None:
            return
        ack = {"type": "message.ack", "client_mid": client_mid, "status": status}
        if mid is not None:
            ack["mid"] = mid
        if error is not None:
            ack["error"] = error
        self._queue_message(websocket, ack)

    def _deliver_notification(self, uid : int, record : dict,
                              event_type : str = "NOTIFICATION.NEW"):
        self.push_raw(uid, {"type" : event_type, "notification" : record})

    @staticmethod
    def _ephemeral_record(notification : dict, time_stamp : float) -> dict:
        """瞬时通知推送记录"""
        return {
            "id" : -1,
            "time_stamp" : time_stamp,
            "read_at" : None,
            "info" : notification
        }

    def notify_user(self, uid : int, notification : dict, ephemeral : bool = False):
        """推送系统事件通知

        消息事件不再使用，请使用 push_message / push_messages

        ephemeral=True 时只做实时推送
        """
        notification = dict(notification)
        if ephemeral:
            record = self._ephemeral_record(notification, time.time())
            self._deliver_notification(uid, record, "NOTIFICATION.EPHEMERAL")
            return record
        stored = self.notification_cursor.add_event(uid, notification)
        record = {
            "id" : stored["id"],
            "time_stamp" : stored["time_stamp"],
            "read_at" : None,
            "info" : notification
        }
        self.push_raw(uid, {"type": "NOTIFICATION.NEW", "notification": record})
        return record

    def notify_users(self, uid_notifications, ephemeral : bool = False) -> list:
        """批量写入系统事件通知并推送给各自已连接的客户端

        :param uid_notifications: [(uid, notification), ...]
        :param ephemeral: 只推送
        :return: [{id, time_stamp, read_at, info}, ...]
        """
        if not uid_notifications:
            return []
        prepared = [(int(uid), dict(notification)) for uid, notification in uid_notifications]
        if ephemeral:
            now = time.time()
            records = []
            for index, (uid, notification) in enumerate(prepared):
                record = self._ephemeral_record(notification, now + index * 1e-6)
                records.append(record)
                self._deliver_notification(uid, record, "NOTIFICATION.EPHEMERAL")
            return records
        stored = self.notification_cursor.add_events(prepared)
        targets = self._outboxes_by_uid(uid for uid, _ in prepared)
        records = []
        groups = []
        for (uid, notification), meta in zip(prepared, stored):
            record = {
                "id": meta["id"],
                "time_stamp": meta["time_stamp"],
                "read_at": None,
                "info": notification,
            }
            records.append(record)
            if uid in targets:
                groups.append((targets[uid], {"type": "NOTIFICATION.NEW", "notification": record}))
        self._dispatch(groups)
        return records

    def push_message(self, uid : int, message : dict):
        """实时推送消息事件（MESSAGE.NEW）
        不写入 notifications
        """
        self.push_raw(uid, {"type": "MESSAGE.NEW", "message": message})
        return message

    def push_raw(self, uid : int, message : dict, exclude_websocket=None):
        """按原样中继一条信令/消息给某用户的所有在线连接。"""
        self._broadcast_raw((uid,), message, exclude_websocket)

    def filter_online(self, uids) -> list:
        """返回给定 uid 集合中当前在线的子集"""
        with self._clients_lock:
            return [int(uid) for uid in set(uids) if self.connected_clients.get(int(uid))]

    def _presence_enabled(self) -> bool:
        return bool(self.features.get("presence", True))

    def _user_shows_presence(self, uid):
        """用户是否允许向好友展示在线状态（默认展示）
        """
        try:
            flags = self.user_cursor.get_show_status_flags([uid])
        except Exception as e:
            print("[WARN] 读取在线状态开关失败(uid={}): {}".format(uid, e))
            return None
        info = flags.get(int(uid))
        if info is None:
            return False
        return bool(info.get("show_online_status", True))

    def _presence_targets(self, uid):
        """这次上下线事件推给
        """
        if self.loop is None or not self._presence_enabled():
            return []
        shows = self._user_shows_presence(uid)
        if shows is None:
            return None
        if not shows:
            return []
        try:
            friends = self.user_cursor.list_friend_uids(uid)
        except Exception as e:
            print("[WARN] 读取好友列表失败(uid={}): {}".format(uid, e))
            return None
        return self.filter_online(friends)

    def _push_presence(self, uid, online, targets):
        """把上下线事件推给 targets"""
        if not targets:
            return
        payload = {
            "type": "presence.update",
            "uid": uid,
            "status": "online" if online else "offline",
            "ts": int(time.time() * 1000),
        }
        self._broadcast_raw(targets, payload)

    def _deliver_offline(self, uid, targets):
        """复查仍在离线并广播 offline（判定与广播原子
        """
        with self._presence_lock:
            with self._clients_lock:
                still_online = bool(self.connected_clients.get(uid))
            if still_online:
                return False
            self._presence_state.pop(uid, None)
            self._push_presence(uid, False, targets)
        return True

    def _queue_presence_retry(self, uid, online):
        if self.loop is None or not self._presence_enabled():
            return
        with self._presence_lock:
            attempts = self._presence_retry.get(uid, (online, 0))[1] + 1
            if attempts > self._presence_retry_limit:
                self._presence_retry.pop(uid, None)
                print("[WARN] 在线状态扇出重试 {} 次仍失败，放弃(uid={})".format(
                    self._presence_retry_limit, uid))
                return
            self._presence_retry[uid] = (online, attempts)
            if uid in self._presence_retry_timers:
                return
            timer = threading.Timer(
                self._presence_retry_delay, self._fire_presence_retry, (uid,))
            timer.daemon = True
            self._presence_retry_timers[uid] = timer
            timer.start()

    def _fire_presence_retry(self, uid):
        with self._presence_lock:
            self._presence_retry_timers.pop(uid, None)
            pending = self._presence_retry.get(uid)
        if pending is None:
            return
        online = pending[0]
        if bool(self.filter_online([uid])) != online:
            with self._presence_lock:
                self._presence_retry.pop(uid, None)
            return
        if online:
            if self._fanout_presence(uid, True):
                with self._presence_lock:
                    self._presence_retry.pop(uid, None)
            else:
                self._queue_presence_retry(uid, True)
            return
        targets = self._presence_targets(uid)
        if targets is None:
            self._queue_presence_retry(uid, False)
            return
        self._deliver_offline(uid, targets)
        with self._presence_lock:
            self._presence_retry.pop(uid, None)

    def _fanout_presence(self, uid, online, targets=None):
        if targets is None:
            targets = self._presence_targets(uid)
            if targets is None:
                return False
        self._push_presence(uid, online, targets)
        return True

    def _mark_online(self, uid):
        if not self._presence_enabled():
            return
        needs_offline = False
        with self._presence_lock:
            timer = self._presence_timers.pop(uid, None)
            if timer is not None:
                timer.cancel()
            if self._presence_state.get(uid):
                return
            with self._clients_lock:
                still_connected = bool(self.connected_clients.get(uid))
            if still_connected:
                self._presence_state[uid] = True
            else:
                self._presence_state.pop(uid, None)
                needs_offline = True
        if needs_offline:
            self._schedule_offline(uid)
            return
        if not self._fanout_presence(uid, True):
            self._queue_presence_retry(uid, True)

    def _schedule_offline(self, uid):
        if not self._presence_enabled():
            return
        with self._presence_lock:
            timer = self._presence_timers.pop(uid, None)
            if timer is not None:
                timer.cancel()

            def _fire():
                targets = self._presence_targets(uid)
                with self._presence_lock:
                    self._presence_timers.pop(uid, None)
                if targets is None:
                    self._queue_presence_retry(uid, False)
                    return
                self._deliver_offline(uid, targets)

            timer = threading.Timer(self._presence_grace, _fire)
            timer.daemon = True
            self._presence_timers[uid] = timer
            timer.start()

    def presence_hidden(self, uid):
        """用户关闭在线状态时，向好友 hidden 让在线指示器立即消失。"""
        if self.loop is None or not self._presence_enabled():
            return
        try:
            friends = self.user_cursor.list_friend_uids(uid)
        except Exception as e:
            print("[WARN] 读取好友列表失败(uid={}): {}".format(uid, e))
            return
        targets = self.filter_online(friends)
        if not targets:
            return
        payload = {
            "type": "presence.update",
            "uid": uid,
            "status": "hidden",
            "ts": int(time.time() * 1000),
        }
        self._broadcast_raw(targets, payload)

    def presence_shown(self, uid):
        """用户重新开启在线状态且当前在线时，向好友 online"""
        if self.loop is None or not self._presence_enabled():
            return
        if not self.filter_online([uid]):
            return
        with self._presence_lock:
            self._presence_state[uid] = True
        if not self._fanout_presence(uid, True):
            self._queue_presence_retry(uid, True)

    def emit_private_read_receipt(self, reader_uid, peer_uid, room_key,
                                  last_mid, last_seq):
        """私聊已读回执
        """
        if not self._read_receipt_enabled():
            return
        if not self._user_shows_read_status(reader_uid):
            return
        if not last_seq or last_seq <= 0:
            return
        self._emit_read_receipt(reader_uid, peer_uid, room_key, last_mid, last_seq)

    def _read_receipt_enabled(self) -> bool:
        return bool(self.features.get('chat', {}).get('read_receipt', True))

    def _user_shows_read_status(self, uid) -> bool:
        """用户是否允许向他人展示自己已读"""
        try:
            flags = self.user_cursor.get_show_status_flags([uid])
        except Exception as e:
            print("[WARN] 读取已读展示开关失败(uid={}): {}".format(uid, e))
            return False
        info = flags.get(int(uid))
        return info is not None and bool(info.get('show_read_status', True))

    def _emit_read_receipt(self, reader_uid, peer_uid, room_key, last_mid, last_seq):
        """向私聊对方推送已读回执
        """
        key = (reader_uid, room_key)
        payload = {
            "type": "message.read_receipt",
            "room_id": "U{}".format(reader_uid),
            "uid": reader_uid,
            "last_mid": last_mid,
            "last_seq": last_seq,
            "ts": int(time.time() * 1000),
        }

        def _fire():
            allowed = self._read_receipt_enabled() and self._user_shows_read_status(reader_uid)
            with self._read_receipt_lock:
                if self._read_receipt_timers.get(key) is not timer:
                    return
                self._read_receipt_timers.pop(key, None)
                pending = self._read_receipt_pending.pop(key, None)
                if pending is None or not allowed:
                    return
                target_uid, pending_payload = pending
                self._read_receipt_last[key] = (time.monotonic(), pending_payload["last_seq"])
                self.push_raw(target_uid, pending_payload)

        window = self._read_receipt_window
        with self._read_receipt_lock:
            now = time.monotonic()
            last = self._read_receipt_last.get(key)
            pending = self._read_receipt_pending.get(key)
            if ((last and last_seq <= last[1])
                    or (pending and last_seq <= pending[1]["last_seq"])):
                return
            remaining = window - (now - last[0]) if last else 0
            if remaining <= 0:
                self._read_receipt_last[key] = (now, last_seq)
                old_timer = self._read_receipt_timers.pop(key, None)
                if old_timer is not None:
                    old_timer.cancel()
                self._read_receipt_pending.pop(key, None)
                self.push_raw(peer_uid, payload)
            else:
                self._read_receipt_pending[key] = (peer_uid, payload)
                if key not in self._read_receipt_timers:
                    timer = threading.Timer(remaining, _fire)
                    timer.daemon = True
                    self._read_receipt_timers[key] = timer
                    timer.start()

    def _queue_call_ack(self, websocket, call_id, request, status):
        """针对 call.* 信令的回执（差不多就是 call 专用版 _queue_ack）"""
        if not call_id or self.loop is None:
            return
        ack = {
            "type": "call.ack",
            "call_id": call_id,
            "for": request,
            "status": status,
        }
        self._queue_message(websocket, ack)

    async def _handle_call_message(self, websocket, message : dict):
        """视频通话信令中继
        """
        sender_uid = self.clients_belonged[websocket]
        if not self._check_ws_rate(sender_uid):
            self._queue_call_ack(websocket, message.get('call_id'), message['type'], "rate_limited")
            return
        target_uid = message.get('target_uid')
        call_id = message.get('call_id')
        if isinstance(target_uid, bool) or not isinstance(target_uid, int) or not 0 <= target_uid < 2**63:
            self._queue_call_ack(websocket, call_id, message['type'], "invalid_target")
            return
        if target_uid == sender_uid:
            self._queue_call_ack(websocket, call_id, message['type'], "invalid_target")
            return
        if not isinstance(call_id, str) or not call_id or len(call_id) > 64:
            self._queue_call_ack(websocket, call_id, message['type'], "invalid_call_id")
            return
        if not await to_thread(self.user_cursor.is_friend, sender_uid, target_uid):
            self._queue_call_ack(websocket, call_id, message['type'], "not_friends")
            return

        mtype = message['type']
        relay = {"type": mtype, "call_id": call_id, "from_uid": sender_uid}
        if mtype in ("call.invite", "call.answer"):
            payload = message.get('payload')
            if not isinstance(payload, dict) or not isinstance(payload.get('sdp'), str):
                self._queue_call_ack(websocket, call_id, mtype, "invalid_request")
                return
            candidates = payload.get('candidates')
            if candidates is not None and not isinstance(candidates, list):
                self._queue_call_ack(websocket, call_id, mtype, "invalid_request")
                return
            relay["payload"] = payload
        elif mtype == "call.ice":
            candidate = message.get('candidate')
            if not isinstance(candidate, dict) or not isinstance(candidate.get('candidate'), str):
                self._queue_call_ack(websocket, call_id, mtype, "invalid_request")
                return
            relay["candidate"] = candidate
        elif mtype == "call.hangup":
            reason = message.get('reason')
            if not isinstance(reason, str) or reason not in ("hangup", "decline", "cancel", "busy", "error"):
                self._queue_call_ack(websocket, call_id, mtype, "invalid_request")
                return
            relay["reason"] = reason
        else:
            self._queue_call_ack(websocket, call_id, mtype, "invalid_request")
            return

        online = bool(self.connected_clients.get(target_uid))
        self.push_raw(target_uid, relay)
        self._queue_call_ack(
            websocket, call_id, mtype,
            "delivered" if (online or mtype != "call.invite") else "offline",
        )

    def push_recall(self, uid : int, message : dict):
        """实时推送消息撤回事件（MESSAGE.RECALLED），不写入 notifications"""
        self.push_raw(uid, {"type": "MESSAGE.RECALLED", "message": message})
        return message

    def push_group_recall(self, uids, message):
        self._broadcast_raw(uids, {"type": "MESSAGE.RECALLED", "message": message})

    def push_messages(self, uid_messages) -> list:
        """批量实时推送消息事件（MESSAGE.NEW），不写入 notifications。"""
        if not uid_messages:
            return []
        prepared = [(int(uid), dict(message)) for uid, message in uid_messages]
        targets = self._outboxes_by_uid(uid for uid, _ in prepared)
        self._dispatch((targets[uid], {"type": "MESSAGE.NEW", "message": message})
                       for uid, message in prepared if uid in targets)
        return [message for _, message in prepared]

    def push_group_message(self, members, sender_uid, message, *, respect_preferences=True):
        """Serialize each distinct pair of recipient flags once, across all devices."""
        targets = self._outboxes_by_uid(members)
        if not targets:
            return
        mentioned = set(message["mentioned_uids"])
        preferences = (self.messages_cursor.get_room_preference_map(targets, message["room_id"])
                       if respect_preferences else {})
        variants = defaultdict(list)
        for uid, outboxes in targets.items():
            alert = uid != sender_uid and alert_from_preference(preferences.get(uid), uid, mentioned)
            variants[uid in mentioned, alert].extend(outboxes)
        self._dispatch(
            (boxes, {"type": "MESSAGE.NEW",
                     "message": dict(message, mentions_me=mentions_me, should_alert=alert)})
            for (mentions_me, alert), boxes in variants.items()
        )

    async def _close_revoked_sockets(self, sockets):
        for websocket in sockets:
            self._cleanup_client(websocket)
        await asyncio.gather(*(ws.close() for ws in sockets), return_exceptions=True)

    def _disconnect_matching(self, identities, value):
        with self._clients_lock:
            self._auth_revision += 1
            if identities is self.clients_belonged:
                sockets = list(self.connected_clients.get(value, ()))
            else:
                sockets = [ws for ws, stored in identities.items() if stored == value]
            for websocket in sockets:
                outbox = self.send_queue.get(websocket)
                if outbox is not None:
                    outbox.stop()
        if self.loop is None:
            for websocket in sockets:
                self._cleanup_client(websocket)
        elif sockets:
            asyncio.run_coroutine_threadsafe(self._close_revoked_sockets(sockets), self.loop)

    def disconnect_user(self, uid : int):
        self._disconnect_matching(self.clients_belonged, uid)

    def disconnect_jti(self, jti : str):
        """断开使用指定 token 的连接。"""
        self._disconnect_matching(self.clients_token, jti)

    def disconnect_session(self, session_id : str):
        """断开该会话的所有 WebSocket 连接。"""
        self._disconnect_matching(self.clients_session, session_id)

    async def _register_login(self, websocket, message):
        # A worker can return an old credential result while an HTTP thread revokes it.
        # Check the revision under the same lock used to snapshot revoked connections.
        token = message.get("token")
        target = None if token else _parse_room_target("U{}".format(message.get("uid")))
        while True:
            with self._clients_lock:
                revision = self._auth_revision
            if token:
                identity = await self._verify_ws_token(token)
            elif target is not None and self.legacy_auth_enabled:
                identity = await self._auth_work(self._verify_ws_password, target[1], message["password"])
            else:
                identity = None
            if identity is None:
                raise ValueError("WS authentication failed")
            uid, jti, sid, _auth_version, expires_at = identity
            if expires_at is not None:
                expires_at = int(expires_at)
                if expires_at <= time.time():
                    raise ValueError("Token expired")
            with self._clients_lock:
                if revision != self._auth_revision:
                    continue
                queue = _Outbox(websocket, self.SEND_QUEUE_LIMIT, self.SEND_QUEUE_BYTES)
                self.connected_clients[-1].remove(websocket)
                became_online = not self.connected_clients.get(uid)
                self.connected_clients.setdefault(uid, []).append(websocket)
                self.clients_belonged[websocket] = uid
                self.clients_token[websocket] = jti
                self.clients_session[websocket] = sid
                self._client_last_inbound[websocket] = time.monotonic()
                self.send_queue[websocket] = queue
                return uid, became_online, queue, expires_at

    async def sender(self, websocket, queue):
        try:
            count = 0
            byte_count = 0
            while (frame := await queue.get()) is not None:
                await websocket.send(self._encrypt_frame(frame, websocket), text=True)
                count += 1
                byte_count += len(frame)
                # send() may complete synchronously on a writable socket.
                if count >= 16 or byte_count >= 65536:
                    await asyncio.sleep(0)
                    count = byte_count = 0
        except (asyncio.CancelledError, websockets.exceptions.ConnectionClosed):
            pass
    
    async def handler(self, websocket: ServerConnection):
        with self._clients_lock:
            self.connected_clients[-1].add(websocket)
            self.clients_belonged[websocket] = -1
        try:
            if not self._check_ws_auth_rate(websocket.remote_address):
                raise ValueError("登录请求过于频繁")
            message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            message = json.loads(message)
            if message['type'] != 'REQ.UPDATE_AES_KEY':
                raise ValueError("{} 而非 REQ.UPDATE_AES_KEY".format(message.get('type')))
            wrapped_key = base64.b64decode(message["aes_key"])
            if len(wrapped_key) != (self.pri_key.key_size + 7) // 8:
                raise ValueError("RSA key envelope has the wrong length")
            aes_key = await self._auth_work(crypto.decrypt, self.pri_key, wrapped_key)
            if len(aes_key) not in (16, 24, 32):
                raise ValueError("Invalid AES key length")
            self.aes_key[websocket] = aes_key

        except asyncio.CancelledError:
            self._cleanup_client(websocket)
            raise
        except Exception:
            self._cleanup_client(websocket)
            print("[ERR] 客户端链接 WS 服务器后没有发出 AES 密钥声明")
            return
        
        expiry_task = None
        send_task = None
        expires_at = None
        try:
            message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            message = json.loads(message)
            message = json.loads(crypto.aes_decrypt(base64.b64decode(message['iv']), base64.b64decode(message['content']), self.aes_key[websocket]))
            if message['type'] != 'AUTH.LOGIN':
                raise ValueError("{} 而非 AUTH.LOGIN".format(message.get('type')))
            verified_uid, became_online, queue, expires_at = await asyncio.wait_for(
                self._register_login(websocket, message), timeout=10.0)
            if queue.closed:
                self._cleanup_client(websocket)
                return
            if expires_at is not None:
                expiry_task = asyncio.create_task(self._close_on_expiry(websocket, expires_at))
            await websocket.send(self.encrypt_response({"type" : "AUTH.LOGIN_SUCCEEDED"}, websocket))
            if became_online and self.send_queue.get(websocket) is queue:
                await to_thread(self._mark_online, verified_uid)
            if self.send_queue.get(websocket) is not queue:
                return
            send_task = asyncio.create_task(self.sender(websocket, queue))

        except asyncio.CancelledError:
            self._cleanup_client(websocket)
            raise
        except Exception:
            print("[ERR] 客户端链接 WS 服务器后没有登录")
            return
        finally:
            if send_task is None:
                if expiry_task is not None:
                    expiry_task.cancel()
                self._cleanup_client(websocket)

        try:
            async for message in websocket:
                if queue.closed or (expires_at is not None and time.time() >= expires_at):
                    break
                self._touch_client_activity(websocket)
                message = json.loads(message)
                message = json.loads(crypto.aes_decrypt(base64.b64decode(message['iv']), base64.b64decode(message['content']), self.aes_key[websocket]))
                if not isinstance(message, dict) or not isinstance(message.get("type"), str):
                    continue
                sender_uid = self.clients_belonged[websocket]

                if message['type'] == 'PING':
                    self._queue_message(websocket, {"type": "PONG"})
                    continue

                if message['type'] in ("message.plain", "message.file"):
                    info = await to_thread(self.user_cursor.uid_query, sender_uid)
                    block = await to_thread(
                        content_block, self.punishments_cursor,
                        sender_uid, info[0][4] if info else "unknown")
                    if block is not None:
                        self._queue_ack(websocket, message.get('client_mid'),
                                        status="failed", error=block)
                        # 封禁直接断开；禁言只拒这一条，连接保留
                        if block == "account_banned":
                            break
                        continue

                    if not self._check_ws_rate(sender_uid):
                        self._queue_ack(websocket, message.get('client_mid'), status="failed", error="rate_limited")
                        continue

                    content = message.get('content')
                    client_mid = message.get('client_mid')
                    if (not isinstance(content, dict)
                            or (client_mid is not None and not isinstance(client_mid, str)
                                and (type(client_mid) is not int or not -(2**63) <= client_mid < 2**63))):
                        self._queue_ack(websocket, client_mid, status="failed", error="invalid_request")
                        continue
                    target = _parse_room_target(content.get('send_to'))
                    if target is None:
                        self._queue_ack(websocket, client_mid, status="failed", error="invalid_target")
                        continue
                    target_kind, target_id = target
                    chat_feature = 'group_chat' if target_kind == 'G' else 'private_chat'
                    if not self.features.get('chat', {}).get(chat_feature, True):
                        self._queue_ack(websocket, client_mid, status="failed", error="feature_disabled_" + chat_feature)
                        continue
                    quote = _parse_quote(content)
                    if quote is None:
                        self._queue_ack(websocket, client_mid, status="failed", error="invalid_quote")
                        continue
                    if quote >= 0 and not await to_thread(
                            self._verify_quote, quote, target_kind, target_id, sender_uid):
                        self._queue_ack(websocket, client_mid, status="failed", error="invalid_quote")
                        continue

                if message['type'] == "message.plain":
                    plain = content.get('plain')
                    if not isinstance(plain, str):
                        self._queue_ack(websocket, client_mid, status="failed", error="invalid_request")
                        continue
                    if len(plain) > self.max_message_length:
                        self._queue_ack(websocket, client_mid, status="failed", error="message_too_long")
                        continue
                    if target_kind == 'U':
                        # 发送给用户
                        send_to = target_id
                        sender_uid = self.clients_belonged[websocket]
                        if not await to_thread(self.user_cursor.is_friend, sender_uid, send_to):
                            self._queue_ack(websocket, client_mid, status="failed", error="not_friends")
                            continue
                        mentioned_uids = await to_thread(
                            resolve_mentioned_uids, plain, self.user_cursor, [send_to],
                            exclude_uid=sender_uid,
                        )
                        msg_record = await to_thread(
                            self.messages_cursor.add_message,
                            sender_uid, send_to, plain,
                            content_type='plain', quote=quote,
                            client_mid=client_mid, mentioned_uids=mentioned_uids,
                        )
                        if msg_record.get("duplicate"):
                            if not await to_thread(
                                    self.messages_cursor.request_matches,
                                    msg_record["mid"], sender_uid, send_to, plain, "plain",
                                    quote=quote):
                                self._queue_ack(
                                    websocket, client_mid, status="failed",
                                    error="client_mid_conflict",
                                )
                                continue
                            self._queue_ack(websocket, client_mid, mid=msg_record["mid"], status="sent")
                            continue
                        self._queue_ack(websocket, client_mid, mid=msg_record["mid"], status="sent")
                        sender_str = "U{}".format(sender_uid)
                        recv_notif = {
                            "event" : "message.plain",
                            "title" : str(msg_record["send_time"]),
                            "content" : plain,
                            "sender" : sender_str,
                            "meta" : quote,
                            "mid" : msg_record["mid"],
                            "client_mid" : client_mid,
                            "room_id" : sender_str,
                            "room_seq" : msg_record.get("room_seq")
                        }
                        if quote >= 0:
                            recv_notif["quote_preview"] = await to_thread(
                                self.messages_cursor.get_quote_preview, quote, msg_record)
                        else:
                            recv_notif["quote_preview"] = None
                        recv_notif["mentioned_uids"] = mentioned_uids
                        recv_notif["mentions_me"] = send_to in mentioned_uids
                        recv_notif["should_alert"] = await to_thread(
                            should_alert, self.messages_cursor, send_to, sender_str, mentioned_uids
                        )
                        sender_notif = dict(recv_notif)
                        sender_notif["room_id"] = "U{}".format(send_to)
                        sender_notif["mentions_me"] = False
                        sender_notif["should_alert"] = False
                        self.push_message(send_to, recv_notif)
                        self.push_message(sender_uid, sender_notif)
                        # 发送即已读：这次隐式前进也要告诉对方，否则对方的推送
                        # 通道会停在旧水位（见 emit_private_read_receipt 的注释）。
                        await to_thread(
                            self.emit_private_read_receipt,
                            sender_uid, send_to,
                            self.messages_cursor.room_key_of(sender_uid, send_to),
                            msg_record["mid"], msg_record.get("room_seq") or 0,
                        )

                    else:
                        gid = target_id
                        members, error = await to_thread(self._group_recipients, gid, sender_uid)
                        if error:
                            self._queue_ack(websocket, client_mid, status="failed", error=error)
                            continue
                        sender_str = "G{}U{}".format(gid, sender_uid)
                        mentioned_uids = await to_thread(
                            resolve_mentioned_uids, plain, self.user_cursor, members,
                            exclude_uid=sender_uid,
                        )
                        msg_record = await to_thread(
                            self.messages_cursor.add_message,
                            self.clients_belonged[websocket], 0, plain,
                            content_type='plain', quote=quote, group_id=gid,
                            client_mid=client_mid, mentioned_uids=mentioned_uids,
                        )
                        if msg_record.get("duplicate"):
                            if not await to_thread(
                                    self.messages_cursor.request_matches,
                                    msg_record["mid"], self.clients_belonged[websocket], 0,
                                    plain, "plain", quote=quote, group_id=gid):
                                self._queue_ack(
                                    websocket, client_mid, status="failed",
                                    error="client_mid_conflict",
                                )
                                continue
                            self._queue_ack(websocket, client_mid, mid=msg_record["mid"], status="sent")
                            continue
                        self._queue_ack(websocket, client_mid, mid=msg_record["mid"], status="sent")
                        notif_dict = {
                            "event" : "message.plain",
                            "title" : str(msg_record["send_time"]),
                            "content" : plain,
                            "sender" : sender_str,
                            "meta" : quote,
                            "mid" : msg_record["mid"],
                            "client_mid" : client_mid,
                            "room_id" : "G{}".format(gid),
                            "group_id" : gid,
                            "room_seq" : msg_record.get("room_seq")
                        }
                        if quote >= 0:
                            notif_dict["quote_preview"] = await to_thread(
                                self.messages_cursor.get_quote_preview, quote, msg_record)
                        else:
                            notif_dict["quote_preview"] = None
                        notif_dict["mentioned_uids"] = mentioned_uids
                        try:
                            await to_thread(self.push_group_message, members, sender_uid, notif_dict)
                        except Exception as e:
                            print("[WARN] 批量推送失败(群{}): {}".format(gid, e))

                elif message["type"] == "message.file":
                    file_hashes = content.get('file_hashes')
                    duration = content.get('duration_ms')
                    try:
                        duration = int(duration) if duration is not None else None
                    except (TypeError, ValueError, OverflowError):
                        duration = None
                    if duration is not None and not 0 <= duration < 2**31:
                        duration = None
                    # hyw
                    if not isinstance(file_hashes, str) or len(file_hashes) != 64 or not all(c in '0123456789abcdefABCDEF' for c in file_hashes):
                        self._queue_ack(websocket, client_mid, status="failed", error="invalid_file_hash")
                        continue
                    if target_kind == 'U':
                        # 发送给用户
                        send_to = target_id
                        sender_uid = self.clients_belonged[websocket]
                        if not await to_thread(self.user_cursor.is_friend, sender_uid, send_to):
                            self._queue_ack(websocket, client_mid, status="failed", error="not_friends")
                            continue
                        metadata = (
                            await to_thread(self.file_cursor.acquire_reference,
                                            sender_uid, file_hashes)
                            if self.file_cursor is not None else None)
                        if metadata is None:
                            self._queue_ack(websocket, client_mid, status="failed", error="file_not_owned")
                            continue
                        try:
                            msg_record = await to_thread(
                                self.messages_cursor.add_message,
                                sender_uid, send_to, file_hashes,
                                content_type='file', file_hash=file_hashes, quote=quote,
                                client_mid=client_mid, file_name=metadata["file_name"],
                                duration=duration, add_file_reference=self.file_cursor.add_reference,
                                remove_file_reference=self.file_cursor.remove_reference,
                            )
                        except db.FileReferenceUnavailable:
                            self._queue_ack(websocket, client_mid, status="failed", error="file_reference_failed")
                            continue
                        if msg_record.get("duplicate"):
                            if not await to_thread(
                                    self.messages_cursor.request_matches,
                                    msg_record["mid"], sender_uid, send_to, file_hashes, "file",
                                    file_hash=file_hashes, quote=quote, duration=duration):
                                self._queue_ack(
                                    websocket, client_mid, status="failed",
                                    error="client_mid_conflict",
                                )
                                continue
                            self._queue_ack(websocket, client_mid, mid=msg_record["mid"], status="sent")
                            continue
                        self._queue_ack(websocket, client_mid, mid=msg_record["mid"], status="sent")
                        sender_str = "U{}".format(sender_uid)
                        recv_notif = {
                            "event" : "message.file",
                            "title" : str(msg_record["send_time"]),
                            "content" : file_hashes,
                            "sender" : sender_str,
                            "meta" : {"quote": quote, "avatar_url": "/avatar/get_avatar/user/{}".format(sender_uid)},
                            "quote" : quote,
                            "mid" : msg_record["mid"],
                            "file_hash" : file_hashes,
                            "client_mid" : client_mid,
                            "room_id" : sender_str,
                            "room_seq" : msg_record.get("room_seq")
                        }
                        if quote >= 0:
                            recv_notif["quote_preview"] = await to_thread(
                                self.messages_cursor.get_quote_preview, quote, msg_record)
                        else:
                            recv_notif["quote_preview"] = None
                        if duration is not None:
                            recv_notif["duration"] = duration
                        if self.file_cursor is not None:
                            recv_notif["file"] = _metadata_with_name(
                                await to_thread(
                                    self.file_cursor.get_metadata,
                                    file_hashes, owner_uid=sender_uid),
                                metadata["file_name"],
                            )
                        recv_notif["mentioned_uids"] = []
                        recv_notif["mentions_me"] = False
                        recv_notif["should_alert"] = await to_thread(
                            should_alert, self.messages_cursor, send_to, sender_str, []
                        )
                        sender_notif = dict(recv_notif)
                        sender_notif["room_id"] = "U{}".format(send_to)
                        sender_notif["should_alert"] = False
                        self.push_message(send_to, recv_notif)
                        self.push_message(sender_uid, sender_notif)
                        # 发送即已读：这次隐式前进也要告诉对方，否则对方的推送
                        # 通道会停在旧水位（见 emit_private_read_receipt 的注释）。
                        await to_thread(
                            self.emit_private_read_receipt,
                            sender_uid, send_to,
                            self.messages_cursor.room_key_of(sender_uid, send_to),
                            msg_record["mid"], msg_record.get("room_seq") or 0,
                        )

                    else:
                        gid = target_id
                        members, error = await to_thread(self._group_recipients, gid, sender_uid)
                        if error:
                            self._queue_ack(websocket, client_mid, status="failed", error=error)
                            continue
                        sender_str = "G{}U{}".format(gid, sender_uid)
                        sender_uid = self.clients_belonged[websocket]
                        metadata = (
                            await to_thread(self.file_cursor.acquire_reference,
                                            sender_uid, file_hashes)
                            if self.file_cursor is not None else None)
                        if metadata is None:
                            self._queue_ack(websocket, client_mid, status="failed", error="file_not_owned")
                            continue
                        try:
                            msg_record = await to_thread(
                                self.messages_cursor.add_message,
                                sender_uid, 0, file_hashes,
                                content_type='file', file_hash=file_hashes, quote=quote, group_id=gid,
                                client_mid=client_mid, file_name=metadata["file_name"],
                                duration=duration, add_file_reference=self.file_cursor.add_reference,
                                remove_file_reference=self.file_cursor.remove_reference,
                            )
                        except db.FileReferenceUnavailable:
                            self._queue_ack(websocket, client_mid, status="failed", error="file_reference_failed")
                            continue
                        if msg_record.get("duplicate"):
                            if not await to_thread(
                                    self.messages_cursor.request_matches,
                                    msg_record["mid"], sender_uid, 0, file_hashes, "file",
                                    file_hash=file_hashes, quote=quote, group_id=gid, duration=duration):
                                self._queue_ack(
                                    websocket, client_mid, status="failed",
                                    error="client_mid_conflict",
                                )
                                continue
                            self._queue_ack(websocket, client_mid, mid=msg_record["mid"], status="sent")
                            continue
                        self._queue_ack(websocket, client_mid, mid=msg_record["mid"], status="sent")
                        notif_dict = {
                            "event" : "message.file",
                            "title" : str(msg_record["send_time"]),
                            "content" : file_hashes,
                            "sender" : sender_str,
                            "meta" : {"quote": quote, "avatar_url": "/avatar/get_avatar/user/{}".format(sender_uid)},
                            "quote" : quote,
                            "mid" : msg_record["mid"],
                            "file_hash" : file_hashes,
                            "client_mid" : client_mid,
                            "room_id" : "G{}".format(gid),
                            "group_id" : gid,
                            "room_seq" : msg_record.get("room_seq")
                        }
                        if quote >= 0:
                            notif_dict["quote_preview"] = await to_thread(
                                self.messages_cursor.get_quote_preview, quote, msg_record)
                        else:
                            notif_dict["quote_preview"] = None
                        if duration is not None:
                            notif_dict["duration"] = duration
                        if self.file_cursor is not None:
                            notif_dict["file"] = _metadata_with_name(
                                await to_thread(
                                    self.file_cursor.get_metadata,
                                    file_hashes,
                                    owner_uid=self.clients_belonged[websocket],
                                ),
                                metadata["file_name"],
                            )
                        notif_dict["mentioned_uids"] = []
                        try:
                            await to_thread(self.push_group_message, members, sender_uid, notif_dict)
                        except Exception as e:
                            print("[WARN] 批量推送失败(群{}): {}".format(gid, e))

                elif message["type"] in ("call.invite", "call.answer", "call.ice", "call.hangup"):
                    await self._handle_call_message(websocket, message)

                elif message["type"] in ("typing.start", "typing.stop"):
                    if not self._check_ws_rate(sender_uid, max_per_second=20, bucket="typing"):
                        continue
                    room_id = message.get("room_id")
                    target = _parse_room_target(room_id)
                    if target is None:
                        continue
                    kind, target_id = target
                    # 新增字段：scope（缺省 typing）、progress（仅 uploading）、ts（服务器兜底）
                    scope = message.get("scope", "typing")
                    if scope not in ("typing", "uploading"):
                        continue
                    progress = message.get("progress")
                    if progress is not None:
                        if not isinstance(progress, (int, float)) or not (0 <= progress <= 1):
                            continue
                    ts = message.get("ts")
                    if ts is not None:
                        if not isinstance(ts, (int, float)) or (isinstance(ts, float) and not math.isfinite(ts)):
                            ts = None
                        else:
                            ts = int(ts)
                    if ts is None:
                        ts = int(time.time() * 1000)
                    if kind == 'U':
                        if not await to_thread(self.user_cursor.is_friend, sender_uid, target_id):
                            continue
                        # 私聊：广播给接收方时 room_id 需为接收方视角
                        # 不然就会 BOOM~~
                        # 是的这个 BUG 八百年不能发现
                        broadcast = {
                            "type": message["type"],
                            "room_id": "U{}".format(sender_uid),
                            "uid": sender_uid,
                            "scope": scope,
                            "ts": ts,
                        }
                        if progress is not None:
                            broadcast["progress"] = progress
                        self.push_raw(target_id, broadcast)
                    else:
                        broadcast = {
                            "type": message["type"],
                            "room_id": room_id,
                            "uid": sender_uid,
                            "scope": scope,
                            "ts": ts,
                        }
                        if progress is not None:
                            broadcast["progress"] = progress
                        members = await to_thread(
                            self.group_cursor.get_member_uids_for_sender, target_id, sender_uid)
                        await to_thread(self._broadcast_raw,
                                        (uid for uid in members if uid != sender_uid), broadcast)

                elif message["type"] == "message.read":
                    sender_uid = self.clients_belonged[websocket]
                    if not self._check_ws_rate(sender_uid, max_per_second=5, bucket="read"):
                        continue
                    room_id = message.get("room_id")
                    last_mid = message.get("last_mid")
                    if (not isinstance(room_id, str) or isinstance(last_mid, bool)
                            or not isinstance(last_mid, int) or not 0 < last_mid < 2**63):
                        continue
                    if not await to_thread(
                            can_access_room,
                            self.user_cursor, self.group_cursor, sender_uid, room_id):
                        continue
                    if room_id.startswith('U'):
                        room_key = self.messages_cursor.room_key_of(
                            sender_uid, int(room_id[1:]))
                    else:
                        room_key = self.messages_cursor.room_key_of(
                            sender_uid, 0, group_id=int(room_id[1:]))
                    cursor = await to_thread(
                        self.messages_cursor.sync_cursor_for_mid, room_key, last_mid)
                    if cursor is None or cursor[0] is None:
                        continue
                    if not await to_thread(
                            self.messages_cursor.update_read_state,
                            sender_uid, room_key, cursor[0], last_mid):
                        continue
                    # 多端已读同步
                    self.push_raw(sender_uid, {
                        "type": "message.read",
                        "room_id": room_id,
                        "uid": sender_uid,
                        "last_mid": last_mid,
                        "last_seq": cursor[0],
                        "ts": int(time.time() * 1000),
                    }, exclude_websocket=websocket)
                    # 私聊：把已读水位回执推给对方（内部要读隐私开关 + 推送，
                    # 与其它调用点一致地挪出事件循环线程）
                    if room_id.startswith('U'):
                        await to_thread(
                            self.emit_private_read_receipt,
                            sender_uid, int(room_id[1:]), room_key,
                            last_mid, cursor[0])

        except Exception as e:
            print("[ERR] WS消息处理异常: {}".format(e))

        finally:
            if expiry_task is not None:
                expiry_task.cancel()
            send_task.cancel()
            await asyncio.gather(send_task, return_exceptions=True)
            self._cleanup_client(websocket)
            

    @staticmethod
    async def _close_on_expiry(websocket, expires_at):
        await asyncio.sleep(max(0, expires_at - time.time()))
        await websocket.close(code=1008, reason="Token expired")

    async def main(self):
        print("[INFO] 已严肃启动 TCP 服务器")
        self.loop = asyncio.get_running_loop()
        websocket_logger = logging.getLogger("touchfish.websocket")
        websocket_logger.addFilter(_InvalidHandshakeFilter())
        async with websockets.serve(
            self.handler, "0.0.0.0", self.port_tcp, logger=websocket_logger
        ):
            await asyncio.Future() 
