import asyncio
import base64
import json
import threading
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

from websockets.exceptions import ConnectionClosed

import crypto
from channel import InstantConnect


TIMEOUT = 3
UID = 42
SID = "test-session"


class LoginSocket:
    remote_address = ("127.0.0.1", 12345)
    key = b"test" * 8

    def __init__(self):
        iv, content = crypto.aes_encrypt(
            json.dumps({"type": "AUTH.LOGIN", "token": "test-token"}), self.key
        )
        self.recv = AsyncMock(side_effect=[
            json.dumps({"type": "REQ.UPDATE_AES_KEY", "aes_key": "dGVzdA=="}),
            json.dumps({
                "iv": base64.b64encode(iv).decode(),
                "content": base64.b64encode(content).decode(),
            }),
        ])
        self.closed = asyncio.Event()
        self.close = AsyncMock(side_effect=self._close)
        self.frames = asyncio.Queue()

    async def _close(self, code=1000, reason=""):
        self.closed.set()

    async def send(self, frame):
        if self.closed.is_set():
            raise ConnectionClosed(None, None)
        frame = json.loads(frame)
        plaintext = crypto.aes_decrypt(
            base64.b64decode(frame["iv"]), base64.b64decode(frame["content"]), self.key
        )
        self.frames.put_nowait(json.loads(plaintext))

    def __aiter__(self):
        return self

    async def __anext__(self):
        await self.closed.wait()
        raise StopAsyncIteration


class LoginQueueTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.socket = LoginSocket()
        self.rechecking = asyncio.Event()
        self.resume_recheck = threading.Event()
        self.auth_version = 4
        self.expires_at = int(time.time()) + 60
        users = Mock()
        users.get_auth_version.side_effect = self._get_auth_version
        with patch("channel.crypto.load_pri"), patch.object(InstantConnect, "_start_cleanup_thread"):
            self.hub = InstantConnect(7000, 7001, Mock(), users, Mock(), Mock(),
                                      jwt_secret="test", jwt_key_store=Mock())
        self.hub.features["presence"] = False
        self.hub.loop = asyncio.get_running_loop()
        self.hub._verify_ws_token = AsyncMock(
            return_value=(UID, "test-token-id", SID, self.auth_version, self.expires_at)
        )
        decrypt = patch("channel.crypto.decrypt", return_value=self.socket.key)
        decrypt.start()
        self.addCleanup(decrypt.stop)

    def _get_auth_version(self, uid):
        self.hub.loop.call_soon_threadsafe(self.rechecking.set)
        if not self.resume_recheck.wait(timeout=2 * TIMEOUT):
            raise TimeoutError("auth version recheck was not released")
        return self.auth_version

    async def _start_login(self):
        task = asyncio.create_task(self.hub.handler(self.socket))
        self.addAsyncCleanup(self._stop_login, task)
        await asyncio.wait_for(self.rechecking.wait(), TIMEOUT)
        return task

    async def _stop_login(self, task):
        self.resume_recheck.set()
        self.socket.closed.set()
        if not task.done():
            await asyncio.wait_for(task, TIMEOUT)

    async def _flush_pushes(self):
        async def barrier():
            pass

        # Submit after the push callbacks. Queue inserts with capacity finish without yielding.
        future = asyncio.run_coroutine_threadsafe(barrier(), self.hub.loop)
        await asyncio.wait_for(asyncio.wrap_future(future), TIMEOUT)

    def _assert_detached(self):
        self.assertEqual(self.hub.connected_clients, {-1: []})
        for mapping in (self.hub.clients_belonged, self.hub.clients_token,
                        self.hub.clients_session, self.hub.send_queue, self.hub.aes_key):
            self.assertNotIn(self.socket, mapping)

    async def test_pushes_during_recheck_follow_login_reply(self):
        await self._start_login()
        self.assertEqual(self.hub.filter_online([UID]), [UID])

        self.hub.push_message(UID, {"mid": 1})
        self.hub.push_messages([(UID, {"mid": 2}), (UID, {"mid": 3})])
        await self._flush_pushes()
        self.assertTrue(self.socket.frames.empty())

        self.resume_recheck.set()
        get_frame = self.socket.frames.get
        self.assertEqual(await asyncio.wait_for(get_frame(), TIMEOUT), {
            "type": "AUTH.LOGIN_SUCCEEDED",
        })
        # A post-login push makes the lost-frame case fail without waiting for a timeout.
        self.hub.push_message(UID, {"mid": 4})
        for mid in (1, 2, 3, 4):
            self.assertEqual(await asyncio.wait_for(get_frame(), TIMEOUT), {
                "type": "MESSAGE.NEW", "message": {"mid": mid},
            })

    async def test_changed_credentials_discard_queued_push(self):
        task = await self._start_login()
        self.hub.push_message(UID, {"mid": 1})
        await self._flush_pushes()

        self.auth_version += 1
        self.resume_recheck.set()
        await asyncio.wait_for(task, TIMEOUT)

        self.assertTrue(self.socket.frames.empty())
        self._assert_detached()

    async def test_expired_token_discards_queued_push(self):
        task = await self._start_login()
        self.hub.push_message(UID, {"mid": 1})
        await self._flush_pushes()

        with patch("channel.time.time", return_value=self.expires_at):
            self.resume_recheck.set()
            await asyncio.wait_for(task, TIMEOUT)

        self.assertTrue(self.socket.frames.empty())
        self._assert_detached()

    async def test_session_disconnect_during_recheck_discards_queued_push(self):
        task = await self._start_login()
        self.hub.push_message(UID, {"mid": 1})
        await self._flush_pushes()
        await self.hub._disconnect_session(SID)

        self.resume_recheck.set()
        await asyncio.wait_for(task, TIMEOUT)

        self.socket.close.assert_awaited_once()
        self.assertTrue(self.socket.frames.empty())
        self._assert_detached()

    async def test_cancelled_recheck_cleans_registration(self):
        task = await self._start_login()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self._assert_detached()

    async def test_queue_overflow_during_recheck_closes_slow_socket(self):
        self.hub.SEND_QUEUE_LIMIT = 1
        task = await self._start_login()
        self.hub.push_messages([(UID, {"mid": 1}), (UID, {"mid": 2})])

        await asyncio.wait_for(self.socket.closed.wait(), TIMEOUT)
        self.socket.close.assert_awaited_once_with(code=1013)
        self.resume_recheck.set()
        await asyncio.wait_for(task, TIMEOUT)

        self.assertTrue(self.socket.frames.empty())
        self._assert_detached()

    async def test_disconnect_during_presence_update_cleans_login(self):
        updating = asyncio.Event()
        resume_presence = threading.Event()

        def mark_online(uid):
            self.hub.loop.call_soon_threadsafe(updating.set)
            if not resume_presence.wait(timeout=2 * TIMEOUT):
                raise TimeoutError("presence update was not released")

        with patch.object(self.hub, "_mark_online", side_effect=mark_online):
            task = await self._start_login()
            self.resume_recheck.set()
            try:
                await asyncio.wait_for(updating.wait(), TIMEOUT)
                await self.hub._disconnect_user(UID)
            finally:
                resume_presence.set()
            await asyncio.wait_for(task, TIMEOUT)

        self.assertEqual(self.socket.frames.get_nowait(), {"type": "AUTH.LOGIN_SUCCEEDED"})
        self.assertTrue(self.socket.frames.empty())
        self._assert_detached()
