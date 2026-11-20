import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from channel import InstantConnect
from config_utils import password_allowed
from db.user import UserDb, USERS_COL_PUBLIC_EMAIL
import web


class CredentialTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.users = UserDb(Mock(), str(Path(temp.name) / "users.db"), 7000, 7001)
        self.addCleanup(self.users.conn.close)
        self.users.hasher.hash.side_effect = lambda password: "test-hash:" + password
        self.users.create_user_table()
        self.assertTrue(self.users.user_create("tester", "old password", time.time()))
        self.uid = self.users.username_query("tester")[0][0]

    def test_email_is_opt_in(self):
        self.assertEqual(self.users.uid_query(self.uid)[0][USERS_COL_PUBLIC_EMAIL], 0)
        self.users.set_public_email(self.uid, True)
        self.users.create_user_table()
        self.assertEqual(self.users.uid_query(self.uid)[0][USERS_COL_PUBLIC_EMAIL], 1)

    def test_reading_punishments_preserves_account_ban(self):
        self.assertTrue(self.users.update_user_with_root_guard(self.uid, stat="banned"))
        punishments = Mock()
        punishments.active_ban.return_value = None
        punishments.list_for_user.return_value = []
        with patch("web.read_json", return_value={}), patch("web.RateLimiter"):
            app = web.main(7000, 7001, None, None, None, self.users, Mock(), Mock(),
                           Mock(), Mock(), Mock(), Mock(), jwt_secret="test",
                           jwt_key_store=Mock(), punishments_cursor=punishments)
            with app.test_request_context(), patch.object(self.users, "verify_user", return_value=True):
                app.view_functions["punishment_list"].__wrapped__({"uid": self.uid, "password": "test"})
        punishments.list_for_user.assert_called_once_with(self.uid)
        self.assertEqual(self.users.uid_query(self.uid)[0][4], "banned")

    def test_password_rotation_revokes_access_and_refresh(self):
        now = time.time()
        sid = self.users.create_session(self.uid, "test refresh", now, now + 60)
        self.assertTrue(self.users.issue_token("test access", self.uid, now, now + 60))
        self.assertTrue(self.users.change_pwd(self.uid, "new password"))
        self.assertEqual(self.users.get_auth_version(self.uid), 1)
        self.assertFalse(self.users.session_is_active(sid))
        self.assertFalse(self.users.token_exists("test access"))

    def test_revocation_failure_rolls_back_password(self):
        before = self.users.uid_query(self.uid)[0]
        self.users.execute(
            "CREATE TRIGGER abort_rotation BEFORE UPDATE OF auth_version ON users "
            "BEGIN SELECT RAISE(ABORT, 'simulated failure'); END"
        )
        self.assertFalse(self.users.change_pwd(self.uid, "new password"))
        self.assertEqual(self.users.uid_query(self.uid)[0], before)

    def test_password_policy_respects_configured_boundary(self):
        cfg = {"min_password_length": 12}
        self.assertFalse(password_allowed("a" * 11, cfg))
        self.assertTrue(password_allowed("a" * 12, cfg))
        self.assertFalse(password_allowed("", {}))
        self.assertFalse(password_allowed(None, cfg))


class ConnectionExpiryTests(unittest.IsolatedAsyncioTestCase):
    async def test_password_change_handler_closes_connected_socket(self):
        users = Mock()
        users.verify_user.return_value = True
        users.change_pwd.return_value = True
        uid = 42
        with patch("channel.crypto.load_pri"), patch.object(InstantConnect, "_start_cleanup_thread"):
            hub = InstantConnect(7000, 7001, Mock(), users, Mock(), Mock(),
                                 jwt_secret="test", jwt_key_store=Mock())
        hub.features["presence"] = False
        hub.loop = asyncio.get_running_loop()
        closed = asyncio.Event()
        socket = AsyncMock()
        socket.close.side_effect = closed.set
        hub.connected_clients[uid] = [socket]
        hub.clients_belonged[socket] = uid
        with patch("web.read_json", return_value={}), patch("web.RateLimiter"):
            app = web.main(7000, 7001, None, None, None, users, Mock(), Mock(),
                           Mock(), Mock(), Mock(), hub, jwt_secret="test", jwt_key_store=Mock())
            with app.test_request_context():
                result = app.view_functions["change_pwd"].__wrapped__(
                    {"uid": uid, "password": "old password", "new_pwd": "replacement password"})
        self.assertTrue(result.endswith("True"))
        users.change_pwd.assert_called_once_with(uid, "replacement password")
        await asyncio.wait_for(closed.wait(), timeout=1)
        socket.close.assert_awaited_once()
        self.assertNotIn(uid, hub.connected_clients)

    async def test_idle_socket_closed_at_expiry(self):
        socket = AsyncMock()
        with patch("channel.time.time", return_value=100), patch.object(asyncio, "sleep", new_callable=AsyncMock) as sleep:
            await InstantConnect._close_on_expiry(socket, 112)
        sleep.assert_awaited_once_with(12)
        socket.close.assert_awaited_once_with(code=1008, reason="Token expired")
