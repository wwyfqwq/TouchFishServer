import asyncio
import base64
import json
import tempfile
import threading
import unittest
from contextlib import AsyncExitStack
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import websockets

import crypto
from channel import InstantConnect, _Outbox, _encode_frame
from db.group import GroupDb
from db.messages import MessagesDb


def encrypted(message, key):
    iv, data = crypto.aes_encrypt(json.dumps(message), key)
    return json.dumps({
        "iv": base64.b64encode(iv).decode(),
        "content": base64.b64encode(data).decode(),
    })


async def receive(websocket, key):
    envelope = json.loads(await asyncio.wait_for(websocket.recv(), timeout=3))
    return json.loads(crypto.aes_decrypt(
        base64.b64decode(envelope["iv"]), base64.b64decode(envelope["content"]), key))


def make_channel(user_cursor=None, messages_cursor=None, private_key=None):
    with (patch("channel.crypto.load_pri", return_value=private_key),
          patch.object(InstantConnect, "_start_cleanup_thread")):
        contact = InstantConnect(0, 0, None, user_cursor, messages_cursor, Mock(),
                                 jwt_secret=b"test", jwt_key_store=object())
    return contact


class RealtimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_message_validation_keeps_connection_and_acknowledges_next_send(self):
        private_key, public_key, *_ = crypto.generate_rsa_keys()
        key = crypto.generate_aes_key()
        users = Mock()
        users.verify_user.side_effect = lambda uid, password: uid == 8 and password == "test"
        users.uid_query.return_value = [(8, "sender", None, None, "user")]
        users.get_show_status_flags.return_value = {}
        users.is_friend.side_effect = lambda sender, recipient: (sender, recipient) == (8, 9)
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            with MessagesDb(str(Path(temp) / "messages.db"), 0) as messages:
                contact = make_channel(users, messages, private_key)
                contact.file_cursor = Mock()
                contact.file_cursor.acquire_reference.return_value = {"file_name": "picture.png"}
                contact.file_cursor.get_metadata.return_value = {"file_type": "image"}
                contact.file_cursor.add_reference.side_effect = [False, True]
                contact.loop = asyncio.get_running_loop()
                async with websockets.serve(contact.handler, "127.0.0.1", 0) as server:
                    port = server.sockets[0].getsockname()[1]
                    async with websockets.connect(f"ws://127.0.0.1:{port}") as websocket:
                        await websocket.send(json.dumps({
                            "type": "REQ.UPDATE_AES_KEY",
                            "aes_key": base64.b64encode(crypto.encrypt(public_key, key)).decode(),
                        }))
                        await websocket.send(encrypted({
                            "type": "AUTH.LOGIN", "uid": "8", "password": "test",
                        }, key))
                        self.assertEqual((await receive(websocket, key))["type"], "AUTH.LOGIN_SUCCEEDED")
                        attempts = [
                            ("message.plain", {"plain": "draft"}, "invalid_target"),
                            ("message.plain", {"send_to": "U9", "plain": None}, "invalid_request"),
                            ("message.plain", {"send_to": "U9", "plain": "draft", "quote": "gone"}, "invalid_quote"),
                            ("message.file", {"send_to": "G", "quote": 1}, "invalid_target"),
                        ]
                        for index, (kind, content, error) in enumerate(attempts):
                            client_mid = f"draft-{index}"
                            await websocket.send(encrypted({
                                "type": kind, "client_mid": client_mid, "content": content,
                            }, key))
                            self.assertEqual(await receive(websocket, key), {
                                "type": "message.ack", "status": "failed",
                                "client_mid": client_mid, "error": error,
                            })
                        await websocket.send(encrypted({"type": "typing.stop"}, key))
                        await websocket.send(encrypted({"type": "PING"}, key))
                        self.assertEqual(await receive(websocket, key), {"type": "PONG"})
                        await websocket.send(encrypted({
                            "type": "message.plain", "client_mid": "ready",
                            "content": {"send_to": "U9", "plain": "ready to send"},
                        }, key))
                        ack = await receive(websocket, key)
                        self.assertEqual(ack["status"], "sent")
                        self.assertEqual(messages.get_message(ack["mid"])["content"], "ready to send")
                        self.assertEqual((await receive(websocket, key))["type"], "MESSAGE.NEW")

                        file_packet = encrypted({
                            "type": "message.file", "client_mid": "draft-file",
                            "content": {"send_to": "U9", "file_hashes": "a" * 64},
                        }, key)
                        await websocket.send(file_packet)
                        failed = await receive(websocket, key)
                        self.assertEqual(failed["error"], "file_reference_failed")
                        self.assertEqual(messages.current_room_seq("U8U9"), 1)
                        self.assertIsNone(messages.get_by_client_mid(8, "draft-file"))

                        await websocket.send(file_packet)
                        retry = await receive(websocket, key)
                        self.assertEqual(retry["status"], "sent")
                        self.assertEqual(messages.get_message(retry["mid"])["room_seq"], 2)

    async def test_group_chat_and_typing_follow_current_membership_on_real_sockets(self):
        private_key, public_key, *_ = crypto.generate_rsa_keys()
        users = Mock()
        users.verify_user.return_value = True
        users.get_show_status_flags.return_value = {}
        users.uid_query.return_value = [(8, "sender", None, None, "user")]
        users.query.return_value = [(9, "reader")]
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            with GroupDb(str(Path(temp) / "groups.db"), 0, config_reader=dict) as groups, \
                    MessagesDb(str(Path(temp) / "messages.db"), 0) as messages:
                gid = groups.create_group(8, "Room", "", "")
                self.assertTrue(groups.add_member(gid, 9))
                room = f"G{gid}"
                self.assertTrue(messages.update_room_preference(9, room, notify_level=1))
                contact = make_channel(users, messages, private_key)
                contact.group_cursor = groups
                contact.loop = asyncio.get_running_loop()
                async with AsyncExitStack() as stack:
                    server = await stack.enter_async_context(
                        websockets.serve(contact.handler, "127.0.0.1", 0))
                    url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
                    peers = {}
                    for uid in (8, 9):
                        conn = await stack.enter_async_context(websockets.connect(url))
                        key = crypto.generate_aes_key()
                        await conn.send(json.dumps({
                            "type": "REQ.UPDATE_AES_KEY",
                            "aes_key": base64.b64encode(crypto.encrypt(public_key, key)).decode(),
                        }))
                        await conn.send(encrypted({"type": "AUTH.LOGIN", "uid": uid, "password": "test"}, key))
                        self.assertEqual((await receive(conn, key))["type"], "AUTH.LOGIN_SUCCEEDED")
                        peers[uid] = (conn, key)

                    sender, key = peers[8]
                    await sender.send(encrypted({
                        "type": "message.plain", "client_mid": "group-1",
                        "content": {"send_to": room, "plain": "@reader 鱼"},
                    }, key))
                    self.assertEqual((await receive(sender, key))["status"], "sent")
                    own = await receive(sender, key)
                    other = await receive(*peers[9])
                    self.assertEqual(other["type"], "MESSAGE.NEW")
                    self.assertEqual(other["message"]["mentioned_uids"], [9])
                    self.assertTrue(other["message"]["should_alert"])
                    self.assertFalse(own["message"]["should_alert"])
                    self.assertEqual(other["message"]["room_seq"], 1)

                    await sender.send(encrypted({"type": "typing.start", "room_id": room}, key))
                    self.assertEqual((await receive(*peers[9]))["type"], "typing.start")
                    groups.remove_member(gid, 9)
                    peer, peer_key = peers[9]
                    await peer.send(encrypted({
                        "type": "message.plain", "client_mid": "after-leave",
                        "content": {"send_to": room, "plain": "hello"},
                    }, peer_key))
                    self.assertEqual((await receive(peer, peer_key))["error"], "not_group_member")
                    self.assertEqual(messages.current_room_seq(room), 1)

    async def test_acks_apply_the_same_backpressure_as_other_frames(self):
        contact = make_channel()
        contact.loop = asyncio.get_running_loop()
        websocket = AsyncMock()
        completed = asyncio.Event()

        async def close(**_):
            completed.set()

        websocket.close.side_effect = close
        for queue_ack in (
            lambda: contact._queue_ack(websocket, "draft"),
            lambda: contact._queue_call_ack(websocket, "call", "call.invite", "delivered"),
        ):
            with self.subTest(queue_ack=queue_ack):
                queue = _Outbox(websocket, item_limit=1, byte_limit=1024)
                contact.send_queue[websocket] = queue
                self.assertIsNone(queue.put(b"pending"))
                for _ in range(10):
                    queue_ack()
                await asyncio.wait_for(completed.wait(), timeout=1)
                websocket.close.assert_awaited_once_with(code=1013)
                websocket.close.reset_mock(side_effect=False)
                completed.clear()
                self.assertIsNone(await queue.get())

    async def test_group_fanout_personalizes_only_online_members_and_preserves_order(self):
        messages = Mock()
        messages.get_room_preference_map.return_value = {
            2: {"notify_level": 2}, 3: {"notify_level": 1},
            4: {"notify_level": 1},
        }
        contact = make_channel(messages_cursor=messages)
        contact.loop = asyncio.get_running_loop()

        def add(uid):
            socket = AsyncMock()
            contact.connected_clients.setdefault(uid, []).append(socket)
            box = _Outbox(socket, 8, 1024)
            contact.send_queue[socket] = box
            return box

        boxes = {uid: add(uid) for uid in range(1, 7)}
        other_device = add(1)
        sockets = [*boxes.values(), other_device]
        first = {box: asyncio.create_task(box.get()) for box in sockets}
        await asyncio.sleep(0)
        event = {"room_id": "G1", "content": "鱼", "mentioned_uids": [2, 3]}
        with patch("channel._encode_frame", wraps=_encode_frame) as encode:
            await asyncio.to_thread(contact.push_group_message, range(1, 101), 1, event)
            self.assertEqual(encode.call_count, 4)
        selected, room = messages.get_room_preference_map.call_args.args
        self.assertEqual(set(selected), set(boxes))
        self.assertEqual(room, "G1")
        await asyncio.wait_for(asyncio.gather(*first.values()), timeout=1)
        self.assertIs(first[other_device].result(), first[boxes[1]].result())
        self.assertIs(first[boxes[5]].result(), first[boxes[6]].result())
        for uid, box in boxes.items():
            frame = json.loads(first[box].result())
            flags = {"mentions_me": uid in (2, 3), "should_alert": uid in (3, 5, 6)}
            self.assertEqual(frame, {"type": "MESSAGE.NEW", "message": dict(event, **flags)})

        def publish():
            for seq in range(4):
                contact.push_raw(1, {"seq": seq}, exclude_websocket=other_device.websocket)

        await asyncio.to_thread(publish)
        self.assertEqual([json.loads(await boxes[1].get())["seq"] for _ in range(4)], list(range(4)))
        self.assertFalse(other_device.frames)
        messages.get_room_preference_map.reset_mock()
        contact.push_group_message(range(7, 101), 1, event)
        messages.get_room_preference_map.assert_not_called()

    async def test_payload_byte_budget_releases_backlog_and_keeps_other_connections_live(self):
        contact = make_channel()
        contact.loop = asyncio.get_running_loop()
        slow, fast = AsyncMock(), AsyncMock()
        small = _Outbox(slow, item_limit=128, byte_limit=36)
        large = _Outbox(fast, item_limit=128, byte_limit=4096)
        contact.connected_clients[1] = [slow, fast]
        contact.send_queue.update({slow: small, fast: large})
        for seq in range(9):
            contact.push_raw(1, {"seq": seq, "text": "鱼"})
        self.assertTrue(small.closed)
        self.assertFalse(small.frames)
        self.assertEqual(small.queued_bytes, 0)
        self.assertEqual([json.loads(await large.get())["seq"] for _ in range(9)], list(range(9)))
        self.assertEqual(large.queued_bytes, 0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        slow.close.assert_awaited_once_with(code=1013)
        fast.close.assert_not_awaited()

        single = _Outbox(fast, item_limit=4, byte_limit=4)
        self.assertIsNone(single.put(b"large legacy frame"))
        self.assertEqual(await single.get(), b"large legacy frame")

    async def test_timed_out_auth_waits_for_actual_worker_before_reusing_permit(self):
        contact = make_channel()
        contact._auth_semaphore = asyncio.Semaphore(1)
        started = threading.Event()
        finish = threading.Event()

        def slow_work():
            started.set()
            finish.wait(3)

        job = asyncio.create_task(contact._auth_work(slow_work))
        try:
            self.assertTrue(await asyncio.to_thread(started.wait, 1))
            job.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await job
            follow_up = Mock()
            with self.assertRaises(asyncio.TimeoutError):
                await contact._auth_work(follow_up, timeout=0.02)
            follow_up.assert_not_called()
        finally:
            finish.set()
        self.assertEqual(await contact._auth_work(lambda: 42, timeout=1), 42)

    async def test_revocation_rechecks_in_flight_login_and_closes_all_devices_together(self):
        contact = make_channel()
        contact.loop = asyncio.get_running_loop()
        contact.features["presence"] = False
        checking, resume = asyncio.Event(), asyncio.Event()
        calls = []

        async def verify(_):
            calls.append(1)
            if len(calls) == 1:
                checking.set()
                await resume.wait()
                return 8, "token", "session", None, None
            return None

        contact._verify_ws_token = verify
        pending = AsyncMock()
        contact.connected_clients[-1].add(pending)
        login = asyncio.create_task(contact._register_login(pending, {"token": "unit-test"}))
        await checking.wait()
        contact.disconnect_session("session")
        resume.set()
        with self.assertRaises(ValueError):
            await login
        self.assertEqual(len(calls), 2)
        self.assertNotIn(8, contact.connected_clients)

        slow, fast, independent = AsyncMock(), AsyncMock(), AsyncMock()
        held = asyncio.Event()
        fast_closed = asyncio.Event()

        async def slow_close():
            await held.wait()

        async def fast_close():
            fast_closed.set()

        slow.close.side_effect = slow_close
        fast.close.side_effect = fast_close
        for ws, sid in ((slow, "session"), (fast, "session"), (independent, "other")):
            contact.connected_clients.setdefault(8, []).append(ws)
            contact.clients_belonged[ws] = 8
            contact.clients_session[ws] = sid
            contact.send_queue[ws] = _Outbox(ws, 8, 1024)
        boxes = [contact.send_queue[ws] for ws in (slow, fast, independent)]
        contact.disconnect_session("session")
        self.assertEqual([box.closed for box in boxes], [True, True, False])
        try:
            await asyncio.wait_for(fast_closed.wait(), timeout=1)
            self.assertEqual(contact.connected_clients[8], [independent])
            independent.close.assert_not_awaited()
        finally:
            held.set()

    async def test_websocket_login_checks_account_status_for_password_and_token(self):
        users = Mock()
        users.verify_user.return_value = True
        contact = make_channel(users)
        for status in ("pending", "banned", "user"):
            users.uid_query.return_value = [(7, "name", None, None, status)]
            users.resolve_session_identity.return_value = (status, 2)
            with patch("channel.jwt_tool.verify_local_token", return_value={
                    "sub": "7", "jti": "token", "sid": "session", "av": 2}):
                self.assertEqual(contact._verify_ws_password(7, "test") is not None, status == "user")
                self.assertEqual((await contact._verify_ws_token("test")) is not None, status == "user")
        contact.punishments_cursor = Mock()
        contact.punishments_cursor.active_ban.return_value = (7, "active")
        self.assertIsNone(contact._verify_ws_password(7, "test"))

    async def test_wire_frame_stays_text_and_decrypts_for_each_device(self):
        contact = make_channel()
        contact.loop = asyncio.get_running_loop()
        sockets = [AsyncMock(), AsyncMock()]
        boxes = [_Outbox(ws, 8, 1024) for ws in sockets]
        contact.connected_clients[5] = sockets
        contact.send_queue.update(zip(sockets, boxes))
        payload = {"type": "example", "value": "鱼\udfff\\\n"}
        for ws in sockets:
            contact.aes_key[ws] = crypto.generate_aes_key()

        contact.push_raw(5, payload)
        tasks = [asyncio.create_task(contact.sender(ws, box)) for ws, box in zip(sockets, boxes)]
        await asyncio.sleep(0)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks)

        ivs = []
        for ws in sockets:
            sent = ws.send.await_args
            self.assertTrue(sent.kwargs["text"])
            envelope = json.loads(sent.args[0])
            ivs.append(envelope["iv"])
            plain = crypto.aes_decrypt(base64.b64decode(envelope["iv"]),
                                       base64.b64decode(envelope["content"]), contact.aes_key[ws])
            self.assertEqual(json.loads(plain), payload)
        self.assertNotEqual(*ivs)

    async def test_idle_sweep_leaves_connection_that_resumed(self):
        contact = make_channel()
        contact._load_config({"ws_idle_timeout": 1})
        websocket = AsyncMock()
        contact.clients_belonged[websocket] = 8
        with patch("channel.time.monotonic", return_value=100):
            contact._client_last_inbound[websocket] = 98
            contact._touch_client_activity(websocket)
            await contact._close_idle_connection(websocket, 98)
            websocket.close.assert_not_awaited()
        with patch("channel.time.monotonic", return_value=102):
            await contact._close_idle_connection(websocket, 100)
            websocket.close.assert_awaited_once_with(code=1001)


class ReadReceiptTests(unittest.TestCase):
    def test_pending_receipts_keep_highest_sequence_and_respect_current_privacy(self):
        contact = make_channel()
        contact.push_raw = Mock()
        contact._user_shows_read_status = Mock(return_value=True)
        with patch("channel.threading.Timer") as timer, patch("channel.time.monotonic") as clock:
            clock.return_value = 100
            contact.emit_private_read_receipt(8, 9, "U8U9", 11, 1)
            clock.return_value += 0.5
            contact.emit_private_read_receipt(8, 9, "U8U9", 14, 4)
            contact.emit_private_read_receipt(8, 9, "U8U9", 13, 3)
            delay, fire = timer.call_args.args
            self.assertEqual(delay, 1.0)
            clock.return_value += delay
            fire()
            self.assertEqual(contact.push_raw.call_count, 2)
            self.assertEqual(contact.push_raw.call_args.args[1]["last_seq"], 4)

            contact.emit_private_read_receipt(8, 9, "U8U9", 15, 5)
            _, fire = timer.call_args.args
            contact._user_shows_read_status.return_value = False
            fire()
            self.assertEqual(contact.push_raw.call_count, 2)


if __name__ == "__main__":
    unittest.main()
