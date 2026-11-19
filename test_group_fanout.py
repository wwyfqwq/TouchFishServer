import asyncio
import threading
import unittest
from unittest.mock import AsyncMock, Mock, patch

from channel import InstantConnect


class GroupFanoutTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.hub = InstantConnect.__new__(InstantConnect)
        self.hub.loop = asyncio.get_running_loop()
        self.hub._clients_lock = threading.Lock()
        self.hub._closing_slow_clients = {}
        self.hub.connected_clients = {}
        self.hub.clients_belonged = {}
        self.hub.send_queue = {}

    def connect(self, uid, capacity=8):
        socket = Mock()
        socket.close = AsyncMock()
        queue = asyncio.Queue(maxsize=capacity)
        self.hub.connected_clients.setdefault(uid, []).append(socket)
        self.hub.clients_belonged[socket] = uid
        self.hub.send_queue[socket] = queue
        return socket, queue

    async def test_one_callback_per_batch_preserves_order_across_devices(self):
        _, first = self.connect(1)
        _, second = self.connect(1)
        _, third = self.connect(2)
        loop = self.hub.loop
        with patch.object(loop, 'call_soon_threadsafe', wraps=loop.call_soon_threadsafe) as schedule:
            for mid in (10, 11):
                alerts = {'mid': mid, 'should_alert': True}
                quiet = {'mid': mid, 'should_alert': False}
                returned = self.hub.push_messages([(1, alerts), (2, quiet)])
                self.assertEqual(returned, [alerts, quiet])
                self.assertIsNot(returned[0], alerts)
            self.assertEqual(schedule.call_count, 2)
        for queue, alert in ((first, True), (second, True), (third, False)):
            for mid in (10, 11):
                self.assertEqual(await asyncio.wait_for(queue.get(), 1), {
                    'type': 'MESSAGE.NEW', 'message': {'mid': mid, 'should_alert': alert},
                })
            self.assertTrue(queue.empty())

    async def test_group_and_single_push_keep_submission_order(self):
        _, queue = self.connect(1)
        self.hub.push_message(1, {'mid': 1})
        self.hub.push_messages([(1, {'mid': 2})])
        self.hub.push_message(1, {'mid': 3})
        for mid in (1, 2, 3):
            received = await asyncio.wait_for(queue.get(), 1)
            self.assertEqual(received['message'], {'mid': mid})

    async def test_disconnected_recipient_does_not_block_other_devices(self):
        stale, old_queue = self.connect(1)
        _, live_queue = self.connect(2)
        self.hub.push_messages([(1, {'mid': 7}), (2, {'mid': 7})])
        self.hub.connected_clients.pop(1)
        self.hub.send_queue.pop(stale)
        self.hub.clients_belonged.pop(stale)
        message = await asyncio.wait_for(live_queue.get(), 1)
        self.assertTrue(old_queue.empty())
        self.assertEqual(message['message'], {'mid': 7})
        stale.close.assert_not_awaited()

    async def test_full_queue_closes_once_without_delaying_other_clients(self):
        slow, slow_queue = self.connect(1, capacity=1)
        _, live_queue = self.connect(2)
        slow_queue.put_nowait({'mid': 0})
        started, release = asyncio.Event(), asyncio.Event()

        async def close(code):
            started.set()
            await release.wait()

        slow.close.side_effect = close
        try:
            for mid in (1, 2):
                self.hub.push_messages([(1, {'mid': mid}), (2, {'mid': mid})])
            await asyncio.wait_for(started.wait(), timeout=1)
            slow.close.assert_awaited_once_with(code=1013)
            self.assertEqual([live_queue.get_nowait()['message']['mid'] for _ in range(2)], [1, 2])
            self.assertEqual(slow_queue.get_nowait(), {'mid': 0})
        finally:
            release.set()
            await asyncio.sleep(0)

    async def test_empty_and_offline_batches(self):
        loop = self.hub.loop
        with patch.object(loop, 'call_soon_threadsafe', wraps=loop.call_soon_threadsafe) as schedule:
            self.assertEqual(self.hub.push_messages([]), [])
            self.assertEqual(self.hub.push_messages([(42, {'mid': 1})]), [{'mid': 1}])
            schedule.assert_not_called()
        self.hub.loop = None
        self.assertEqual(self.hub.push_messages([(42, {'mid': 2})]), [{'mid': 2}])
