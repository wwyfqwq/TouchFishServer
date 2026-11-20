import os
import ssl
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import register_tool


class VerificationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        original = os.getcwd()
        os.chdir(temp.name)
        self.addCleanup(os.chdir, original)
        self.lock = threading.Lock()
        self.email = "test@example.invalid"

    def issue(self, purpose):
        return register_tool.issue_email_code(1, self.email, self.lock, uid=1, purpose=purpose)

    def verify(self, code, purpose="activate", uid=1):
        return register_tool.verify_email(1, self.email, code, self.lock, uid=uid, purpose=purpose)

    def test_email_binding_and_single_use(self):
        code = self.issue("activate")
        self.assertFalse(self.verify(code, purpose="reset"))
        self.assertFalse(self.verify(code, uid=2))
        self.assertTrue(self.verify(code))
        self.assertFalse(self.verify(code))

    def test_legacy_codes_require_reissue(self):
        Path("res/1").mkdir(parents=True)
        path = Path("res/1/activate.json")
        path.write_text('{"test@example.invalid":123456}')
        self.assertFalse(self.verify(123456))
        self.assertTrue(self.verify(self.issue("activate")))

    def test_code_lifetime_and_attempts(self):
        with patch.object(register_tool, "time", return_value=1000):
            code = self.issue("activate")
        with patch.object(register_tool, "time", return_value=1000 + register_tool.EMAIL_CODE_TTL):
            self.assertFalse(self.verify(code))
        code = self.issue("activate")
        for _ in range(register_tool.EMAIL_CODE_ATTEMPTS):
            self.assertFalse(self.verify(-1))
        self.assertFalse(self.verify(code))

    def test_parallel_image_challenges_have_independent_one_use_ids(self):
        img = Mock()
        answers = {}
        def write_image(answer, path):
            Path(path).touch()
            answers[int(Path(path).stem)] = answer
        img.write.side_effect = write_image
        Path("res/1/captcha").mkdir(parents=True)
        with patch.object(register_tool, "time", return_value=1700000000):
            first = register_tool.generate_captcha(1, img, self.lock)
            second = register_tool.generate_captcha(1, img, self.lock)
            self.assertNotEqual(first, second)
            for stamp in (first, second):
                self.assertEqual(register_tool.verify_captcha(1, stamp, answers[stamp], self.lock), (True, True))
                self.assertEqual(register_tool.verify_captcha(1, stamp, answers[stamp], self.lock), (False, False))

    def test_smtp_verifies_peer_in_both_modes(self):
        for implicit_tls in (True, False):
            with self.subTest(implicit_tls=implicit_tls):
                factory_name = "SMTP_SSL" if implicit_tls else "SMTP"
                with patch.object(register_tool.smtplib, factory_name) as smtp:
                    register_tool.login_email(self.email, "fixture", smtp_use_ssl=implicit_tls)
                call = smtp.call_args if implicit_tls else smtp.return_value.starttls.call_args
                context = call.kwargs["context"]
                self.assertTrue(context.check_hostname)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_only_pending_account_with_matching_mailbox_can_be_activated(self):
        from db.user import UserDb

        hasher = Mock()
        hasher.hash.return_value = "fixture"
        with UserDb(hasher, "fixture.db", 1, 2) as users:
            users.create_user_table()
            self.assertTrue(users.user_create("testuser", "fixture", 1, self.email, stat="pending"))
            uid = users.email_query(self.email)[0][0]
            self.assertFalse(users.activate_pending(uid, "other@example.invalid"))
            self.assertTrue(users.activate_pending(uid, self.email))
            for state in ("user", "banned", "admin", "root"):
                users.change_auth(uid, state)
                self.assertFalse(users.activate_pending(uid, self.email))
                self.assertEqual(users.uid_query(uid)[0][4], state)
