"""
没错，只是为了放验证码和邮箱验证的程序
"""

import os
from concurrent.futures import ThreadPoolExecutor
from json_store import read_json, update_json
import secrets
import ssl
import smtplib
from string import ascii_letters, digits
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from threading import BoundedSemaphore
from time import time

from json_store import read_json, update_json

MAX_DELAY = 300
EMAIL_CODE_TTL = 600
EMAIL_CODE_ATTEMPTS = 5

def login_email(sender_email : str, password : str, smtp_host=None, smtp_port=None, smtp_use_ssl=True):
    """
    password 是登录密码或者授权码，视邮件提供商要求
    smtp_host/smtp_port/smtp_use_ssl 可手动指定 SMTP 参数；
    未指定 smtp_host 时按邮箱域名自动猜测 smtp.<domain>
    smtp_use_ssl: True = SMTP_SSL 直连（默认 465），False = SMTP + STARTTLS（默认 587）
    """
    if smtp_host:
        smtp_server = smtp_host
    else:
        smtp_server = 'smtp.' + sender_email.split('@')[1]
    if smtp_port is None:
        smtp_port = 465 if smtp_use_ssl else 587
    context = ssl.create_default_context()
    if smtp_use_ssl:
        server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10, context=context)
    else:
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.starttls(context=context)
    server.login(sender_email, password)
    return server

def send_email(server, sender_email : str, receiver_email : str, subject : str, content : str):
    """
    server 是 smtplib.SMTP_SSL 对象
    """
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = Header(subject, 'utf-8')
    msg.attach(MIMEText(content, "plain", "utf-8"))
    try:
        server.sendmail(sender_email, receiver_email, msg.as_string())
    except (smtplib.SMTPException, OSError):
        return False
    return True

def _captcha_expiry(stamp, entry):
    if isinstance(entry, dict):
        return entry["expires_at"]
    return int(stamp) + MAX_DELAY


def generate_captcha(port_api : int, Imgcaptcha, lock):
    folder = "res/{}/captcha".format(port_api)
    now = time()
    answer = ''.join(secrets.choice(ascii_letters + digits) for _ in range(6))
    with lock:
        def issue(records):
            for stamp, entry in list(records.items()):
                if _captcha_expiry(stamp, entry) <= now:
                    del records[stamp]
                    try:
                        os.remove(os.path.join(folder, "{}.png".format(int(stamp))))
                    except FileNotFoundError:
                        pass
            stamp = secrets.randbits(52)
            while str(stamp) in records:
                stamp = secrets.randbits(52)
            Imgcaptcha.write(answer, os.path.join(folder, "{}.png".format(stamp)))
            records[str(stamp)] = {"answer": answer, "expires_at": now + MAX_DELAY}
            return stamp

        return update_json(os.path.join(folder, 'captcha.json'), issue, default=dict)


def verify_captcha(port_api : int, time_stamp : int, verify_text : str, lock):
    try:
        stamp = str(int(time_stamp))
    except (TypeError, ValueError):
        return False, False
    folder = "res/{}/captcha".format(port_api)
    with lock:
        def consume(records):
            entry = records.pop(stamp, None)
            if entry is None:
                return False, False
            try:
                os.remove(os.path.join(folder, stamp + ".png"))
            except FileNotFoundError:
                return False, False
            if _captcha_expiry(stamp, entry) <= time():
                return False, False
            answer = entry["answer"] if isinstance(entry, dict) else entry
            return answer.lower() == str(verify_text).lower(), True

        return update_json(os.path.join(folder, 'captcha.json'), consume, default=dict)


def issue_email_code(port_api, email, activate_lock, *, uid, purpose):
    now = time()
    key = f"{purpose}:{uid}"
    with activate_lock:
        def issue(records):
            for k, entry in list(records.items()):
                if not isinstance(entry, dict) or entry.get("expires_at", 0) <= now:
                    del records[k]
            previous = records.get(key)
            if isinstance(previous, dict) and previous.get("email") == email:
                code = previous["code"]
                attempts_left = previous.get("attempts_left", EMAIL_CODE_ATTEMPTS)
            else:
                code = secrets.randbelow(900000) + 100000
                attempts_left = EMAIL_CODE_ATTEMPTS
            records[key] = {
                "email": email, "code": code, "expires_at": now + EMAIL_CODE_TTL,
                "attempts_left": attempts_left,
            }
            return code
        return update_json("res/{}/activate.json".format(port_api), issue, default=dict)


def send_email_code(sender_email : str, port_api : int, email : str, password : str, config_lock, verify_code : int):
    """发送已生成的验证码"""
    folder_path = "res/{}".format(port_api)
    with config_lock:
        cfg = read_json(folder_path + '/config.json')
        server_name = cfg["server_name"]
        smtp_host = cfg.get("smtp_host", "") or None
        smtp_port = cfg.get("smtp_port")
        smtp_use_ssl = cfg.get("smtp_use_ssl", True)
    session = login_email(sender_email, password, smtp_host, smtp_port, smtp_use_ssl)
    return send_email(session, sender_email, email, "{} 验证码".format(server_name), "欢迎使用 {}，您的验证码是 {}。".format(server_name, verify_code))


def email_code(sender_email : str, port_api : int, email : str, password : str, config_lock, activate_lock, *, uid, purpose):
    verify_code = issue_email_code(port_api, email, activate_lock, uid=uid, purpose=purpose)
    return send_email_code(sender_email, port_api, email, password, config_lock, verify_code)


# 避免被刷爆 IO
_EMAIL_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="tfv5-smtp")
_EMAIL_PENDING = BoundedSemaphore(32)


def _send_email_code_logged(sender_email, port_api, email, password, config_lock, verify_code):
    try:
        ok = send_email_code(sender_email, port_api, email, password, config_lock, verify_code)
        if not ok:
            print("[WARN] 验证码邮件发送失败: {}".format(email))
    except Exception as e:
        print("[WARN] 验证码邮件发送异常({}): {}".format(email, e))
    finally:
        _EMAIL_PENDING.release()


def email_code_async(sender_email, port_api, email, password, config_lock, activate_lock, *, uid, purpose):
    """
    写入验证码并后台发信
    False 表示排队已满或验证码写入失败
    """
    if not _EMAIL_PENDING.acquire(blocking=False):
        print("[WARN] 验证码邮件队列已满，拒绝本次请求: {}".format(email))
        return False
    try:
        verify_code = issue_email_code(port_api, email, activate_lock, uid=uid, purpose=purpose)
    except Exception as e:
        _EMAIL_PENDING.release()
        print("[WARN] 验证码写入失败({}): {}".format(email, e))
        return False
    try:
        _EMAIL_EXECUTOR.submit(
            _send_email_code_logged,
            sender_email, port_api, email, password, config_lock, verify_code,
        )
    except Exception as e:
        _EMAIL_PENDING.release()
        print("[WARN] 验证码邮件入队失败: {}".format(e))
        return False
    return True

def verify_email(port_api, email, code, lock, *, uid, purpose):
    if not isinstance(code, int):
        return False
    key = f"{purpose}:{uid}"
    with lock:
        def check(records):
            entry = records.get(key)
            if not isinstance(entry, dict) or entry["email"] != email:
                return False
            if entry["expires_at"] <= time():
                del records[key]
                return False
            if entry["code"] == code:
                return True
            entry["attempts_left"] -= 1
            if entry["attempts_left"] <= 0:
                del records[key]
            return False
        return update_json("res/{}/activate.json".format(port_api), check, default=dict)


def consume_email_code(port_api, email, code, lock, *, uid, purpose):
    """状态变更成功后作废验证码"""
    key = f"{purpose}:{uid}"
    with lock:
        def consume(records):
            entry = records.get(key)
            if isinstance(entry, dict) and entry.get("email") == email and entry.get("code") == code:
                del records[key]
        update_json("res/{}/activate.json".format(port_api), consume, default=dict)
