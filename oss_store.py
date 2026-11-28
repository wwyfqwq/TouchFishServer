"""
OSS2 (阿里云对象存储) 适配模块。

当服务器的 res/<port_api>/config.json 中 storage_backend 为 "oss2" 时，
普通文件与贴图文件的 blob 以
  file/<hash>.file      （普通文件）
  sticker/<hash>.file   （贴图文件）
为 Object Key 存放在指定的 OSS2 Bucket 中。

本地磁盘仅作为上传 / 下载的临时中转：上传时先存本地、再传 OSS、最后删本地；
下载时先从 OSS 拉回本地临时文件（.oss_ 前缀）、发给客户端、再删除临时文件。
"""
from __future__ import annotations

import os
import time
import json
import threading
import unicodedata
import urllib.parse
import uuid
import glob

try:
    import oss2
    _OSS2_AVAILABLE = True
except ImportError:
    oss2 = None
    _OSS2_AVAILABLE = False

_config_cache = {}
_config_cache_ttl = 60.0
_config_lock = threading.Lock()

_download_locks = [threading.Lock() for _ in range(64)]


def _read_config(port_api: int) -> dict:
    """读取服务器配置（带 60 秒 TTL 缓存）。"""
    now = time.time()
    with _config_lock:
        cached = _config_cache.get(port_api)
        if cached and now - cached[0] < _config_cache_ttl:
            return cached[1]
        try:
            with open("res/{}/config.json".format(port_api), "r", encoding="utf-8") as handle:
                cfg = json.load(handle)
        except Exception:
            cfg = {}
        _config_cache[port_api] = (now, cfg)
        return cfg


def is_oss_enabled(port_api: int, cfg: dict = None) -> bool:
    """返回该服务器是否配置并启用了 OSS2 文件存储。"""
    if cfg is None:
        cfg = _read_config(port_api)
    if cfg.get("storage_backend") != "oss2":
        return False
    if not _OSS2_AVAILABLE:
        return False
    return bool(cfg.get("oss2_authid") and cfg.get("oss2_authkey")
                and cfg.get("oss2_endpoint") and cfg.get("oss2_bucket"))


_DEFAULT_ENDPOINT_SCHEME = "https://"


def _normalize_endpoint(endpoint) -> str:
    """补全 scheme、去掉尾部斜杠。

    不带 scheme 时统一补 https：预签名 URL 是直接下发到浏览器的，http 会在
    https 页面上被当混合内容拦掉。
    """
    if not isinstance(endpoint, str):
        return ""
    value = endpoint.strip().rstrip("/")
    if not value:
        return ""
    if "://" not in value:
        value = _DEFAULT_ENDPOINT_SCHEME + value
    return value


def _endpoint_host(endpoint: str) -> str:
    return endpoint.split("://", 1)[-1].rstrip("/") if endpoint else ""


def internal_endpoint(cfg: dict) -> str:
    """服务端自己读写 OSS 用的 endpoint（一般是 VPC 内网地址），保持配置原样。"""
    value = cfg.get("oss2_endpoint")
    return value.strip() if isinstance(value, str) else ""


def public_endpoint(cfg: dict) -> str:
    """下发给客户端的预签名 URL 所用的 endpoint，必须是公网可达地址。

    ``oss2_endpoint`` 常被配成 ``xxx-internal.aliyuncs.com`` 这类内网域名，
    它只在阿里云 VPC 内可解析（公网解析到 100.64/10 段），外部客户端连不上。
    优先读 ``oss2_public_endpoint``；未配置时从 ``oss2_endpoint`` 去掉
    ``-internal`` 推导——这正是阿里云内网 endpoint 的公网对应形式。
    """
    configured = _normalize_endpoint(cfg.get("oss2_public_endpoint"))
    if configured:
        return configured
    host = _endpoint_host(internal_endpoint(cfg)).replace("-internal.", ".")
    if not host:
        return ""
    return _DEFAULT_ENDPOINT_SCHEME + host


def _get_bucket(port_api: int, cfg: dict = None):
    """内网 bucket：上传、下载、head、删除都走这里。"""
    if cfg is None:
        cfg = _read_config(port_api)
    auth = oss2.Auth(cfg["oss2_authid"], cfg["oss2_authkey"])
    return oss2.Bucket(auth, cfg["oss2_endpoint"], cfg["oss2_bucket"])


def _get_sign_bucket(port_api: int, cfg: dict = None):
    """仅用于生成预签名 URL：公网 endpoint。

    OSS V1 签名只覆盖 path 与子资源、与 host 无关，所以用公网 endpoint 签出来的
    地址可以直接给外部客户端使用，不需要额外改写 host。
    """
    if cfg is None:
        cfg = _read_config(port_api)
    auth = oss2.Auth(cfg["oss2_authid"], cfg["oss2_authkey"])
    return oss2.Bucket(
        auth, public_endpoint(cfg) or cfg["oss2_endpoint"], cfg["oss2_bucket"]
    )


def object_key(kind: str, hashes: str) -> str:
    """生成 OSS2 Object Key：file/<hash>.file、sticker/<hash>.file 或 thumb/<hash>.thumb.webp"""
    if kind == "thumb":
        return "thumb/{}.thumb.webp".format(hashes)
    if kind not in ("file", "sticker"):
        raise ValueError("invalid kind: {}".format(kind))
    return "{}/{}.file".format(kind, hashes)


_KIND_DEFAULT_CONTENT_TYPE = {
    "thumb": "image/webp",
    "file": "application/octet-stream",
    "sticker": "application/octet-stream",
}


def upload_file_to_oss(port_api: int, local_path: str, kind: str, hashes: str,
                       cfg: dict = None, content_type: str = None) -> bool:
    """将本地临时文件上传到 OSS2（上传完成后由调用方负责删除本地文件）。

    [content_type] 会写进对象元数据。下载接口不再用预签名覆盖响应头，
    所以这里的 Content-Type 就是客户端最终拿到的类型——图片、贴图要传准，
    否则浏览器会把它当附件下载而不是内联显示。
    """
    if not is_oss_enabled(port_api, cfg):
        return False
    if cfg is None:
        cfg = _read_config(port_api)
    if not os.path.isfile(local_path):
        return False
    bucket = _get_bucket(port_api, cfg)
    key = object_key(kind, hashes)
    headers = {}
    resolved_type = content_type or _KIND_DEFAULT_CONTENT_TYPE.get(kind)
    if resolved_type:
        headers["Content-Type"] = resolved_type
    try:
        bucket.put_object_from_file(key, local_path, headers=headers or None)
        return True
    except Exception as e:
        print("[WARN] OSS2 上传失败 ({}): {}".format(key, e))
        return False


def download_from_oss(port_api: int, kind: str, hashes: str, local_path: str, cfg: dict = None) -> bool:
    """从 OSS2 下载对象到本地临时路径。返回是否成功。"""
    if not is_oss_enabled(port_api, cfg):
        return False
    if cfg is None:
        cfg = _read_config(port_api)
    bucket = _get_bucket(port_api, cfg)
    key = object_key(kind, hashes)
    lock = _download_locks[hash(os.path.abspath(local_path)) % len(_download_locks)]
    with lock:
        if os.path.isfile(local_path):
            return True
        staging = "{}.{}.part".format(local_path, uuid.uuid4().hex)
        try:
            if not bucket.object_exists(key):
                return False
            dirname = os.path.dirname(local_path)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            bucket.get_object_to_file(key, staging)
            os.replace(staging, local_path)
            return True
        except Exception as e:
            print("[WARN] OSS2 下载失败 ({}): {}".format(key, e))
            return False
        finally:
            safe_remove(staging)


def get_size_from_oss(port_api: int, kind: str, hashes: str, cfg: dict = None) -> int:
    """获取 OSS2 对象大小（in Byte) ~~字节跳动~~
    未启用 OSS2、对象不存在或 head 失败时返回 0。
    """
    if not is_oss_enabled(port_api, cfg):
        return 0
    if cfg is None:
        cfg = _read_config(port_api)
    bucket = _get_bucket(port_api, cfg)
    key = object_key(kind, hashes)
    try:
        return int(bucket.head_object(key).content_length or 0)
    except Exception as e:
        print("[WARN] OSS2 head 失败 ({}): {}".format(key, e))
        return 0


_DOWNLOAD_MODES = ("redirect", "proxy")


def get_download_mode(port_api: int, cfg: dict = None) -> str:
    """返回下载模式：redirect（预签名 307）或 proxy（服务端中转）。默认 redirect。"""
    if cfg is None:
        cfg = _read_config(port_api)
    mode = cfg.get("file_download_mode")
    if mode not in _DOWNLOAD_MODES:
        return "redirect"
    return mode


def _content_disposition_value(filename: str):
    """生成与 werkzeug send_file 完全一致的 attachment 头（含 RFC 5987 filename*）。"""
    try:
        from werkzeug.datastructures import Headers
        try:
            filename.encode("ascii")
            names = {"filename": filename}
        except UnicodeEncodeError:
            simple = unicodedata.normalize("NFKD", filename).encode("ascii", "ignore").decode("ascii")
            quoted = urllib.parse.quote(filename, safe="!#$&+-.^_`|~")
            names = {"filename": simple, "filename*": "UTF-8''" + quoted}
        headers = Headers()
        headers.set("Content-Disposition", "attachment", **names)
        return headers["Content-Disposition"]
    except Exception:
        return None


def presigned_download_url(port_api: int, kind: str, hashes: str, filename: str = None,
                           expires: int = 900, cfg: dict = None) -> str:
    """生成 OSS2 预签名下载 URL。未启用 OSS、签名失败时返回空字符串。

    两个硬约束，违反任意一条客户端都拿不到字节：

    1. 必须用**公网** endpoint 签名（见 :func:`public_endpoint`）。内网域名在
       公网解析到 100.64/10 段，请求会一直挂着直到超时。
    2. **不能带** ``response-content-type``。OSS 对该参数直接返回
       ``400 InvalidRequest: Can not override response header on content-type``
       （EC 0017-00000902），连签名合法都没用。响应类型改由对象自身的
       Content-Type 元数据决定，由 :func:`upload_file_to_oss` 在上传时写入。
    """
    if not is_oss_enabled(port_api, cfg):
        return ""
    if cfg is None:
        cfg = _read_config(port_api)
    bucket = _get_sign_bucket(port_api, cfg)
    key = object_key(kind, hashes)
    params = {}
    if filename:
        disposition = _content_disposition_value(filename)
        if disposition:
            params["response-content-disposition"] = disposition
    try:
        return bucket.sign_url("GET", key, expires, params=params or None, slash_safe=True)
    except Exception as e:
        print("[WARN] OSS2 预签名失败 ({}): {}".format(key, e))
        return ""


def head_and_prefix(port_api: int, kind: str, hashes: str, length: int = 4096,
                    cfg: dict = None):
    """返回 (对象总大小, 头部若干字节) 0byte head only pls"""
    if length <= 0:
        length = 4096
    if not is_oss_enabled(port_api, cfg):
        return None
    if cfg is None:
        cfg = _read_config(port_api)
    bucket = _get_bucket(port_api, cfg)
    key = object_key(kind, hashes)
    try:
        size = int(bucket.head_object(key).content_length or 0)
    except Exception as e:
        print("[WARN] OSS2 head 失败 ({}): {}".format(key, e))
        return None
    if size <= 0:
        return size, b""
    try:
        obj = bucket.get_object(key, byte_range=(0, min(length, size) - 1))
        try:
            data = obj.read()
        finally:
            try:
                obj.close()
            except Exception:
                pass
        return size, data or b""
    except Exception as e:
        print("[WARN] OSS2 范围读取失败 ({}): {}".format(key, e))
        return None


def download_bytes_from_oss(port_api: int, kind: str, hashes: str,
                            max_size: int = 10 * 1024 * 1024, cfg: dict = None):
    """完整拉取小块对象（仅用于 ≤max_size """
    if not is_oss_enabled(port_api, cfg):
        return None
    if cfg is None:
        cfg = _read_config(port_api)
    bucket = _get_bucket(port_api, cfg)
    key = object_key(kind, hashes)
    try:
        size = int(bucket.head_object(key).content_length or 0)
    except Exception as e:
        print("[WARN] OSS2 head 失败 ({}): {}".format(key, e))
        return None
    if size <= 0 or size > max_size:
        return None
    try:
        obj = bucket.get_object(key)
        try:
            return obj.read()
        finally:
            try:
                obj.close()
            except Exception:
                pass
    except Exception as e:
        print("[WARN] OSS2 读取失败 ({}): {}".format(key, e))
        return None


def delete_from_oss(port_api: int, kind: str, hashes: str, cfg: dict = None) -> bool:
    """从 OSS2 删除对象。"""
    if not is_oss_enabled(port_api, cfg):
        return False
    if cfg is None:
        cfg = _read_config(port_api)
    bucket = _get_bucket(port_api, cfg)
    key = object_key(kind, hashes)
    try:
        bucket.delete_object(key)
        return True
    except Exception as e:
        print("[WARN] OSS2 删除失败 ({}): {}".format(key, e))
        return False


def temp_download_path(port_api: int, kind: str, hashes: str) -> str:
    """
    生成一个唯一的 OSS 下载临时文件路径
    使用 .oss_ 前缀 + uuid，避免与本地存储的正式文件冲突，
    也避免并发下载同一 hash 时互相覆盖。
    """
    return "res/{}/tmp/.oss_{}_{}_{}.file".format(port_api, kind, uuid.uuid4().hex, hashes)


def safe_remove(path: str, retries: int = 5, delay: float = 0.2):
    """
    安全删除本地文件，带重试机制。
    解决 Windows 上 WinError 32（文件被占用）导致删除失败的问题。
    失败时不抛出异常，多次重试后仍失败则仅打印警告（交由后台清理兜底）。
    """
    for attempt in range(retries):
        try:
            if os.path.isfile(path):
                os.remove(path)
            return True
        except OSError:
            if attempt < retries - 1:
                time.sleep(delay)
    try:
        if os.path.isfile(path):
            print("[WARN] 临时文件删除失败(多次重试): {}".format(path))
    except OSError:
        pass
    return False


def cleanup_temp_files(port_api: int, kind: str, max_age: float = 3600.0):
    """
    清理残留的 .oss_ 
    正常情况下临时文件用后即删；这里兜底清理因异常崩溃等未能删除的残留。
    max_age 秒数：只清理超过该时间的旧文件，避免误删正在使用的文件。
    """
    if kind not in ("file", "sticker"):
        return
    directories = ("res/{}/tmp".format(port_api), "res/{}/{}".format(port_api, kind))
    now = time.time()
    for directory in directories:
        if not os.path.isdir(directory):
            continue
        try:
            pattern = os.path.join(directory, ".oss_*")
            for path in glob.glob(pattern):
                try:
                    if now - os.path.getmtime(path) > max_age:
                        safe_remove(path)
                except OSError:
                    pass
        except OSError:
            pass
