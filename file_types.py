"""
文件类型检测（是的，非常高端！）
"""
from __future__ import annotations
import gzip
import io
import json
import re
from xml.parsers import expat
import zlib


IMAGE_TYPES = {"png", "jpg", "gif", "bmp", "svg", "tgs"}


MAX_STICKER_DOCUMENT_BYTES = 10 * 1024 * 1024
_HASH_PATTERN = re.compile(r"[0-9a-fA-F]{8,128}")


def is_valid_file_hash(value):
    return isinstance(value, str) and _HASH_PATTERN.fullmatch(value) is not None


def _svg_root(prefix):
    if b"<" not in prefix:
        return False
    roots = []
    parser = expat.ParserCreate(namespace_separator=" ")

    def root(name, attrs):
        roots.append(name)
        raise StopIteration

    def reject_entity(*args):
        raise ValueError("Entity declarations are unnecessary for type detection")

    parser.StartElementHandler = root
    parser.EntityDeclHandler = reject_entity
    try:
        parser.Parse(prefix, False)
    except (StopIteration, ValueError, expat.ExpatError):
        pass
    return bool(roots) and roots[0] in {"svg", "http://www.w3.org/2000/svg svg"}


def detect_file_type(content: bytes, fallback_name: str = "") -> str:
    """返回文件类型"""
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if content.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if content.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if content.startswith(b"BM"):
        return "bmp"
    if _svg_root(content[:4096]):
        return "svg"

    if content.startswith(b"\x1f\x8b") and len(content) <= MAX_STICKER_DOCUMENT_BYTES:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as compressed:
                document = compressed.read(MAX_STICKER_DOCUMENT_BYTES + 1)
            if len(document) <= MAX_STICKER_DOCUMENT_BYTES:
                if _svg_root(document[:4096]):
                    return "svg"
                payload = json.loads(document)
                if isinstance(payload, dict) and (
                    "tgs" in payload or ("v" in payload and "layers" in payload)
                ):
                    return "tgs"
        except (OSError, ValueError, EOFError, RecursionError, zlib.error):
            pass

    suffix = fallback_name.rsplit(".", 1)[-1].lower() if "." in fallback_name else ""
    aliases = {"jpeg": "jpg", "svgz": "svg"}
    return aliases.get(suffix, suffix) if suffix in IMAGE_TYPES | {"jpeg", "svgz"} else "unknown"


def is_sticker_type(content: bytes, fallback_name: str = "") -> bool:
    return detect_file_type(content) in IMAGE_TYPES
