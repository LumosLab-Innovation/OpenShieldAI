"""Read-only release exposure policy; never an anti-reversing or vulnerability verdict.

Original rules informed by REA 27dc42d's documented artifact/map reconstruction.
No REA code, runtime, target execution, URL retrieval or file modification is used.
"""

import hashlib
import html
import json
import os
import re
import stat
import time
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote


DEFAULT_LIMITS = {"files": 2048, "entries": 4096, "depth": 16,
                  "fileBytes": 8 * 1024 * 1024, "totalBytes": 64 * 1024 * 1024,
                  "seconds": 10, "observations": 256}
SOURCE_SUFFIXES = {".ts", ".tsx", ".jsx", ".vue", ".svelte", ".scss", ".sass",
                   ".less", ".py", ".rb", ".php", ".go", ".rs", ".java", ".cs", ".sql"}
TEXT_SUFFIXES = {".js", ".mjs", ".cjs", ".css", ".html", ".htm", ".json", ".map",
                 ".txt", ".xml", ".svg", ".webmanifest"} | SOURCE_SUFFIXES
TEXT_NAMES = {"license", "licence", "notice", "authors", "copying", "_headers", "_redirects"}
CONTAINERS = {".zip", ".gz", ".br", ".tgz", ".tar", ".7z", ".asar", ".wasm"}
CONTAINER_HEADERS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b",
                     b"\xfd7zXZ\0", b"BZh", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07",
                     b"\x28\xb5\x2f\xfd", b"\0asm")
BINARY_HEADERS = {".png": (b"\x89PNG\r\n\x1a\n",), ".jpg": (b"\xff\xd8\xff",),
                  ".jpeg": (b"\xff\xd8\xff",), ".gif": (b"GIF87a", b"GIF89a"),
                  ".ico": (b"\0\0\x01\0",), ".woff": (b"wOFF",), ".woff2": (b"wOF2",)}
DEV_NAMES = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
             "tsconfig.json", "vite.config.js", "vite.config.ts", "webpack.config.js",
             "dockerfile", "docker-compose.yml", "compose.yaml"}
PRAGMA = re.compile(r"^[#@]\s*sourceMappingURL\s*=\s*(\S+)", re.I)
LINE_END = re.compile(r"[\r\n\u2028\u2029]")
DATA_CODE = re.compile(r"data\s*:\s*(?:text|application)/(?:javascript|ecmascript|css)(?:[;,\s]|$)", re.I)
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\r\n]+"
                         rb"[A-Za-z0-9+/=\r\n]{32,}-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")


class _Gap(Exception):
    def __init__(self, code):
        self.code = code


class _InlineCode(HTMLParser):
    def __init__(self, gap):
        super().__init__(convert_charrefs=False)
        self.current = None
        self.code = []
        self.gap = gap

    def handle_starttag(self, tag, attrs):
        tag = tag.rsplit(":", 1)[-1]
        if tag in {"script", "iframe", "object", "embed"}:
            for name, value in attrs:
                reference = re.sub(r"[\t\r\n]", "", _decoded(value or "")).lstrip().lower()
                if value and (name == "srcdoc" or name.rsplit(":", 1)[-1] in {"src", "href", "data"}
                              and reference.startswith(("data:", "blob:", "javascript:"))):
                    self.gap("EMBEDDED_CODE_CARRIER_UNINSPECTED")
        if tag in {"script", "style"}:
            self.current = tag

    def handle_endtag(self, tag):
        if tag.rsplit(":", 1)[-1] == self.current:
            self.current = None

    def handle_data(self, data):
        if self.current:
            self.code.append((data, self.current == "style"))

    def unknown_decl(self, data):
        if self.current:
            self.gap("EMBEDDED_CODE_CARRIER_UNINSPECTED")


def _decoded(value):
    for _ in range(3):
        decoded = html.unescape(unquote(value))
        if decoded == value:
            break
        value = decoded
    return value


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _linked(value):
    return stat.S_ISLNK(value.st_mode) or bool(getattr(value, "st_file_attributes", 0) & 0x400)


def _comments(text, tick, gap, css=False):
    """Bounded lexical approximation; not a JavaScript parser (see limitations)."""
    position, length = 0, len(text)
    has_candidate = "sourcemappingurl" in text.lower()
    ambiguous = False
    if not css and has_candidate and "`" in text and "${" in text:
        gap("JAVASCRIPT_COMMENT_COVERAGE_PARTIAL")
        ambiguous = True
    while position < length:
        if position % 4096 == 0:
            tick()
        character = text[position]
        if character in "'\"`":
            quote = character
            position += 1
            while position < length:
                if position % 4096 == 0:
                    tick()
                if text[position] == "\\":
                    position += 2
                elif text[position] == quote:
                    position += 1
                    break
                else:
                    position += 1
        elif text.startswith("/*", position):
            end = text.find("*/", position + 2)
            yield text[position + 2:end if end >= 0 else length].strip()
            position = length if end < 0 else end + 2
        elif not css and text.startswith("//", position):
            end = LINE_END.search(text, position + 2)
            yield text[position + 2:end.start() if end else length].strip()
            position = end.end() if end else length
        else:
            # shortcut: regex/division grammar is not parsed; candidate maps fail closed.
            if not css and has_candidate and character == "/" and not ambiguous:
                gap("JAVASCRIPT_COMMENT_COVERAGE_PARTIAL")
                ambiguous = True
            position += 1


def _rules(relative, data, tick, gap):
    name = _decoded(relative.name).lower()
    suffix = Path(name).suffix
    parts = [_decoded(part).lower() for part in relative.parts]
    codes = set()
    if name == ".env" or name.startswith(".env.") or name in {".npmrc", ".netrc", "credentials.json"}:
        codes.add("ENVIRONMENT_ARTIFACT")
    if suffix in {".key", ".p12", ".pfx", ".keystore"}:
        codes.add("PRIVATE_KEY_ARTIFACT")
    if PRIVATE_KEY.search(data):
        codes.add("PRIVATE_KEY_MATERIAL")
    if name.endswith((".bak", ".backup", ".old", ".orig", ".swp", "~")) or suffix in {".sqlite", ".sqlite3", ".db"}:
        codes.add("BACKUP_OR_DATABASE_ARTIFACT")
    if suffix in SOURCE_SUFFIXES:
        codes.add("SOURCE_ARTIFACT")
    if name in DEV_NAMES or any(part in {".git", ".svn", ".hg", ".vscode", "__tests__", "test-results", "coverage"} for part in parts):
        codes.add("DEVELOPMENT_ARTIFACT")
    if suffix in CONTAINERS or data.startswith(CONTAINER_HEADERS) or data[257:262] == b"ustar":
        gap("UNINSPECTED_CONTAINER")
        return codes, False
    if suffix not in TEXT_SUFFIXES and name not in TEXT_NAMES:
        if suffix in BINARY_HEADERS and data.startswith(BINARY_HEADERS[suffix]):
            return codes, False
        if suffix == ".webp" and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            return codes, False
        gap("UNINSPECTED_FILE_TYPE")
        return codes, False
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        gap("TEXT_ENCODING_UNSUPPORTED")
        return codes, False
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
        gap("TEXT_CONTAINS_BINARY_CONTROL")
        return codes, False
    tick()
    if suffix in {".map", ".json", ".webmanifest"} or text.lstrip().startswith("{"):
        try:
            value = json.loads(text)
            if isinstance(value, dict) and value.get("version") == 3 and (
                    isinstance(value.get("sources"), list) or isinstance(value.get("sections"), list)):
                codes.add("SOURCE_MAP_FILE")
                if isinstance(value.get("sourcesContent"), list) and any(isinstance(item, str) and item for item in value["sourcesContent"]):
                    codes.add("SOURCE_MAP_ORIGINAL_CONTENT")
        except (ValueError, RecursionError):
            if suffix in {".map", ".json", ".webmanifest"}:
                gap("SOURCE_MAP_UNPARSEABLE" if suffix == ".map" else "JSON_UNPARSEABLE")
    sources = [(text, suffix == ".css")] if suffix in {".js", ".mjs", ".cjs", ".css"} else []
    if suffix in {".html", ".htm", ".svg", ".xml"}:
        parser = _InlineCode(gap)
        parser.feed(text)
        sources = parser.code
    for source, css in sources:
        if DATA_CODE.search(_decoded(source)):
            gap("EMBEDDED_CODE_CARRIER_UNINSPECTED")
        for comment in _comments(source, tick, gap, css=css):
            match = PRAGMA.match(comment)
            if match:
                reference = _decoded(match.group(1)).lower()
                codes.add("INLINE_SOURCE_MAP" if reference.startswith("data:") else "SOURCE_MAP_REFERENCE")
    return codes, True


def exposure_audit(path, authorized=False, limits=None):
    """Audit an owner-authorized, stable local web release directory without writing.

    ``limits`` can only reduce DEFAULT_LIMITS. ``pass`` means this bounded policy
    found no matching exposure and no gaps; it never means unreconstructable.
    """
    selected = dict(DEFAULT_LIMITS)
    result = {"schemaVersion": "release_exposure_v1", "status": "blocked", "complete": False,
              "artifactSha256": None, "counts": {"entries": 0, "files": 0, "bytes": 0,
              "inspectedTextFiles": 0, "observations": 0, "gaps": 0,
              "observationDetailsOmitted": 0, "gapDetailsOmitted": 0}, "categories": [],
              "observations": [], "gaps": [], "limits": selected,
              "targetCodeExecuted": False, "networkRequestsMade": False, "isFinding": False,
              "limitations": ["PASS_IS_ONLY_THIS_RELEASE_POLICY",
                              "NO_RUNTIME_OR_HTTP_HEADER_INSPECTION",
                              "NO_GENERAL_SECRET_OR_PII_DETECTION",
                              "BINARY_ASSETS_HEADER_CHECK_ONLY",
                              "LEXICAL_COMMENTS_NOT_FULL_JAVASCRIPT_GRAMMAR",
                              "STABLE_COPY_REQUIRED_NO_OS_SANDBOX",
                              "DEADLINE_COOPERATIVE_OS_IO_CAN_BLOCK",
                              "OPAQUE_DIGESTS_ARE_NOT_AUTHENTICITY"]}
    categories = Counter()

    def gap(code, file_id=None):
        result["counts"]["gaps"] += 1
        if len(result["gaps"]) < selected["observations"]:
            result["gaps"].append({"code": code, **({"fileId": file_id} if file_id else {})})
        else:
            result["counts"]["gapDetailsOmitted"] += 1

    if authorized is not True:
        gap("AUTHORIZATION_REQUIRED")
        return result
    if limits is not None:
        if not isinstance(limits, dict) or any(key not in selected or isinstance(value, bool)
                or not isinstance(value, (int, float)) or not 0 < value <= selected[key]
                or (key != "seconds" and not isinstance(value, int)) for key, value in limits.items()):
            gap("LIMITS_INVALID")
            return result
        selected.update(limits)
    started = time.monotonic()

    def tick():
        if time.monotonic() - started >= selected["seconds"]:
            raise _Gap("DEADLINE_EXCEEDED")

    snapshots, manifest = [], []

    def safe(pathname):
        value = pathname.lstat()
        if _linked(value) or os.path.normcase(os.path.realpath(pathname)) != os.path.normcase(str(pathname)):
            raise _Gap("LINK_OR_ALIAS_NOT_ALLOWED")
        return value

    def read(pathname, before):
        if before.st_nlink != 1:
            raise _Gap("HARDLINK_NOT_ALLOWED")
        if before.st_size > selected["fileBytes"]:
            raise _Gap("FILE_BYTES_LIMIT")
        if result["counts"]["bytes"] + before.st_size > selected["totalBytes"]:
            raise _Gap("TOTAL_BYTES_LIMIT")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(pathname, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
                raise _Gap("INPUT_CHANGED")
            data = bytearray()
            while len(data) <= before.st_size:
                tick()
                part = os.read(descriptor, min(65536, before.st_size + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            if len(data) != before.st_size or _identity(opened) != _identity(os.fstat(descriptor)):
                raise _Gap("INPUT_CHANGED")
            return bytes(data)
        finally:
            os.close(descriptor)

    def walk(directory, depth):
        tick()
        if depth > selected["depth"]:
            raise _Gap("DIRECTORY_DEPTH_LIMIT")
        before = safe(directory)
        if not stat.S_ISDIR(before.st_mode):
            raise _Gap("DIRECTORY_REQUIRED")
        snapshots.append((directory, _identity(before)))
        with os.scandir(directory) as entries:
            for entry in entries:
                tick()
                result["counts"]["entries"] += 1
                if result["counts"]["entries"] > selected["entries"]:
                    raise _Gap("ENTRY_COUNT_LIMIT")
                child = directory / entry.name
                relative = child.relative_to(root)
                file_id = "file_" + hashlib.sha256(relative.as_posix().encode("utf-8", errors="surrogatepass")).hexdigest()[:24]
                try:
                    before_child = safe(child)
                    if stat.S_ISDIR(before_child.st_mode):
                        walk(child, depth + 1)
                        continue
                    if not stat.S_ISREG(before_child.st_mode):
                        raise _Gap("NONREGULAR_FILE_NOT_ALLOWED")
                    if result["counts"]["files"] >= selected["files"]:
                        raise _Gap("FILE_COUNT_LIMIT")
                    data = read(child, before_child)
                    digest = hashlib.sha256(data).hexdigest()
                    result["counts"]["files"] += 1
                    result["counts"]["bytes"] += len(data)
                    snapshots.append((child, _identity(before_child)))
                    manifest.append((relative.as_posix(), digest))
                    codes, inspected = _rules(relative, data, tick, lambda code: gap(code, file_id))
                    result["counts"]["inspectedTextFiles"] += int(inspected)
                    for code in sorted(codes):
                        categories[code] += 1
                        result["counts"]["observations"] += 1
                        if len(result["observations"]) < selected["observations"]:
                            result["observations"].append({"code": code, "fileId": file_id, "sha256": digest})
                        else:
                            result["counts"]["observationDetailsOmitted"] += 1
                except _Gap as error:
                    if error.code in {"DEADLINE_EXCEEDED", "FILE_COUNT_LIMIT", "ENTRY_COUNT_LIMIT", "TOTAL_BYTES_LIMIT"}:
                        raise
                    gap(error.code, file_id)
                except (OSError, ValueError):
                    gap("INPUT_UNREADABLE_OR_UNSAFE", file_id)

    try:
        value = os.fspath(path)
        if not isinstance(value, str) or not value.strip() or "\0" in value or value.startswith(("\\\\", "//")) or re.match(r"^[a-z][a-z\d+.-]*:", value, re.I) and not re.match(r"^[a-z]:[\\/]", value, re.I):
            raise _Gap("LOCAL_DIRECTORY_REQUIRED")
        root = Path(os.path.abspath(value))
        walk(root, 0)
        if not result["counts"]["files"]:
            gap("EMPTY_RELEASE")
        for pathname, identity in snapshots:
            tick()
            if _identity(safe(pathname)) != identity:
                raise _Gap("INPUT_CHANGED")
        if not result["counts"]["gaps"]:
            digest = hashlib.sha256()
            for name, content_digest in sorted(manifest):
                digest.update(name.encode("utf-8", errors="surrogatepass") + b"\0" + content_digest.encode("ascii") + b"\0")
            result["artifactSha256"] = digest.hexdigest()
            result["complete"] = True
    except _Gap as error:
        gap(error.code)
    except (OSError, ValueError, TypeError):
        gap("INPUT_UNREADABLE_OR_UNSAFE")
    result["categories"] = [{"code": code, "count": count} for code, count in sorted(categories.items())]
    result["status"] = "blocked" if result["counts"]["observations"] else "pass" if result["complete"] else "partial"
    return result
