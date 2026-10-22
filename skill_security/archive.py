"""Stage one bounded ZIP package as inert bytes, including incomplete drafts.

Only stored and deflated ZIP32 members are supported. Nested archives remain
opaque files; they are never expanded. A single enclosing folder is removed
automatically only when it directly contains SKILL.md. Use package_root="."
to retain the archive root, or an explicit directory for an enveloped draft.
Selecting a root never silently discards files elsewhere in the archive.
"""

import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import struct
import unicodedata
import zipfile
import zlib

from .staging import MAX_DEPTH, MAX_FILE, MAX_FILES, MAX_PACKAGE, MAX_PATH_BYTES, _plain_path, _safe_path

MAX_ARCHIVE = MAX_PACKAGE + 16 * 1024 * 1024
MAX_ENTRIES = MAX_FILES * 2
MAX_CENTRAL_DIRECTORY = 16 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
RATIO_MINIMUM = 1024 * 1024
CHUNK = 64 * 1024
_WRAPPER = (b"---\nname: draft-package\ndescription: Draft skill package security scan.\n"
            b"---\n# Draft package\nInspect all supporting files.\n")


def _central_directory(data: bytes) -> tuple[int, int]:
    """Bound metadata before ZipFile allocates an object for every entry."""
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        raise ValueError("invalid-archive")
    _, disk, start_disk, disk_count, count, size, start, comment = struct.unpack_from("<4s4H2IH", data, end)
    if end + 22 + comment != len(data) or disk or start_disk or disk_count != count:
        raise ValueError("unsupported-archive-layout")
    if count == 65535 or size == 0xFFFFFFFF or start == 0xFFFFFFFF:
        raise ValueError("zip64-not-supported")
    if not count:
        raise ValueError("empty-package")
    if count > MAX_ENTRIES or size > MAX_CENTRAL_DIRECTORY:
        raise ValueError("archive-resource-limit")
    if start + size != end:
        raise ValueError("unsupported-archive-layout")
    cursor = start
    actual = 0
    while cursor < end:
        if cursor + 46 > end or data[cursor:cursor + 4] != b"PK\x01\x02":
            raise ValueError("invalid-archive")
        name, extra, comment_length = struct.unpack_from("<3H", data, cursor + 28)
        if name > MAX_PATH_BYTES or cursor + 46 + name + extra + comment_length > end:
            raise ValueError("archive-resource-limit")
        actual += 1
        if actual > MAX_ENTRIES:
            raise ValueError("archive-resource-limit")
        cursor += 46 + name + extra + comment_length
    if actual != count or cursor != end:
        raise ValueError("invalid-archive")
    return start, count


def _extra_fields(data: bytes) -> None:
    cursor = 0
    while cursor < len(data):
        if cursor + 4 > len(data):
            raise ValueError("invalid-archive")
        kind, length = struct.unpack_from("<2H", data, cursor)
        cursor += 4
        if kind == 1:
            raise ValueError("zip64-not-supported")
        if cursor + length > len(data):
            raise ValueError("invalid-archive")
        cursor += length


def _key(parts: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", unicodedata.normalize("NFC", part).casefold()) for part in parts)


def _members(infos: list[zipfile.ZipInfo]) -> list[tuple[zipfile.ZipInfo, PurePosixPath, bool]]:
    nodes = {}
    explicit = set()
    entries = []
    total = count = 0
    for info in infos:
        # orig_filename retains NULs that ZipInfo.filename otherwise truncates.
        name = info.orig_filename
        directory = name.endswith("/")
        path = _safe_path(name[:-1] if directory else name)
        if any(char in name for char in '<>"|?*'):
            raise ValueError("unsafe-file-path")
        if len(path.parts) > MAX_DEPTH:
            raise ValueError("unsafe-file-path")
        mode = info.external_attr >> 16
        kind = stat.S_IFMT(mode)
        allowed = {0, stat.S_IFDIR} if directory else {0, stat.S_IFREG}
        if kind not in allowed or (not directory and info.external_attr & 0x10) or info.external_attr & 0x408:
            raise ValueError("unsupported-link-or-special-file")
        if info.flag_bits & ~0x080E:
            raise ValueError("encrypted-or-unsupported-archive")
        if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED} or info.extract_version > 20:
            raise ValueError("unsupported-archive-compression")
        _extra_fields(info.extra)
        if info.volume:
            raise ValueError("unsupported-archive-layout")
        if directory and info.file_size:
            raise ValueError("nonempty-directory-member")
        if info.compress_type == zipfile.ZIP_STORED and info.file_size != info.compress_size:
            raise ValueError("archive-size-mismatch")
        if info.file_size >= RATIO_MINIMUM and info.file_size > MAX_COMPRESSION_RATIO * max(1, info.compress_size):
            raise ValueError("archive-expansion-limit")
        if not directory:
            count += 1
            total += info.file_size
            if count > MAX_FILES or info.file_size > MAX_FILE or total > MAX_PACKAGE:
                raise ValueError("package-resource-limit")
        for depth in range(1, len(path.parts) + 1):
            parts = path.parts[:depth]
            key = _key(parts)
            leaf = depth == len(path.parts)
            new_kind = "directory" if directory or not leaf else "file"
            prior = nodes.get(key)
            if prior is not None and (prior != (parts, "directory") or new_kind != "directory"):
                raise ValueError("duplicate-or-conflicting-archive-path")
            if leaf:
                if key in explicit:
                    raise ValueError("duplicate-or-conflicting-archive-path")
                explicit.add(key)
            nodes[key] = (parts, new_kind)
        entries.append((info, path, directory))
    if not count:
        raise ValueError("empty-package")
    return entries


def _ranges(data: bytes, entries: list, central: int) -> dict[int, tuple[int, int]]:
    """Validate local headers, descriptors and nonoverlapping member extents."""
    ranges = {}
    cursor = 0
    for info, _, _ in sorted(entries, key=lambda entry: entry[0].header_offset):
        offset = info.header_offset
        if offset != cursor or offset + 30 > central:
            raise ValueError("unsupported-archive-layout")
        signature, version, flags, method, _, _, crc, compressed, expanded, name_size, extra_size = struct.unpack_from("<4s5H3I2H", data, offset)
        start = offset + 30 + name_size + extra_size
        end = start + info.compress_size
        if signature != b"PK\x03\x04" or version > 20 or flags != info.flag_bits or method != info.compress_type or end > central:
            raise ValueError("invalid-archive")
        expected_name = info.orig_filename.encode("utf-8" if flags & 0x800 else "cp437")
        if data[offset + 30:offset + 30 + name_size] != expected_name:
            raise ValueError("archive-name-mismatch")
        _extra_fields(data[offset + 30 + name_size:start])
        expected = (info.CRC, info.compress_size, info.file_size)
        if flags & 8:
            if any(value not in {0, wanted} for value, wanted in zip((crc, compressed, expanded), expected)):
                raise ValueError("archive-size-mismatch")
            descriptor = end + (4 if data[end:end + 4] == b"PK\x07\x08" else 0)
            if descriptor + 12 > central or struct.unpack_from("<3I", data, descriptor) != expected:
                raise ValueError("invalid-archive-descriptor")
            cursor = descriptor + 12
        else:
            if (crc, compressed, expanded) != expected:
                raise ValueError("archive-size-mismatch")
            cursor = end
        ranges[offset] = (start, end)
    if cursor != central:
        raise ValueError("unsupported-archive-layout")
    return ranges


def _package_root(entries: list, requested: str | None) -> PurePosixPath:
    if requested is not None:
        root = PurePosixPath() if requested == "." else _safe_path(requested)
    else:
        top = entries[0][1].parts[0]
        enveloped = all(path.parts[0] == top for _, path, _ in entries)
        metadata = any(path.parts == (top, "SKILL.md") and not directory for _, path, directory in entries)
        root = PurePosixPath(top) if enveloped and metadata else PurePosixPath()
    for _, path, directory in entries:
        if not path.is_relative_to(root) and not (directory and root.is_relative_to(path)):
            raise ValueError("archive-files-outside-package-root")
    if not any(not directory and path != root and path.is_relative_to(root) for _, path, directory in entries):
        raise ValueError("empty-package")
    return root


def _chunks(data: bytes, info: zipfile.ZipInfo, bounds: tuple[int, int]):
    """Bound actual expansion, require an exact stream end, and verify CRC."""
    start, end = bounds
    decoder = zlib.decompressobj(-zlib.MAX_WBITS) if info.compress_type == zipfile.ZIP_DEFLATED else None
    size = crc = 0
    for cursor in range(start, end, CHUNK):
        compressed = data[cursor:min(cursor + CHUNK, end)]
        while compressed:
            try:
                chunk = decoder.decompress(compressed, CHUNK) if decoder else compressed
            except zlib.error:
                raise ValueError("invalid-archive-compression") from None
            compressed = decoder.unconsumed_tail if decoder else b""
            size += len(chunk)
            if size > info.file_size or size > MAX_FILE:
                raise ValueError("archive-size-mismatch")
            crc = zlib.crc32(chunk, crc)
            yield chunk
            if decoder and decoder.unused_data:
                raise ValueError("trailing-archive-member-data")
    if (decoder and not decoder.eof) or size != info.file_size or crc != info.CRC:
        raise ValueError("archive-size-or-crc-mismatch")


def stage_archive(archive: Path, target: Path, *, package_root: str | None = None) -> dict:
    """Create a new staging directory or remove only our partial one on error.

    sha256 covers sorted original paths, logical Git modes and original bytes,
    excluding the optional generated wrapper. paths contains original file
    paths only. archive_sha256 identifies the entire uploaded ZIP. No package
    instruction, permission bit, script, installer or nested archive is executed.
    The caller must supply an existing private parent directory for target.
    """
    try:
        return _stage_archive(archive, target, package_root=package_root)
    except (zipfile.BadZipFile, zlib.error, struct.error, UnicodeError, NotImplementedError):
        # Raw decoder errors can contain names or hostile bytes. Callers receive
        # a stable input failure, never an uncaught library diagnostic.
        raise ValueError("invalid-archive") from None


def _stage_archive(archive: Path, target: Path, *, package_root: str | None) -> dict:
    target = Path(target).absolute()
    _plain_path(target)
    if target.exists():
        raise FileExistsError("stage-destination-exists")
    archive = Path(archive).absolute()
    _plain_path(archive)
    if not stat.S_ISREG(archive.lstat().st_mode):
        raise ValueError("archive-is-not-regular-file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(archive, flags), "rb") as stream:
        source = os.fstat(stream.fileno())
        if not stat.S_ISREG(source.st_mode) or source.st_size > MAX_ARCHIVE:
            raise ValueError("archive-resource-limit")
        data = stream.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise ValueError("archive-resource-limit")
    central, count = _central_directory(data)
    with zipfile.ZipFile(io.BytesIO(data)) as bundle:
        infos = bundle.infolist()
        if len(infos) != count:
            raise ValueError("invalid-archive")
        entries = _members(infos)
        ranges = _ranges(data, entries, central)
    root = _package_root(entries, package_root)
    files = sorted(((info, path.relative_to(root)) for info, path, directory in entries if not directory),
                   key=lambda item: item[1].as_posix().encode("utf-8"))
    # Reserve the wrapper name on both case-sensitive and insensitive hosts.
    for _, path, directory in entries:
        if path.is_relative_to(root):
            relative = path.relative_to(root)
            if _key(relative.parts) == ("skill.md",) and (directory or relative.as_posix() != "SKILL.md"):
                raise ValueError("metadata-path-conflict")
    generated = not any(path.as_posix() == "SKILL.md" for _, path in files)
    digest = hashlib.sha256()
    total = 0
    _plain_path(target)
    target.mkdir(exist_ok=False)
    owned = target.stat()
    try:
        # Validate even empty directory streams; directory names are inert.
        for info, path, directory in entries:
            if directory:
                for _ in _chunks(data, info, ranges[info.header_offset]):
                    pass
                if path.is_relative_to(root):
                    destination = target.joinpath(*path.relative_to(root).parts)
                    _plain_path(destination)
                    destination.mkdir(parents=True, exist_ok=True)
        for info, relative in files:
            destination = target.joinpath(*relative.parts)
            _plain_path(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)
            mode = b"100755" if (info.external_attr >> 16) & 0o111 else b"100644"
            digest.update(relative.as_posix().encode("utf-8") + b"\0" + mode + b"\0")
            with destination.open("xb") as output:
                for chunk in _chunks(data, info, ranges[info.header_offset]):
                    output.write(chunk)
                    digest.update(chunk)
                    total += len(chunk)
                    if total > MAX_PACKAGE:
                        raise ValueError("package-resource-limit")
            digest.update(b"\0")
        if generated:
            with (target / "SKILL.md").open("xb") as output:
                output.write(_WRAPPER)
        return {"sha256": digest.hexdigest(), "archive_sha256": hashlib.sha256(data).hexdigest(),
                "files": len(files), "bytes": total, "metadata_generated": generated,
                "paths": [path.as_posix() for _, path in files], "package_root": root.as_posix()}
    except BaseException:
        current = target.lstat()
        if stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
            _plain_path(target)
            shutil.rmtree(target)
        raise
