"""ZIP submissions are data, including malformed drafts and hostile containers."""

import hashlib
import io
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

from skill_security import archive


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.source = self.base / "upload.zip"
        self.target = self.base / "package"

    def bundle(self, entries, compression=zipfile.ZIP_DEFLATED):
        with warnings.catch_warnings(), zipfile.ZipFile(self.source, "w", compression=compression) as bundle:
            warnings.simplefilter("ignore", UserWarning)
            for name, content in entries:
                bundle.writestr(name, content)
        return self.source

    def stage(self, **kwargs):
        return archive.stage_archive(self.source, self.target, **kwargs)

    def rejected(self, code=None, **kwargs):
        with self.assertRaisesRegex(ValueError, code or ".+"):
            self.stage(**kwargs)
        self.assertFalse(self.target.exists(), "Failed staging must remove its partial directory")

    def mutate_headers(self, local_offset, central_offset, fmt, value):
        data = bytearray(self.source.read_bytes())
        central = data.index(b"PK\x01\x02")
        struct.pack_into(fmt, data, local_offset, value)
        struct.pack_into(fmt, data, central + central_offset, value)
        self.source.write_bytes(data)

    def test_full_package_preserves_original_bytes_and_never_executes_scripts(self):
        marker = self.base / "executed"
        skill = b"---\nname: [ unfinished\r\n\xff\x00"
        script = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n".encode()
        self.bundle([("SKILL.md", skill), ("scripts/setup.py", script), ("evals/cases.json", b"[]")])
        result = self.stage()
        self.assertEqual((self.target / "SKILL.md").read_bytes(), skill)
        self.assertEqual((self.target / "scripts/setup.py").read_bytes(), script)
        self.assertFalse(marker.exists())
        self.assertFalse(result["metadata_generated"])
        self.assertEqual(result["files"], 3)
        self.assertEqual(result["bytes"], len(skill) + len(script) + 2)
        self.assertEqual(result["paths"], ["SKILL.md", "evals/cases.json", "scripts/setup.py"])
        self.assertEqual(result["package_root"], ".")
        self.assertEqual(result["archive_sha256"], hashlib.sha256(self.source.read_bytes()).hexdigest())

    def test_single_envelope_with_metadata_is_unwrapped(self):
        self.bundle([("my-skill/", b""), ("my-skill/SKILL.md", b"draft"), ("my-skill/references/data.bin", b"\x00\xff")])
        result = self.stage()
        self.assertEqual(result["package_root"], "my-skill")
        self.assertEqual(result["paths"], ["SKILL.md", "references/data.bin"])
        self.assertFalse((self.target / "my-skill").exists())

    def test_scripts_only_draft_keeps_its_folder_and_gets_temporary_metadata(self):
        self.bundle([("scripts/tool.py", b"# draft\r\n")])
        result = self.stage()
        self.assertTrue(result["metadata_generated"])
        self.assertEqual(result["package_root"], ".")
        self.assertEqual(result["paths"], ["scripts/tool.py"])
        self.assertEqual((self.target / "scripts/tool.py").read_bytes(), b"# draft\r\n")
        self.assertEqual((self.target / "SKILL.md").read_bytes(), archive._WRAPPER)
        self.assertEqual(result["bytes"], 9)

    def test_explicit_root_unwraps_an_incomplete_draft(self):
        self.bundle([("outer/", b""), ("outer/draft/", b""), ("outer/draft/scripts/a.py", b"pass")])
        result = self.stage(package_root="outer/draft")
        self.assertEqual(result["package_root"], "outer/draft")
        self.assertEqual(result["paths"], ["scripts/a.py"])
        self.assertTrue(result["metadata_generated"])

    def test_explicit_dot_keeps_an_enclosing_folder(self):
        self.bundle([("wrapped/SKILL.md", b"draft")])
        result = self.stage(package_root=".")
        self.assertTrue(result["metadata_generated"])
        self.assertEqual((self.target / "wrapped/SKILL.md").read_bytes(), b"draft")

    def test_root_selection_never_drops_outside_files(self):
        self.bundle([("draft/SKILL.md", b"draft"), ("outside.txt", b"must be scanned too")])
        self.rejected("archive-files-outside-package-root", package_root="draft")
        result = self.stage()
        self.assertEqual(result["paths"], ["draft/SKILL.md", "outside.txt"])

    def test_content_digest_ignores_archive_order_compression_and_envelope(self):
        entries = [("SKILL.md", b"draft\r\n"), ("scripts/a.py", b"print('inert')\n")]
        self.bundle(entries, zipfile.ZIP_STORED)
        first = self.stage()
        self.target = self.base / "other"
        self.bundle([("wrapped/" + name, body) for name, body in reversed(entries)])
        second = self.stage()
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertNotEqual(first["archive_sha256"], second["archive_sha256"])
        digest = hashlib.sha256()
        for name, body in entries:
            digest.update(name.encode() + b"\0" + b"100644\0" + body + b"\0")
        self.assertEqual(first["sha256"], digest.hexdigest())

    def test_executable_bit_changes_logical_digest_but_not_file_execution(self):
        info = zipfile.ZipInfo("script.py")
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o755) << 16
        self.bundle([(info, b"# inert")])
        result = self.stage()
        self.assertEqual(result["sha256"], hashlib.sha256(b"script.py\0" + b"100755\0# inert\0").hexdigest())

    def test_nested_archive_is_preserved_opaque_and_not_unpacked(self):
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as package:
            package.writestr("../escape.txt", "never expand nested bytes")
        self.bundle([("data/fixture.zip", nested.getvalue())])
        result = self.stage()
        self.assertEqual((self.target / "data/fixture.zip").read_bytes(), nested.getvalue())
        self.assertEqual(result["files"], 1)
        self.assertFalse((self.base / "escape.txt").exists())

    def test_path_attacks_are_rejected(self):
        names = ("../escape", "/absolute", "C:/drive", "C:\\drive", "a\\b", "a//b", "a/./b", "a/../b",
                 "a/.GIT/config", "a/CON.txt", "a/space ", "a/dot.", "a/stream:secret", "a/line\nbreak",
                 "a/question?", "a/pipe|", "a/*", "a/quote\"", "a/" + "x" * 256, "/")
        for index, name in enumerate(names):
            with self.subTest(name=name):
                self.target = self.base / f"package-{index}"
                # Windows ZipInfo writers normalize backslashes; mutate the
                # encoded headers to exercise the actual hostile input bytes.
                written = name.replace("\\", "X")
                self.bundle([(written, b"data")])
                if written != name:
                    self.source.write_bytes(self.source.read_bytes().replace(written.encode(), name.encode()))
                self.rejected()

    def test_embedded_nul_filename_is_rejected_without_truncation(self):
        self.bundle([("evilX.txt", b"data")], zipfile.ZIP_STORED)
        self.source.write_bytes(self.source.read_bytes().replace(b"evilX.txt", b"evil\x00.txt"))
        self.rejected("unsafe-file-path")

    def test_deep_paths_and_oversized_encoded_paths_are_rejected(self):
        self.bundle([("/".join(["a"] * 65), b"data")])
        self.rejected("unsafe-file-path")
        self.bundle([("/".join(["a" * 250] * 20), b"data")])
        self.rejected("archive-resource-limit")

    def test_duplicate_equivalent_and_prefix_collisions_are_rejected(self):
        pairs = (("same", "same"), ("A.txt", "a.txt"), ("caf\u00e9.txt", "cafe\u0301.txt"),
                 ("STRA\u1e9eE.txt", "strasse.txt"), ("a", "a/b"), ("a/b", "a"),
                 ("A/x", "a/y"), ("a/", "a/"), ("a/", "a"), ("a", "a/"))
        for first, second in pairs:
            with self.subTest(first=first, second=second):
                self.bundle([(first, b"" if first.endswith("/") else b"one"),
                             (second, b"" if second.endswith("/") else b"two")])
                self.rejected("duplicate-or-conflicting-archive-path")

    def test_explicit_directory_after_child_is_allowed(self):
        self.bundle([("scripts/a.py", b"draft"), ("scripts/", b"")])
        result = self.stage()
        self.assertEqual(result["paths"], ["scripts/a.py"])

    def test_special_files_symlinks_and_directory_mismatches_are_rejected(self):
        for kind in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFDIR):
            with self.subTest(kind=kind):
                info = zipfile.ZipInfo("unsafe")
                info.create_system = 3
                info.external_attr = (kind | 0o777) << 16
                self.bundle([(info, b"../../outside")])
                self.rejected("unsupported-link-or-special-file")
        info = zipfile.ZipInfo("not-a-directory/")
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        self.bundle([(info, b""), ("notes", b"draft")])
        self.rejected("unsupported-link-or-special-file")

    def test_metadata_name_conflicts_are_rejected(self):
        for name in ("skill.md", "SKILL.md/", "Skill.Md/"):
            with self.subTest(name=name):
                self.bundle([(name, b"" if name.endswith("/") else b"draft"), ("notes", b"other")])
                self.rejected("metadata-path-conflict")

    def test_nonempty_directory_member_is_rejected(self):
        self.bundle([("folder/", b"hidden content"), ("notes", b"draft")])
        self.rejected("nonempty-directory-member")

    def test_file_total_and_count_limits_are_enforced_before_extraction(self):
        self.bundle([("a", b"1234"), ("b", b"5678")])
        for constant, value in (("MAX_FILE", 3), ("MAX_PACKAGE", 7), ("MAX_FILES", 1), ("MAX_ENTRIES", 1), ("MAX_ARCHIVE", 1), ("MAX_CENTRAL_DIRECTORY", 1)):
            with self.subTest(constant=constant), patch.object(archive, constant, value):
                self.rejected("resource-limit")

    def test_high_compression_ratio_is_rejected(self):
        self.bundle([("zeros", b"0" * (1024 * 1024))])
        self.rejected("archive-expansion-limit")

    def test_regular_large_deflate_stream_expands_fully_in_bounded_chunks(self):
        body = bytes(range(256)) * 4096
        self.bundle([("binary", body)])
        with patch.object(archive, "MAX_COMPRESSION_RATIO", 2000):
            result = self.stage()
        self.assertEqual((self.target / "binary").read_bytes(), body)
        self.assertEqual(result["bytes"], len(body))

    def test_encryption_flags_and_unsupported_compression_are_rejected(self):
        for flag in (1, 0x40, 0x2000, 0x20):
            with self.subTest(flag=flag):
                self.bundle([("notes", b"draft")])
                self.mutate_headers(6, 8, "<H", flag)
                self.rejected("encrypted-or-unsupported-archive")
        for compression in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            with self.subTest(compression=compression):
                self.bundle([("notes", b"draft")], compression)
                self.rejected("unsupported-archive-compression")

    def test_zip64_headers_are_rejected(self):
        with zipfile.ZipFile(self.source, "w") as package:
            with package.open("notes", "w", force_zip64=True) as output:
                output.write(b"draft")
        self.rejected()

    def test_corrupt_crc_cleans_up_previously_extracted_members(self):
        self.bundle([("a-first", b"keep only on success"), ("z-last", b"corrupt me")], zipfile.ZIP_STORED)
        data = self.source.read_bytes()
        self.source.write_bytes(data.replace(b"corrupt me", b"corrupt XX"))
        self.rejected("archive-size-or-crc-mismatch")

    def test_forged_deflate_size_cannot_silently_truncate_original_content(self):
        self.bundle([("notes", b"original content is longer")])
        self.mutate_headers(22, 24, "<I", 2)
        self.rejected("archive-size-mismatch")

    def test_corrupt_deflate_produces_a_fixed_input_error_and_cleans_up(self):
        self.bundle([("notes", b"draft")])
        data = bytearray(self.source.read_bytes())
        name_size, extra_size = struct.unpack_from("<2H", data, 26)
        payload = 30 + name_size + extra_size
        # DEFLATE block type 3 is reserved and must fail decompression.
        data[payload] = (data[payload] & ~0x06) | 0x06
        self.source.write_bytes(data)
        self.rejected("^invalid-archive-compression$")

    def test_parser_library_errors_are_translated_to_fixed_input_error(self):
        self.bundle([("notes", b"draft")])
        with patch.object(archive, "_central_directory", side_effect=struct.error("private raw bytes")):
            self.rejected("^invalid-archive$")

    def test_local_and_central_header_mismatch_is_rejected(self):
        self.bundle([("notes", b"draft")])
        data = bytearray(self.source.read_bytes())
        struct.pack_into("<I", data, 22, 1)
        self.source.write_bytes(data)
        self.rejected("archive-size-mismatch")

    def test_truncated_deflate_stream_is_not_accepted_as_complete(self):
        self.bundle([("notes", b"draft content")])
        data = bytearray(self.source.read_bytes())
        central = data.index(b"PK\x01\x02")
        compressed_size = struct.unpack_from("<I", data, 18)[0]
        del data[central - 1]
        central -= 1
        struct.pack_into("<I", data, 18, compressed_size - 1)
        struct.pack_into("<I", data, central + 20, compressed_size - 1)
        end = data.rindex(b"PK\x05\x06")
        struct.pack_into("<I", data, end + 16, central)
        self.source.write_bytes(data)
        self.rejected("archive-size-or-crc-mismatch")

    def test_overlapping_member_offsets_are_rejected(self):
        self.bundle([("first", b"draft"), ("second", b"other")])
        data = bytearray(self.source.read_bytes())
        first = data.index(b"PK\x01\x02")
        second = data.index(b"PK\x01\x02", first + 4)
        struct.pack_into("<I", data, second + 42, 0)
        self.source.write_bytes(data)
        self.rejected("unsupported-archive-layout")

    def test_local_and_central_file_names_must_match(self):
        self.bundle([("notes", b"draft")])
        data = bytearray(self.source.read_bytes())
        data[30:35] = b"other"
        self.source.write_bytes(data)
        self.rejected("archive-name-mismatch")

    def test_actual_metadata_count_is_checked_before_zipfile(self):
        self.bundle([("a", b"draft"), ("b", b"draft")])
        data = bytearray(self.source.read_bytes())
        end = data.rindex(b"PK\x05\x06")
        struct.pack_into("<2H", data, end + 8, 1, 1)
        self.source.write_bytes(data)
        with patch.object(archive.zipfile, "ZipFile") as reader:
            self.rejected("invalid-archive")
            reader.assert_not_called()

    def test_multidisk_and_prepended_or_appended_bytes_are_rejected(self):
        self.bundle([("notes", b"draft")])
        original = self.source.read_bytes()
        for data in (b"executable prefix" + original, original + b"extra bytes"):
            self.source.write_bytes(data)
            self.rejected()
        data = bytearray(original)
        end = data.rindex(b"PK\x05\x06")
        struct.pack_into("<H", data, end + 4, 1)
        self.source.write_bytes(data)
        self.rejected("unsupported-archive-layout")

    def test_valid_streamed_zip_with_data_descriptors_is_supported(self):
        class Unseekable(io.BytesIO):
            def seekable(self):
                return False

            def seek(self, *args):
                raise OSError("unseekable")

        output = Unseekable()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as package:
            package.writestr("SKILL.md", b"draft")
            package.writestr("scripts/a.py", b"# inert")
        self.source.write_bytes(output.getvalue())
        result = self.stage()
        self.assertEqual(result["files"], 2)
        self.assertEqual((self.target / "SKILL.md").read_bytes(), b"draft")

    def test_empty_or_invalid_archive_and_directory_only_archive_are_rejected(self):
        for data in (b"", b"not a zip"):
            self.source.write_bytes(data)
            self.rejected()
        for entries in ([], [("folder/", b"")]):
            self.bundle(entries)
            self.rejected("empty-package")

    def test_preexisting_destination_is_never_deleted_or_changed(self):
        self.bundle([("SKILL.md", b"new")])
        self.target.mkdir()
        (self.target / "SKILL.md").write_bytes(b"original")
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual((self.target / "SKILL.md").read_bytes(), b"original")

    def test_write_failure_removes_only_the_owned_stage(self):
        self.bundle([("notes", b"draft")])
        sentinel = self.base / "keep.txt"
        sentinel.write_bytes(b"keep")
        original = Path.open

        def fail_wrapper(path, *args, **kwargs):
            if path == self.target / "SKILL.md":
                raise OSError("simulated disk failure")
            return original(path, *args, **kwargs)

        with patch.object(Path, "open", fail_wrapper), self.assertRaisesRegex(OSError, "simulated disk failure"):
            self.stage()
        self.assertFalse(self.target.exists())
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_linked_destination_parent_is_rejected(self):
        self.bundle([("notes", b"draft")])
        outside = self.base / "outside"
        outside.mkdir()
        link = self.base / "linked"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("Symlink creation is unavailable on this host")
        with self.assertRaisesRegex(ValueError, "linked-stage-destination"):
            archive.stage_archive(self.source, link / "package")
        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
