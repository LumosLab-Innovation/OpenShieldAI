"""Synthetic release-policy controls; no third-party target code or secrets."""

import contextlib
import base64
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from openshield import exposure


MAP = json.dumps({"version": 3, "sources": ["private-module.ts"],
                  "sourcesContent": ["SYNTHETIC_ORIGINAL_CONTENT"], "mappings": ""})


class ExposurePolicy(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return path

    def audit(self, **kwargs):
        return exposure.exposure_audit(self.root, authorized=True, **kwargs)

    def codes(self, result):
        return {value["code"] for value in result["categories"]}

    def test_complete_public_release_and_notices_pass_without_execution_or_mutation(self):
        code = 'globalThis.releaseLoaded=true; throw Error("Do not execute this artifact");'
        self.write("app.js", code)
        self.write("index.html", '<script src="app.js"></script>')
        self.write("LICENSE", "Synthetic permission and copyright notice, preserve this file.")
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            result = self.audit()
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["complete"])
        self.assertRegex(result["artifactSha256"], "^[a-f0-9]{64}$")
        self.assertFalse(result["targetCodeExecuted"])
        self.assertFalse(result["networkRequestsMade"])
        self.assertFalse(result["isFinding"])
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_requires_literal_authorization_before_any_filesystem_access(self):
        with patch.object(Path, "lstat", side_effect=AssertionError("must not inspect")):
            for value in (False, None, 1, "true"):
                result = exposure.exposure_audit(self.root, authorized=value)
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["gaps"], [{"code": "AUTHORIZATION_REQUIRED"}])

    def test_orphan_maps_and_encoded_filename_and_json_alias_are_detected(self):
        for name in ("orphan.js.map", "alias.json", "encoded.js%2emap", "aliased.txt"):
            with self.subTest(name=name):
                path = self.write(name, MAP)
                result = self.audit()
                self.assertEqual(result["status"], "blocked")
                self.assertTrue({"SOURCE_MAP_FILE", "SOURCE_MAP_ORIGINAL_CONTENT"} <= self.codes(result))
                path.unlink()

    def test_inline_and_external_maps_in_script_css_and_html(self):
        samples = [("app.js", "//# sourceMappingURL=data:application/json;base64,e30=", "INLINE_SOURCE_MAP"),
                   ("app.js", "//# sourceMappingURL=data%3Aapplication%2Fjson%3Be30=", "INLINE_SOURCE_MAP"),
                   ("style.css", "/*# sourceMappingURL=https://invalid.example/private.map */", "SOURCE_MAP_REFERENCE"),
                   ("app.js", "//# sourceMappingURL=blob:opaque-value", "SOURCE_MAP_REFERENCE"),
                   ("app.js", "//# sourceMappingURL=../outside%2emap?token=SYNTHETIC_ONLY", "SOURCE_MAP_REFERENCE"),
                   ("index.html", "<script>//# sourceMappingURL=data:application/json,e30=\n</script>", "INLINE_SOURCE_MAP"),
                   ("index.html", "<style>/*# sourceMappingURL=style.map */</style>", "SOURCE_MAP_REFERENCE")]
        for name, content, code in samples:
            with self.subTest(content=content):
                path = self.write(name, content)
                self.assertIn(code, self.codes(self.audit()))
                path.unlink()

    def test_map_looking_string_literals_public_endpoints_and_geographic_map_are_benign(self):
        self.write("app.js", '''const a="//# sourceMappingURL=not-a-declaration";
const b='/*# sourceMappingURL=not-a-declaration */';
const c=`//# sourceMappingURL=also-a-string`;
fetch("/api/public-prices");''')
        self.write("map.json", '{"type":"FeatureCollection","features":[]}')
        self.write("geography.map", '{"projection":"Mercator"}')
        result = self.audit()
        self.assertEqual(result["status"], "pass")
        self.assertFalse(self.codes(result))

    def test_explicit_sensitive_source_backup_and_dev_artifacts_are_policy_failures(self):
        self.write(".env.production", "SYNTHETIC_SECRET=not-real")
        self.write("private.py", "SYNTHETIC_PRIVATE_FUNCTION = 1")
        self.write("app.js.bak", "SYNTHETIC_BACKUP")
        self.write(".git/config", "SYNTHETIC_CONFIG")
        self.write("bundle.txt", b"-----BEGIN PRIVATE KEY-----\n" + b"A" * 64 + b"\n-----END PRIVATE KEY-----")
        result = self.audit()
        self.assertTrue({"ENVIRONMENT_ARTIFACT", "SOURCE_ARTIFACT", "BACKUP_OR_DATABASE_ARTIFACT",
                         "DEVELOPMENT_ARTIFACT", "PRIVATE_KEY_MATERIAL"} <= self.codes(result))
        output = json.dumps(result)
        for value in (".env.production", "private.py", "SYNTHETIC_SECRET", "not-real", "SYNTHETIC_BACKUP", str(self.root)):
            self.assertNotIn(value, output)

    def test_private_key_words_and_certificate_header_are_not_key_material(self):
        self.write("help.txt", "The term PRIVATE KEY is not a key.\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")
        self.write("app.js", 'const header="-----BEGIN PRIVATE KEY-----";')
        self.assertEqual(self.audit()["status"], "pass")

    def test_ambiguous_regex_or_template_cannot_hide_candidate_map_with_a_pass(self):
        samples = ['const rx=/"/;\n//# sourceMappingURL=data:application/json,e30=',
                   'const t=`${1 /*# sourceMappingURL=secret.map */}`;']
        for source in samples:
            with self.subTest(source=source):
                self.write("app.js", source)
                result = self.audit()
                self.assertNotEqual(result["status"], "pass")
                self.assertIn("JAVASCRIPT_COMMENT_COVERAGE_PARTIAL", {gap["code"] for gap in result["gaps"]})

    def test_all_javascript_line_terminators_end_an_ordinary_comment(self):
        for terminator in ("\n", "\r", "\r\n", "\u2028", "\u2029"):
            with self.subTest(terminator=repr(terminator)):
                self.write("app.js", "// ordinary comment" + terminator + "//# sourceMappingURL=data:application/json,e30=")
                self.assertIn("INLINE_SOURCE_MAP", self.codes(self.audit()))

    def test_svg_inline_script_and_styles_are_checked(self):
        for source in ('<svg xmlns="http://www.w3.org/2000/svg"><script>//# sourceMappingURL=data:application/json,e30=\n</script></svg>',
                       '<svg:svg><svg:script>//# sourceMappingURL=data:application/json,e30=\n</svg:script></svg:svg>',
                       '<svg><style>/*# sourceMappingURL=data:application/json,e30= */</style></svg>'):
            with self.subTest(source=source):
                self.write("image.svg", source)
                self.assertIn("INLINE_SOURCE_MAP", self.codes(self.audit()))

    def test_encoded_embedded_code_carriers_are_explicit_gaps(self):
        samples = [("index.html", '<script src="data:text/javascript,//#%20sourceMappingURL=data:application/json,e30="></script>'),
                   ("index.html", '<script src="data%3Atext/javascript,//#%20sourceMappingURL=hidden.map"></script>'),
                   ("index.html", '<script src="blob:opaque"></script>'),
                   ("index.html", '<script src="da&#x09;ta:text/javascript,//#%20sourceMappingURL=hidden.map"></script>'),
                   ("index.html", '<iframe srcdoc="&lt;script&gt;private code&lt;/script&gt;"></iframe>'),
                   ("image.svg", '<svg><script xlink:href="data:text/javascript,//#%20sourceMappingURL=hidden.map"/></svg>')]
        for name, source in samples:
            with self.subTest(source=source):
                path = self.write(name, source)
                result = self.audit()
                self.assertNotEqual(result["status"], "pass")
                self.assertIn("EMBEDDED_CODE_CARRIER_UNINSPECTED", {gap["code"] for gap in result["gaps"]})
                path.unlink()

    def test_container_magic_and_binary_controls_cannot_hide_behind_javascript_suffix(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("private.js.map", MAP)
        samples = [stream.getvalue(), b"\x1f\x8b\x08\0", b"\0asm\x01\0\0\0", b"plain\0binary"]
        for value in samples:
            with self.subTest(value=value[:8]):
                self.write("archive_alias.js", value)
                result = self.audit()
                self.assertNotEqual(result["status"], "pass")
                self.assertTrue({"UNINSPECTED_CONTAINER", "TEXT_CONTAINS_BINARY_CONTROL"} & {gap["code"] for gap in result["gaps"]})

    def test_data_javascript_import_and_css_import_are_uninspected_carriers(self):
        encoded = base64.b64encode(b"//# sourceMappingURL=data:application/json,e30=").decode("ascii")
        samples = [("app.js", 'import "data:text/javascript;base64,' + encoded + '";'),
                   ("style.css", '@import url("data:text/css;base64,' + encoded + '");'),
                   ("app.js", 'import "data%3Aapplication%2Fjavascript%3Bbase64,' + encoded + '";')]
        for name, source in samples:
            with self.subTest(name=name):
                path = self.write(name, source)
                result = self.audit()
                self.assertNotEqual(result["status"], "pass")
                self.assertIn("EMBEDDED_CODE_CARRIER_UNINSPECTED", {gap["code"] for gap in result["gaps"]})
                path.unlink()

    def test_xml_svg_and_namespaced_cdata_cannot_hide_embedded_source_map(self):
        source = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:s="http://www.w3.org/2000/svg"><s:script><![CDATA[//# sourceMappingURL=data:application/json,e30=\n]]></s:script></svg>'
        for name in ("image.svg", "document.xml"):
            with self.subTest(name=name):
                path = self.write(name, source)
                result = self.audit()
                self.assertNotEqual(result["status"], "pass")
                self.assertIn("EMBEDDED_CODE_CARRIER_UNINSPECTED", {gap["code"] for gap in result["gaps"]})
                path.unlink()

    def test_empty_unsupported_binary_precompressed_and_invalid_text_cannot_pass(self):
        self.assertEqual(self.audit()["status"], "partial")
        samples = [("app.js.gz", b"\x1f\x8b"), ("app.js.br", b"compressed"),
                   ("app.wasm", b"\0asm"), ("unknown.bin", b"\x80\0\xff"),
                   ("app.js", b"\xff"), ("app.js.map", b"not-json")]
        for name, content in samples:
            with self.subTest(name=name):
                path = self.write(name, content)
                result = self.audit()
                self.assertEqual(result["status"], "partial")
                self.assertFalse(result["complete"])
                self.assertIsNone(result["artifactSha256"])
                path.unlink()

    def test_limits_cannot_be_disabled_extended_or_added(self):
        for limits in ({"files": 0}, {"files": 999999}, {"seconds": float("nan")},
                       {"seconds": float("inf")}, {"seconds": True}, {"unknown": 1}, {"files": 1.2}, []):
            with self.subTest(limits=limits):
                self.assertEqual(self.audit(limits=limits)["gaps"], [{"code": "LIMITS_INVALID"}])

    def test_byte_count_file_count_depth_time_and_detail_bounds(self):
        self.write("a.js", "let a=1;")
        self.write("b.js", "let b=2;")
        for limits, code in [({"files": 1}, "FILE_COUNT_LIMIT"), ({"entries": 1}, "ENTRY_COUNT_LIMIT"),
                             ({"fileBytes": 1}, "FILE_BYTES_LIMIT"), ({"totalBytes": 1}, "TOTAL_BYTES_LIMIT")]:
            with self.subTest(limits=limits):
                result = self.audit(limits=limits)
                self.assertNotEqual(result["status"], "pass")
                self.assertIn(code, {gap["code"] for gap in result["gaps"]})
        self.write("deep/one/two/file.js", "let nested=true;")
        self.assertIn("DIRECTORY_DEPTH_LIMIT", {gap["code"] for gap in self.audit(limits={"depth": 1})["gaps"]})
        with patch.object(exposure.time, "monotonic", side_effect=[0, 11]):
            self.assertEqual(self.audit()["gaps"], [{"code": "DEADLINE_EXCEEDED"}])
        self.write("first.ts", "let a=1;")
        self.write("second.ts", "let b=2;")
        result = self.audit(limits={"observations": 1})
        self.assertEqual(len(result["observations"]), 1)
        self.assertGreater(result["counts"]["observationDetailsOmitted"], 0)

    def test_local_directory_only_and_error_diagnostics_never_export_input(self):
        for value in ("https://invalid.example/private", "file:///private", "\\\\server\\share", "\\\\?\\C:\\device", "missing-SYNTHETIC_SECRET"):
            with self.subTest(value=value):
                result = exposure.exposure_audit(value, authorized=True)
                self.assertNotEqual(result["status"], "pass")
                self.assertNotIn(value, json.dumps(result))

    def test_hardlink_is_never_read(self):
        path = self.write("app.js", "SYNTHETIC_ONLY")
        os.link(path, self.root / "alias.js")
        result = self.audit()
        self.assertEqual(result["counts"]["files"], 0)
        self.assertIn("HARDLINK_NOT_ALLOWED", {gap["code"] for gap in result["gaps"]})

    def test_symlink_and_root_alias_are_rejected(self):
        path = self.write("app.js", "SYNTHETIC_ONLY")
        try:
            os.symlink(path, self.root / "alias.js")
        except OSError:
            self.skipTest("OS does not grant symlink creation")
        result = self.audit()
        self.assertIn("LINK_OR_ALIAS_NOT_ALLOWED", {gap["code"] for gap in result["gaps"]})

    def test_concurrent_file_change_is_not_a_complete_snapshot(self):
        path = self.write("app.js", "let before=1;")
        original = exposure._rules

        def change(*args):
            result = original(*args)
            path.write_text("let after=2;", encoding="utf-8")
            return result

        with patch.object(exposure, "_rules", side_effect=change):
            result = self.audit()
        self.assertFalse(result["complete"])
        self.assertIsNone(result["artifactSha256"])
        self.assertIn("INPUT_CHANGED", {gap["code"] for gap in result["gaps"]})


if __name__ == "__main__":
    unittest.main()
