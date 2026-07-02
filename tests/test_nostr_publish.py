import json
import os
import tempfile
from pathlib import Path

import pytest

from nostr_publish.scanner import (
    is_blocked_file,
    scan_content,
    scan_file,
    scan_directory,
    verify_clean,
    verify_content_clean,
    shannon_entropy,
    is_high_entropy_hex,
)
from nostr_publish.blossom import compute_sha256, get_blob_url, guess_content_type
from nostr_publish.nostr_events import (
    publish_nip94_event,
    publish_test_run_event,
    _nostr_now,
    KIND_NIP94_FILE_METADATA,
    KIND_APP_DATA,
)
from nostr_publish.publisher import (
    publish_results,
    _guess_mime_type,
    _is_hard_blocked,
    _generate_run_id,
    DEFAULT_MAX_FILE_SIZE,
)


# ---------------------------------------------------------------------------
# Secret scanner tests
# ---------------------------------------------------------------------------

class TestBlockedFiles:
    def test_blocks_env_files(self):
        assert is_blocked_file(".env")
        assert is_blocked_file(".env.local")
        assert is_blocked_file(".env.production")

    def test_blocks_key_files(self):
        assert is_blocked_file("id_rsa")
        assert is_blocked_file("id_ed25519")
        assert is_blocked_file("nsec")
        assert is_blocked_file("nsec.txt")
        assert is_blocked_file("bot_nsec")

    def test_blocks_by_suffix(self):
        assert is_blocked_file("cert.pem")
        assert is_blocked_file("ca.key")
        assert is_blocked_file("store.p12")

    def test_blocks_config_json(self):
        assert is_blocked_file("config.json")
        assert is_blocked_file("config.local.json")
        assert is_blocked_file("credentials.json")

    def test_allows_normal_files(self):
        assert not is_blocked_file("report.html")
        assert not is_blocked_file("results.json")
        assert not is_blocked_file("screenshot.png")
        assert not is_blocked_file("analysis.txt")
        assert not is_blocked_file("secret_scanner.py")


class TestSecretDetection:
    def test_detects_nsec_bech32(self):
        content = "my key is nsec1" + "x" * 58
        sanitized, findings = scan_content(content)
        assert len(findings) == 1
        assert findings[0]["type"] == "nostr-nsec-bech32"
        assert "[REDACTED:" in sanitized

    def test_detects_nsec_hex_assignment(self):
        hex_key = "a" * 64
        content = f'NOSTR_SECRET_KEY="{hex_key}"'
        sanitized, findings = scan_content(content)
        assert len(findings) >= 1
        assert any(f["type"] == "nostr-nsec-hex" for f in findings)

    def test_detects_github_token(self):
        content = "GITHUB_TOKEN=ghp_" + "x" * 36
        _, findings = scan_content(content)
        assert any(f["type"] == "github-token" for f in findings)

    def test_detects_openai_key(self):
        content = "API_KEY=sk-" + "x" * 40
        _, findings = scan_content(content)
        assert any(f["type"] == "openai-key" for f in findings)

    def test_detects_pem_block(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nsomedata\n-----END RSA PRIVATE KEY-----"
        _, findings = scan_content(content)
        assert any(f["type"] == "pem-private-key" for f in findings)

    def test_detects_cashu_token(self):
        content = "token=cashuBA" + "x" * 30
        _, findings = scan_content(content)
        assert any(f["type"] == "cashu-token" for f in findings)

    def test_detects_ssh_password(self):
        content = "sshpass -p 'mysecret123'"
        sanitized, findings = scan_content(content)
        assert any(f["type"] == "ssh-password-sshpass" for f in findings)
        assert "[REDACTED:" in sanitized

    def test_detects_router_password(self):
        content = 'router_password: "admin1234"'
        _, findings = scan_content(content)
        assert any(f["type"] == "router-password" for f in findings)

    def test_clean_content_no_findings(self):
        content = "This is a normal log file with no secrets.\nAll good here."
        sanitized, findings = scan_content(content)
        assert len(findings) == 0
        assert sanitized == content

    def test_safe_hex_not_flagged(self):
        content = "sha256: " + "a" * 64
        _, findings = scan_content(content)
        assert not any(f["type"] == "suspicious-bare-hex" for f in findings)

    def test_multiple_secrets_in_one_file(self):
        content = (
            "nsec1" + "x" * 58 + "\n"
            "ghp_" + "y" * 36 + "\n"
        )
        _, findings = scan_content(content)
        assert len(findings) >= 2


class TestEntropy:
    def test_low_entropy_string(self):
        assert shannon_entropy("aaaaaaa") < 1.0

    def test_high_entropy_hex(self):
        hex_str = "a1b2c3d4e5f67890" * 4
        assert is_high_entropy_hex(hex_str)

    def test_short_string_not_high_entropy(self):
        assert not is_high_entropy_hex("abc")


class TestVerifyClean:
    def test_verify_clean_content(self):
        assert verify_content_clean("hello world")

    def test_verify_dirty_content(self):
        assert not verify_content_clean("nsec1" + "x" * 58)


# ---------------------------------------------------------------------------
# Blossom utility tests
# ---------------------------------------------------------------------------

class TestBlossomUtils:
    def test_compute_sha256_known_value(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        sha = compute_sha256(str(f))
        assert sha == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_compute_sha256_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        sha = compute_sha256(str(f))
        assert sha == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_get_blob_url(self):
        url = get_blob_url("https://blossom.psbt.me", "abc123")
        assert url == "https://blossom.psbt.me/abc123"

    def test_get_blob_url_trailing_slash(self):
        url = get_blob_url("https://blossom.psbt.me/", "abc123")
        assert url == "https://blossom.psbt.me/abc123"

    def test_guess_content_type_html(self):
        assert guess_content_type("report.html") == "text/html"

    def test_guess_content_type_json(self):
        assert "json" in guess_content_type("data.json")

    def test_guess_content_type_unknown(self):
        assert guess_content_type("file.zzznovel") == "application/octet-stream"


# ---------------------------------------------------------------------------
# Publisher helper tests
# ---------------------------------------------------------------------------

class TestPublisherHelpers:
    def test_generate_run_id_format(self):
        run_id = _generate_run_id()
        assert len(run_id) == 16
        assert run_id.endswith("Z")
        assert "T" in run_id

    def test_guess_mime_type_html(self):
        assert _guess_mime_type("report.html") == "text/html"

    def test_guess_mime_type_default(self):
        assert _guess_mime_type("file.unknown") == "application/octet-stream"

    def test_hard_blocked_env(self):
        assert _is_hard_blocked(Path(".env"))

    def test_hard_blocked_pem(self):
        assert _is_hard_blocked(Path("cert.pem"))

    def test_hard_blocked_sqlite(self):
        assert _is_hard_blocked(Path("data.sqlite"))

    def test_not_hard_blocked_html(self):
        assert not _is_hard_blocked(Path("report.html"))

    def test_not_hard_blocked_json(self):
        assert not _is_hard_blocked(Path("results.json"))


# ---------------------------------------------------------------------------
# Dry-run publish pipeline tests
# ---------------------------------------------------------------------------

class TestPublishPipelineDryRun:
    def _make_results_dir(self, tmp_path):
        d = tmp_path / "results"
        d.mkdir()
        (d / "report.html").write_text("<html><body>Test passed</body></html>")
        (d / "results.json").write_text(json.dumps({"passed": 10, "failed": 0}))
        (d / "log.txt").write_text("All tests passed cleanly.\nNo secrets here.")
        (d / ".env").write_text("SECRET_KEY=mysecret")
        return d

    def test_dry_run_scans_and_reports(self, tmp_path):
        results_dir = self._make_results_dir(tmp_path)
        nsec_file = tmp_path / "nsec"
        nsec_file.write_text("a" * 64)

        manifest = publish_results(
            results_dir=str(results_dir),
            nsec_file=str(nsec_file),
            dry_run=True,
        )

        assert manifest["dry_run"] is True
        assert manifest["files"] == []
        assert manifest["summary_event_id"] is None
        assert manifest["scan_summary"]["scanned"] == 4
        assert manifest["scan_summary"]["blocked"] >= 1
        assert manifest["scan_summary"]["clean"] >= 2

    def test_dry_run_generates_run_id(self, tmp_path):
        results_dir = self._make_results_dir(tmp_path)
        nsec_file = tmp_path / "nsec"
        nsec_file.write_text("a" * 64)

        manifest = publish_results(
            results_dir=str(results_dir),
            nsec_file=str(nsec_file),
            dry_run=True,
        )

        assert manifest["run_id"]
        assert len(manifest["run_id"]) == 16

    def test_dry_run_respects_custom_run_id(self, tmp_path):
        results_dir = self._make_results_dir(tmp_path)
        nsec_file = tmp_path / "nsec"
        nsec_file.write_text("a" * 64)

        manifest = publish_results(
            results_dir=str(results_dir),
            nsec_file=str(nsec_file),
            run_id="custom-run-123",
            dry_run=True,
        )

        assert manifest["run_id"] == "custom-run-123"

    def test_dry_run_nonexistent_dir_raises(self, tmp_path):
        nsec_file = tmp_path / "nsec"
        nsec_file.write_text("a" * 64)

        with pytest.raises(FileNotFoundError):
            publish_results(
                results_dir=str(tmp_path / "nonexistent"),
                nsec_file=str(nsec_file),
                dry_run=True,
            )

    def test_dry_run_empty_dir(self, tmp_path):
        results_dir = tmp_path / "empty_results"
        results_dir.mkdir()
        nsec_file = tmp_path / "nsec"
        nsec_file.write_text("a" * 64)

        manifest = publish_results(
            results_dir=str(results_dir),
            nsec_file=str(nsec_file),
            dry_run=True,
        )

        assert manifest["scan_summary"]["scanned"] == 0
        assert manifest["scan_summary"]["clean"] == 0
        assert manifest["scan_summary"]["blocked"] == 0


class TestScanDirectory:
    def test_scan_finds_blocked_and_clean(self, tmp_path):
        (tmp_path / "report.txt").write_text("clean file")
        (tmp_path / ".env").write_text("SECRET=abc")
        (tmp_path / "data.json").write_text('{"key": "value"}')

        result = scan_directory(str(tmp_path))

        assert result["scanned"] == 3
        assert len(result["blocked"]) >= 1
        assert len(result["clean"]) >= 2

    def test_scan_redacts_secrets(self, tmp_path):
        (tmp_path / "config.txt").write_text(
            "nsec1" + "x" * 58 + "\nghp_" + "y" * 36
        )

        result = scan_directory(str(tmp_path))

        assert len(result["redacted"]) == 1
        assert result["redacted"][0]["count"] >= 2

    def test_scan_skips_hidden_dirs(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("some config")
        (tmp_path / "report.txt").write_text("clean")

        result = scan_directory(str(tmp_path))

        assert result["scanned"] == 1
        assert result["clean"] == [str(tmp_path / "report.txt")]


# ---------------------------------------------------------------------------
# Nostr event structure tests (no publishing — just structure verification)
# ---------------------------------------------------------------------------

class TestNostrEventKinds:
    def test_nip94_kind_constant(self):
        assert KIND_NIP94_FILE_METADATA == 1063

    def test_app_data_kind_constant(self):
        assert KIND_APP_DATA == 30078

    def test_nostr_now_returns_int(self):
        ts = _nostr_now()
        assert isinstance(ts, int)
        assert ts > 1700000000


class TestPublishNip94NoNak:
    def test_returns_error_without_nak(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        nsec_file = tmp_path / "nsec"
        nsec_file.write_text("a" * 64)

        result = publish_nip94_event(
            nsec_file=str(nsec_file),
            filename="test.txt",
            blossom_url="https://blossom.psbt.me/abc",
            sha256="abc",
            mime_type="text/plain",
        )

        assert result["success"] is False
        assert "nak" in result["error"].lower()


class TestPublishTestRunEventNoNak:
    def test_returns_error_without_nak(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        nsec_file = tmp_path / "nsec"
        nsec_file.write_text("a" * 64)

        result = publish_test_run_event(
            nsec_file=str(nsec_file),
            run_id="test-run-001",
        )

        assert result["success"] is False
        assert "nak" in result["error"].lower()
