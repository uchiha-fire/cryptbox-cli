"""
Comprehensive test suite for cryptbox-cli.
TDD coverage: AES-256-GCM AEAD encryption, PBKDF2 key derivation,
tamper detection (bit-flipping), directory packing/unpacking,
header inspection, CLI commands, and interactive mode.
"""
import os
import shutil
import tempfile
import pytest

from cryptbox.core import (
    derive_key,
    lock_data,
    unlock_data,
    lock_path,
    unlock_vault,
    inspect_vault,
    AuthenticationError,
    MAGIC_HEADER,
)
from cryptbox.cli import main

TEST_KDF_ROUNDS = 2000  # Fast iteration count for rapid unit testing


# ---------------------------------------------------------------------------
# Cryptographic Primitive Tests
# ---------------------------------------------------------------------------

def test_derive_key():
    salt = os.urandom(16)
    key1 = derive_key("master-password", salt, iterations=TEST_KDF_ROUNDS)
    key2 = derive_key("master-password", salt, iterations=TEST_KDF_ROUNDS)
    key_diff = derive_key("different-password", salt, iterations=TEST_KDF_ROUNDS)

    assert len(key1) == 32
    assert key1 == key2
    assert key1 != key_diff


def test_lock_and_unlock_raw_bytes():
    payload = b"Top secret operational intelligence for Zephyrus Labs."
    password = "super-secret-passphrase"

    vault = lock_data(payload, password, iterations=TEST_KDF_ROUNDS)
    assert vault.startswith(MAGIC_HEADER)
    assert len(vault) > len(payload) + 8 + 16 + 12

    decrypted = unlock_data(vault, password, iterations=TEST_KDF_ROUNDS)
    assert decrypted == payload


def test_wrong_password_raises_authentication_error():
    payload = b"Critical financial records."
    vault = lock_data(payload, "correct-password", iterations=TEST_KDF_ROUNDS)

    with pytest.raises(AuthenticationError):
        unlock_data(vault, "wrong-password", iterations=TEST_KDF_ROUNDS)


def test_tamper_detection_bit_flip():
    payload = b"Tamper-evident data stream."
    vault = bytearray(lock_data(payload, "secret-pass", iterations=TEST_KDF_ROUNDS))

    # Flip one bit in ciphertext
    vault[-1] ^= 0x01

    with pytest.raises(AuthenticationError):
        unlock_data(bytes(vault), "secret-pass", iterations=TEST_KDF_ROUNDS)


def test_invalid_magic_header():
    fake_vault = b"NOTCRYPT" + os.urandom(64)
    with pytest.raises(ValueError, match="Invalid file format"):
        unlock_data(fake_vault, "secret", iterations=TEST_KDF_ROUNDS)


# ---------------------------------------------------------------------------
# File & Directory Vault Tests
# ---------------------------------------------------------------------------

def test_lock_and_unlock_single_file(tmp_path):
    src_file = tmp_path / "document.txt"
    vault_file = tmp_path / "document.box"
    dest_dir = tmp_path / "restored"

    content = "Confidential report content.\nLine 2.\n"
    src_file.write_text(content, encoding="utf-8")

    # Lock file
    lock_path(str(src_file), "my-pass", str(vault_file), iterations=TEST_KDF_ROUNDS)
    assert vault_file.exists()

    # Inspect without password
    meta = inspect_vault(str(vault_file))
    assert meta["valid"] is True
    assert meta["magic"] == "CRYPTBOX"
    assert meta["vault_size"] > 0

    # Unlock file
    out_dir = unlock_vault(str(vault_file), "my-pass", str(dest_dir), iterations=TEST_KDF_ROUNDS)
    restored_file = dest_dir / "document.txt"
    assert restored_file.exists()
    assert restored_file.read_text(encoding="utf-8") == content


def test_lock_and_unlock_directory_structure(tmp_path):
    src_dir = tmp_path / "project"
    src_dir.mkdir()
    sub_dir = src_dir / "nested" / "deep"
    sub_dir.mkdir(parents=True)

    (src_dir / "root.txt").write_text("root file", encoding="utf-8")
    (sub_dir / "config.json").write_text('{"api": "live"}', encoding="utf-8")

    vault_file = tmp_path / "project.box"
    dest_dir = tmp_path / "unpacked"

    lock_path(str(src_dir), "proj-pass", str(vault_file), iterations=TEST_KDF_ROUNDS)
    assert vault_file.exists()

    unlock_vault(str(vault_file), "proj-pass", str(dest_dir), iterations=TEST_KDF_ROUNDS)
    assert (dest_dir / "root.txt").exists()
    assert (dest_dir / "root.txt").read_text(encoding="utf-8") == "root file"
    assert (dest_dir / "nested" / "deep" / "config.json").exists()
    assert (dest_dir / "nested" / "deep" / "config.json").read_text(encoding="utf-8") == '{"api": "live"}'


# ---------------------------------------------------------------------------
# CLI Commands and Interactive Tests
# ---------------------------------------------------------------------------

def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "cryptbox-cli" in captured.out or "0.1.0" in captured.out


def test_cli_lock_unlock_inspect(tmp_path, capsys):
    test_file = tmp_path / "data.txt"
    test_file.write_text("Hello Cryptbox!", encoding="utf-8")
    vault_file = tmp_path / "data.box"
    restore_dir = tmp_path / "restored"

    # 1. Lock command
    lock_code = main(["lock", str(test_file), "-o", str(vault_file), "-p", "pass123", "--fast-test"])
    assert lock_code == 0
    assert vault_file.exists()

    # 2. Inspect command
    inspect_code = main(["inspect", str(vault_file)])
    assert inspect_code == 0
    captured = capsys.readouterr()
    assert "CRYPTBOX" in captured.out

    # 3. Unlock command
    unlock_code = main(["unlock", str(vault_file), "-o", str(restore_dir), "-p", "pass123", "--fast-test"])
    assert unlock_code == 0
    restored = restore_dir / "data.txt"
    assert restored.exists()
    assert restored.read_text(encoding="utf-8") == "Hello Cryptbox!"


def test_cli_interactive_wizard(tmp_path, monkeypatch, capsys):
    test_file = tmp_path / "secret.txt"
    test_file.write_text("Interactive secret", encoding="utf-8")
    vault_file = tmp_path / "secret.box"

    # Mock inputs:
    # 1. Action: 1 (Lock)
    # 2. Source path: str(test_file)
    # 3. Destination vault path: str(vault_file)
    inputs = iter([
        "1",
        str(test_file),
        str(vault_file),
    ])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
    # Mock password entry (enter pass, confirm pass)
    passwords = iter(["my-interactive-pass", "my-interactive-pass"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(passwords))

    exit_code = main(["--interactive", "--fast-test"])
    assert exit_code == 0
    assert vault_file.exists()
