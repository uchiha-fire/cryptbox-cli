"""
Core AES-256-GCM authenticated encryption engine for cryptbox.
Zephyrus Labs (https://zephyrus-labs.tech/)
Lead Developer: Shubham Sharma
"""
import io
import os
import tarfile
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC_HEADER = b"CRYPTBOX"
KDF_ITERATIONS = 600_000


class AuthenticationError(Exception):
    """Raised when authentication tag verification fails (corrupted data or wrong password)."""
    pass


def derive_key(passphrase: str, salt: bytes, iterations: Optional[int] = None) -> bytes:
    """Derives a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    rounds = iterations if iterations is not None else KDF_ITERATIONS
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=rounds,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def lock_data(raw_bytes: bytes, passphrase: str, iterations: Optional[int] = None) -> bytes:
    """Encrypts raw bytes into an authenticated CRYPTBOX binary payload."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase, salt, iterations=iterations)
    aesgcm = AESGCM(key)

    # AESGCM automatically appends a 16-byte authentication tag to ciphertext
    ciphertext = aesgcm.encrypt(nonce, raw_bytes, None)

    return MAGIC_HEADER + salt + nonce + ciphertext


def unlock_data(vault_bytes: bytes, passphrase: str, iterations: Optional[int] = None) -> bytes:
    """Decrypts and authenticates a CRYPTBOX binary payload."""
    if not vault_bytes.startswith(MAGIC_HEADER):
        raise ValueError("Invalid file format: Missing CRYPTBOX header.")

    if len(vault_bytes) < 36 + 16:  # MAGIC(8) + Salt(16) + Nonce(12) + Tag(16)
        raise ValueError("Corrupted vault: Payload is too short to contain cryptographic credentials.")

    salt = vault_bytes[8:24]
    nonce = vault_bytes[24:36]
    ciphertext = vault_bytes[36:]

    key = derive_key(passphrase, salt, iterations=iterations)
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as e:
        raise AuthenticationError("Authentication failed: Incorrect password or corrupted vault file.") from e


def lock_path(
    source_path: str,
    password: str,
    output_path: Optional[str] = None,
    iterations: Optional[int] = None,
) -> str:
    """
    Encrypts a single file or an entire directory into an authenticated .box vault file.
    """
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source path not found: {source_path}")

    if not output_path:
        output_path = f"{source_path.rstrip(os.sep)}.box"

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tar:
        if os.path.isfile(source_path):
            tar.add(source_path, arcname=os.path.basename(source_path))
        else:
            for root, _, files in os.walk(source_path):
                for f in files:
                    full_path = os.path.join(root, f)
                    rel_path = os.path.relpath(full_path, source_path)
                    tar.add(full_path, arcname=rel_path)

    tar_bytes = bio.getvalue()
    vault_bytes = lock_data(tar_bytes, password, iterations=iterations)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(vault_bytes)

    return output_path


def unlock_vault(
    vault_path: str,
    password: str,
    destination_dir: Optional[str] = None,
    iterations: Optional[int] = None,
) -> str:
    """
    Authenticates and decrypts a .box vault, extracting contents to destination_dir.
    """
    if not os.path.exists(vault_path):
        raise FileNotFoundError(f"Vault file not found: {vault_path}")

    if not destination_dir:
        destination_dir = os.path.splitext(vault_path)[0]

    with open(vault_path, "rb") as f:
        vault_bytes = f.read()

    # Authenticate and decrypt bytes (fails completely with zero extraction if tampered)
    decrypted_tar_bytes = unlock_data(vault_bytes, password, iterations=iterations)

    os.makedirs(destination_dir, exist_ok=True)
    bio = io.BytesIO(decrypted_tar_bytes)
    with tarfile.open(fileobj=bio, mode="r:gz") as tar:
        # Protect against path traversal (Zip Slip / Tar Slip)
        for member in tar.getmembers():
            target_path = os.path.abspath(os.path.join(destination_dir, member.name))
            if not target_path.startswith(os.path.abspath(destination_dir) + os.sep) and target_path != os.path.abspath(destination_dir):
                raise SecurityError(f"Attempted path traversal in tar archive: {member.name}")
        tar.extractall(path=destination_dir)

    return destination_dir


def inspect_vault(vault_path: str) -> Dict[str, Any]:
    """
    Reads the header metadata of a .box vault without requiring a password.
    """
    if not os.path.exists(vault_path):
        raise FileNotFoundError(f"Vault file not found: {vault_path}")

    file_size = os.path.getsize(vault_path)
    with open(vault_path, "rb") as f:
        header = f.read(36)

    if not header.startswith(MAGIC_HEADER):
        return {
            "valid": False,
            "error": "Missing CRYPTBOX magic header",
            "vault_size": file_size,
        }

    return {
        "valid": True,
        "magic": "CRYPTBOX",
        "cipher": "AES-256-GCM (AEAD)",
        "kdf": "PBKDF2-HMAC-SHA256 (600,000 rounds)",
        "salt_bytes": 16,
        "nonce_bytes": 12,
        "auth_tag_bytes": 16,
        "vault_size": file_size,
        "payload_size": max(0, file_size - 36),
    }
