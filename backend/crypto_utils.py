from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import base64


def generate_x25519_keypair() -> tuple[str, str]:
    """Returns (private_key_hex, public_key_hex)."""
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_bytes.hex(), public_bytes.hex()


def derive_shared_secret(my_private_hex: str, their_public_hex: str) -> bytes:
    """X25519 ECDH — derive a shared AES key via HKDF."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    private_key = X25519PrivateKey.from_private_bytes(bytes.fromhex(my_private_hex))
    public_key = X25519PublicKey.from_public_bytes(bytes.fromhex(their_public_hex))
    shared = private_key.exchange(public_key)

    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secureline-aes-key",
    ).derive(shared)
    return derived


def aes_encrypt(plaintext: str, key: bytes) -> str:
    """AES-256-GCM encrypt. Returns base64(nonce + ciphertext)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def aes_decrypt(payload_b64: str, key: bytes) -> str:
    """AES-256-GCM decrypt."""
    raw = base64.b64decode(payload_b64)
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode()
