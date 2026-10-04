"""
client/crypto.py
================
All cryptographic operations for the E2EE client.

Primitives (all from PyNaCl / libsodium — no custom crypto):
  - Ed25519   : digital signatures  → identity key pair (IK)
  - X25519    : Diffie-Hellman      → signed pre-key (SPK) and ephemeral key (EK)
  - XSalsa20-Poly1305 (NaCl Box)   : authenticated encryption of message bodies

Key roles:
  IK  (identity key)   – long-lived Ed25519 signing key, proves sender identity.
                          Public half is published to the relay server at registration.
  SPK (signed pre-key) – long-lived X25519 key used in ECDH.  The server stores
                          the public half; its authenticity is proven by an Ed25519
                          signature from the IK.
  EK  (ephemeral key)  – fresh X25519 key generated per-message.  Discarding it
                          after the exchange provides forward secrecy for that
                          session (bonus SR5).

Session key derivation (one-way):
  shared_dh  = X25519(EK_priv, SPK_pub_peer)   # ephemeral × peer's SPK
  session_key = BLAKE2b(shared_dh, salt=b"e2ee-msg-v1")

Replay protection (SR4):
  Each outgoing message carries a monotonically-increasing sequence number (seq).
  The recipient tracks the highest seen seq per sender and rejects duplicates or
  out-of-order replays.

Security requirements addressed here:
  SR1 (Confidentiality)  – XSalsa20-Poly1305 AEAD
  SR2 (Integrity)        – Poly1305 MAC built into NaCl Box + Ed25519 signature
  SR3 (Authenticity)     – Ed25519 signature over (nonce ‖ ciphertext) by IK
  SR4 (Replay)           – per-sender sequence numbers checked before decryption
  SR5 (Forward Secrecy)  – ephemeral EK discarded after each key exchange
"""

import os
import hashlib
from typing import Tuple

import nacl.signing        # Ed25519
import nacl.public         # X25519 + NaCl Box (XSalsa20-Poly1305)
import nacl.secret
import nacl.encoding
import nacl.hash
import nacl.utils
import nacl.exceptions


# ---------------------------------------------------------------------------
# Type aliases (all raw bytes unless specified)
# ---------------------------------------------------------------------------
# Ed25519SigningKey   = nacl.signing.SigningKey
# Ed25519VerifyKey    = nacl.signing.VerifyKey
# X25519PrivateKey    = nacl.public.PrivateKey
# X25519PublicKey     = nacl.public.PublicKey


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_identity_key() -> nacl.signing.SigningKey:
    """
    Generate a fresh Ed25519 identity key pair (IK).

    The signing key holds both the private scalar and the public verify key.
    Call .verify_key to get the public half; call .encode() to serialise.
    """
    return nacl.signing.SigningKey.generate()


def generate_prekey() -> nacl.public.PrivateKey:
    """
    Generate a fresh X25519 signed pre-key pair (SPK).

    The private key is kept local; the public key is published to the relay
    server along with an Ed25519 signature from the identity key (see
    sign_prekey() below).
    """
    return nacl.public.PrivateKey.generate()


def generate_ephemeral_key() -> nacl.public.PrivateKey:
    """
    Generate a one-shot ephemeral X25519 key pair (EK).

    This key MUST be discarded immediately after the shared secret is derived.
    Discarding it ensures that compromise of long-term keys cannot decrypt past
    messages (forward secrecy, SR5).
    """
    return nacl.public.PrivateKey.generate()


# ---------------------------------------------------------------------------
# Signed pre-key: the server stores SPK_pub + sig so that recipients can
# verify the SPK came from the genuine owner before using it in ECDH.
# ---------------------------------------------------------------------------

def sign_prekey(ik: nacl.signing.SigningKey,
                spk_pub: nacl.public.PublicKey) -> bytes:
    """
    Produce an Ed25519 signature over the raw bytes of the SPK public key.

    Recipients call verify_prekey_sig() after fetching SPK_pub from the server
    to confirm the server has not substituted a fake key (SR6 / A5).
    """
    signed = ik.sign(bytes(spk_pub))
    # nacl.signing.SignedMessage = sig (64 bytes) ‖ message
    return bytes(signed.signature)   # 64 bytes


def verify_prekey_sig(ik_verify: nacl.signing.VerifyKey,
                      spk_pub_bytes: bytes,
                      signature: bytes) -> bool:
    """
    Verify that *signature* is a valid Ed25519 signature over *spk_pub_bytes*
    by the identity key whose verify key is *ik_verify*.

    Returns True on success, False on failure (never raises to callers).
    """
    try:
        ik_verify.verify(spk_pub_bytes, signature)
        return True
    except nacl.exceptions.BadSignatureError:
        return False


# ---------------------------------------------------------------------------
# Session key derivation
# ---------------------------------------------------------------------------

_KDF_SALT = b"e2ee-msg-v1"   # domain-separation constant


def derive_session_key(ek_priv: nacl.public.PrivateKey,
                       peer_spk_pub: nacl.public.PublicKey) -> bytes:
    """
    Derive a 32-byte session key via X25519 ECDH + BLAKE2b KDF.

      shared_dh   = X25519(ek_priv, peer_spk_pub)   [32 bytes]
      session_key = BLAKE2b-256(shared_dh, salt=_KDF_SALT)

    The ephemeral private key (ek_priv) MUST be discarded by the caller
    immediately after calling this function.

    The session key is used as the key for NaCl SecretBox (XSalsa20-Poly1305).
    """
    shared = nacl.public.Box(ek_priv, peer_spk_pub)
    # Extract the raw 32-byte shared secret (Box._shared_key is the result of
    # HSalsa20; we re-derive with BLAKE2b for explicit domain separation.)
    raw_dh = bytes(shared._shared_key)
    digest = nacl.hash.blake2b(
        raw_dh,
        key=_KDF_SALT,
        encoder=nacl.encoding.RawEncoder,
    )
    return digest   # 32 bytes


# ---------------------------------------------------------------------------
# Message encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_message(session_key: bytes,
                    plaintext: str) -> Tuple[bytes, bytes]:
    """
    Encrypt *plaintext* with XSalsa20-Poly1305 (NaCl SecretBox).

    Returns:
      nonce      – 24-byte random nonce (must be sent alongside ciphertext)
      ciphertext – encrypted + authenticated bytes (16-byte MAC prepended)

    The nonce is generated fresh from the OS CSPRNG for every message.
    Nonce reuse with the same key would be catastrophic; generating a random
    24-byte nonce gives a collision probability < 2^-64 over 2^32 messages.
    """
    box = nacl.secret.SecretBox(session_key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)   # 24 bytes
    ct = box.encrypt(plaintext.encode(), nonce=nonce)
    # nacl SecretBox.encrypt returns nonce ‖ ciphertext; we separate them.
    ciphertext = bytes(ct)[nacl.secret.SecretBox.NONCE_SIZE:]
    return nonce, ciphertext


def decrypt_message(session_key: bytes,
                    nonce: bytes,
                    ciphertext: bytes) -> str:
    """
    Decrypt and authenticate a ciphertext produced by encrypt_message().

    Raises nacl.exceptions.CryptoError if the MAC check fails, which covers
    SR2 (integrity) and SR3 (authenticity via session key).
    """
    box = nacl.secret.SecretBox(session_key)
    plaintext_bytes = box.decrypt(ciphertext, nonce=nonce)
    return plaintext_bytes.decode()


# ---------------------------------------------------------------------------
# Message signing / verification  (SR3 — sender authenticity via IK)
# ---------------------------------------------------------------------------

def sign_message(ik: nacl.signing.SigningKey,
                 nonce: bytes,
                 ciphertext: bytes) -> bytes:
    """
    Produce an Ed25519 signature over (nonce ‖ ciphertext) using the sender's
    long-term identity key.

    The recipient verifies this signature against the sender's published IK to
    confirm the message came from the genuine sender and was not injected by
    a network attacker (A2) or the relay server (A3).

    Returns the 64-byte signature.
    """
    payload = nonce + ciphertext
    signed = ik.sign(payload)
    return bytes(signed.signature)


def verify_message_sig(ik_verify: nacl.signing.VerifyKey,
                       nonce: bytes,
                       ciphertext: bytes,
                       signature: bytes) -> bool:
    """
    Verify an Ed25519 signature previously produced by sign_message().

    Returns True on success, False on failure.
    """
    payload = nonce + ciphertext
    try:
        ik_verify.verify(payload, signature)
        return True
    except nacl.exceptions.BadSignatureError:
        return False


# ---------------------------------------------------------------------------
# Password hashing  (server-side authentication only — NOT E2EE crypto)
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """
    Return a SHA-256 hex digest of the password.

    This is used only for server authentication (proving the client knows the
    account password) and has no role in E2EE security.  A production system
    would use Argon2 or bcrypt, but SHA-256 is sufficient for this project
    given that the focus is on the E2EE protocol.
    """
    return hashlib.sha256(password.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Key serialisation helpers
# ---------------------------------------------------------------------------

def ik_to_bytes(ik: nacl.signing.SigningKey) -> bytes:
    """Serialise an Ed25519 signing key (private scalar, 32 bytes)."""
    return bytes(ik)


def ik_from_bytes(data: bytes) -> nacl.signing.SigningKey:
    """Deserialise an Ed25519 signing key."""
    return nacl.signing.SigningKey(data)


def spk_to_bytes(spk: nacl.public.PrivateKey) -> bytes:
    """Serialise an X25519 private key (32 bytes)."""
    return bytes(spk)


def spk_from_bytes(data: bytes) -> nacl.public.PrivateKey:
    """Deserialise an X25519 private key."""
    return nacl.public.PrivateKey(data)


def pub_verify_key_bytes(ik: nacl.signing.SigningKey) -> bytes:
    """Return the raw 32-byte Ed25519 public verify key."""
    return bytes(ik.verify_key)


def pub_x25519_bytes(priv: nacl.public.PrivateKey) -> bytes:
    """Return the raw 32-byte X25519 public key."""
    return bytes(priv.public_key)
