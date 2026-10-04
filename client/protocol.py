"""
client/protocol.py
==================
High-level E2EE protocol operations.

This layer sits between the crypto primitives (crypto.py) and the network/UI
(client.py).  It composes primitive operations into the full protocol steps:

  1. register()  – send REGISTER to the relay, publishing the user's public keys.
  2. login()     – send LOGIN to the relay to obtain a server session.
  3. lookup()    – send LOOKUP to fetch and verify a peer's public keys.
  4. send_msg()  – perform ECDH, encrypt, sign, and SEND to the relay.
  5. recv_msg()  – receive INCOMING, verify replay protection, verify signature,
                   derive session key, and decrypt.

Security properties enforced here:
  SR1  – plaintext never leaves this layer unencrypted
  SR2  – decryption will raise if the MAC (Poly1305) fails
  SR3  – Ed25519 signature over (nonce ‖ ciphertext) verified before decrypting
  SR4  – seq number checked via keystore.accept_seq() before any crypto work
  SR5  – ephemeral key generated fresh per message and discarded after derivation
"""

from __future__ import annotations
import json
from typing import Optional, Tuple

import nacl.signing
import nacl.public
import nacl.exceptions
import nacl.encoding
import nacl.hash

from client.crypto import (
    generate_ephemeral_key,
    derive_session_key,
    encrypt_message, decrypt_message,
    sign_message, verify_message_sig,
    verify_prekey_sig,
    pub_x25519_bytes, pub_verify_key_bytes,
    hash_password,
)
from client.keystore import KeyStore
from shared.messages import (
    b64d, b64e,
    make_register, make_login, make_lookup, make_send,
    MSG_ACK, MSG_ERROR, MSG_INCOMING,
    unpack,
)


class ProtocolError(Exception):
    """Raised when the remote peer or server sends an unexpected response."""


class SecurityError(Exception):
    """Raised when a security check fails (bad MAC, bad sig, replay, etc.)."""


# ---------------------------------------------------------------------------
# Registration and authentication
# ---------------------------------------------------------------------------

def build_register(ks: KeyStore, password: str) -> str:
    """
    Build a REGISTER wire message using the keys in *ks*.

    Sends:
      - ik_pub   : Ed25519 public verify key
      - spk_pub  : X25519 signed pre-key public key
      - spk_sig  : Ed25519 signature over spk_pub by ik (proves ownership)
      - password_hash : SHA-256 of password (server auth only)
    """
    return make_register(
        username=ks.username,
        ik_pub=ks.ik_pub_bytes,
        spk_pub=ks.spk_pub_bytes,
        spk_sig=ks.spk_sig,
        password_hash=hash_password(password),
    )


def build_login(username: str, password: str) -> str:
    """Build a LOGIN wire message."""
    return make_login(username, hash_password(password))


def build_lookup(target: str) -> str:
    """Build a LOOKUP wire message."""
    return make_lookup(target)


# ---------------------------------------------------------------------------
# Sending a message
# ---------------------------------------------------------------------------

def build_send(ks: KeyStore, recipient: str, plaintext: str) -> str:
    """
    Encrypt *plaintext* for *recipient* and return the SEND wire message.

    Protocol steps:
      1. Retrieve recipient's cached public keys (ik_verify, spk_pub).
         Caller must have called lookup() first.
      2. Generate a fresh ephemeral X25519 key pair (EK).
      3. Derive session key: BLAKE2b(X25519(EK_priv, SPK_pub_peer)).
      4. Discard EK private key immediately (forward secrecy).
      5. Encrypt plaintext with XSalsa20-Poly1305 using session key + fresh nonce.
      6. Sign (nonce ‖ ciphertext) with the sender's Ed25519 IK.
      7. Increment and embed outgoing seq number.
      8. Serialise to wire format.

    Raises ProtocolError if the recipient's keys are not yet cached.
    """
    peer_keys = ks.get_peer_keys(recipient)
    if peer_keys is None:
        raise ProtocolError(
            f"No cached public keys for '{recipient}'. Run LOOKUP first."
        )
    _, spk_pub = peer_keys   # we only need the X25519 SPK for ECDH

    # Step 2 — ephemeral key
    ek = generate_ephemeral_key()
    ek_pub_bytes = pub_x25519_bytes(ek)

    # Step 3 — session key via ECDH + KDF
    session_key = derive_session_key(ek, spk_pub)

    # Step 4 — discard EK private material by letting `ek` go out of scope
    del ek   # explicit deletion for clarity; GC handles the rest

    # Step 5 — encrypt
    nonce, ciphertext = encrypt_message(session_key, plaintext)

    # Step 6 — sign
    sig = sign_message(ks.ik, nonce, ciphertext)

    # Step 7 — sequence number
    seq = ks.next_seq()
    ks.save()   # persist incremented counter immediately

    return make_send(
        sender=ks.username,
        recipient=recipient,
        eph_pub=ek_pub_bytes,
        ciphertext=ciphertext,
        nonce=nonce,
        sender_ik_pub=ks.ik_pub_bytes,
        sig=sig,
        seq=seq,
    )


# ---------------------------------------------------------------------------
# Receiving a message
# ---------------------------------------------------------------------------

def process_incoming(ks: KeyStore, raw: str) -> Tuple[str, str]:
    """
    Process an INCOMING wire message and return (sender_username, plaintext).

    Security checks (in order — fail fast):
      1. Replay check  : seq must be strictly greater than highest seen for sender.
      2. Key lookup    : sender's ik_verify must be cached (or fetched via LOOKUP).
      3. Sig verify    : Ed25519 signature over (nonce ‖ ciphertext) must be valid.
      4. ECDH + KDF    : derive session key from our SPK private key + EK_pub.
      5. Decrypt       : XSalsa20-Poly1305 decryption; raises on MAC failure.

    Raises SecurityError on any failed check so the caller can log and discard.
    Raises ProtocolError on malformed messages.
    """
    try:
        msg = unpack(raw)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"Malformed JSON: {exc}") from exc

    if msg.get("type") != MSG_INCOMING:
        raise ProtocolError(f"Expected INCOMING, got {msg.get('type')!r}")

    try:
        sender     = msg["sender"]
        eph_pub_b  = b64d(msg["eph_pub"])
        ciphertext = b64d(msg["ciphertext"])
        nonce      = b64d(msg["nonce"])
        ik_pub_b   = b64d(msg["sender_ik_pub"])
        sig        = b64d(msg["sig"])
        seq        = int(msg["seq"])
    except (KeyError, ValueError) as exc:
        raise ProtocolError(f"Missing or invalid field: {exc}") from exc

    # --- SR4: Replay protection ---
    if not ks.accept_seq(sender, seq):
        raise SecurityError(
            f"Replay or duplicate: seq {seq} from '{sender}' already seen."
        )
    ks.save()   # persist updated seq_in counter

    # --- SR3: Sender authenticity — verify Ed25519 signature ---
    peer_keys = ks.get_peer_keys(sender)
    if peer_keys is None:
        raise ProtocolError(
            f"No cached public keys for '{sender}'. Run LOOKUP first."
        )
    ik_verify, _ = peer_keys

    # Also cross-check the ik_pub embedded in the message against our cache.
    # If they differ, a network attacker may have substituted a key (A2/A5).
    if bytes(ik_verify) != ik_pub_b:
        raise SecurityError(
            "sender_ik_pub in message does not match cached identity key."
        )

    if not verify_message_sig(ik_verify, nonce, ciphertext, sig):
        raise SecurityError("Ed25519 signature verification failed.")

    # --- SR1/SR2: Decrypt (Poly1305 MAC checked inside) ---
    ek_pub   = nacl.public.PublicKey(eph_pub_b)
    # Derive the same session key the sender derived:
    #   BLAKE2b(X25519(our_SPK_priv, sender_EK_pub))
    shared_box = nacl.public.Box(ks.spk, ek_pub)
    _KDF_SALT = b"e2ee-msg-v1"
    raw_dh = bytes(shared_box._shared_key)
    session_key = nacl.hash.blake2b(
        raw_dh, key=_KDF_SALT, encoder=nacl.encoding.RawEncoder
    )

    try:
        plaintext = decrypt_message(session_key, nonce, ciphertext)
    except nacl.exceptions.CryptoError as exc:
        raise SecurityError(f"Decryption failed (bad MAC or corrupted data): {exc}") from exc

    return sender, plaintext


# ---------------------------------------------------------------------------
# Processing LOOKUP responses
# ---------------------------------------------------------------------------

def process_lookup_response(ks: KeyStore,
                             response: dict,
                             target: str) -> bool:
    """
    Parse a LOOKUP response, verify the SPK signature, and cache the peer keys.

    Returns True if the keys were successfully verified and cached, False if
    the server returned an error or the SPK signature is invalid.

    The SPK signature check defends against a malicious server (A5 / SR6):
    if the server substitutes a fake SPK, the signature (made by the peer's IK)
    will not verify, and we refuse to use the key.
    """
    if response.get("type") == MSG_ERROR:
        return False

    try:
        ik_pub_b  = b64d(response["ik_pub"])
        spk_pub_b = b64d(response["spk_pub"])
        spk_sig_b = b64d(response["spk_sig"])
    except (KeyError, ValueError):
        return False

    ik_verify = nacl.signing.VerifyKey(ik_pub_b)

    if not verify_prekey_sig(ik_verify, spk_pub_b, spk_sig_b):
        # The SPK signature is invalid — possible key substitution by server.
        return False

    ks.cache_peer_keys(target, ik_pub_b, spk_pub_b)
    return True
