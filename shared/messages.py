"""
shared/messages.py
==================
Wire-format definitions for every message exchanged between clients and the
relay server.  All payloads are serialised as JSON.  Every field name here is
the canonical field name used on the wire; the relay server never touches
fields marked [E2E] — those are opaque bytes (base64-encoded) to the server.

Message types (the "type" field in every envelope):
  REGISTER      client → server : publish identity and public keys
  LOGIN         client → server : authenticate an existing account
  LOOKUP        client → server : fetch a peer's public keys
  SEND          client → server : deliver a ciphertext envelope to a peer
  INCOMING      server → client : deliver a ciphertext envelope from a peer
  ACK           server → client : generic success acknowledgement
  ERROR         server → client : error response with a human-readable reason
"""

from __future__ import annotations
import json
import base64
from dataclasses import dataclass, asdict
from typing import Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def b64e(data: bytes) -> str:
    """Encode bytes to a URL-safe base64 string (no padding stripped)."""
    return base64.urlsafe_b64encode(data).decode()


def b64d(s: str) -> bytes:
    """Decode a URL-safe base64 string back to bytes."""
    # Add padding if needed
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


# ---------------------------------------------------------------------------
# Message type constants
# ---------------------------------------------------------------------------

MSG_REGISTER = "REGISTER"
MSG_LOGIN    = "LOGIN"
MSG_LOOKUP   = "LOOKUP"
MSG_SEND     = "SEND"
MSG_INCOMING = "INCOMING"
MSG_ACK      = "ACK"
MSG_ERROR    = "ERROR"


# ---------------------------------------------------------------------------
# Envelope helpers  (pack / unpack JSON over the wire)
# ---------------------------------------------------------------------------

def pack(msg_type: str, **fields) -> str:
    """Serialise a message to a JSON string ready to send over the socket."""
    payload = {"type": msg_type, **fields}
    return json.dumps(payload)


def unpack(raw: str) -> dict:
    """Deserialise a JSON string received from the socket."""
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Typed request / response constructors
# (These are thin helpers — they do NOT validate; keep validation in crypto.py
#  and protocol.py so that each layer has a single responsibility.)
# ---------------------------------------------------------------------------

def make_register(username: str,
                  ik_pub: bytes,
                  spk_pub: bytes,
                  spk_sig: bytes,
                  password_hash: str) -> str:
    """
    REGISTER request sent by a new client.

    Fields:
      username      – chosen display name / login identifier
      ik_pub        – [E2E] Ed25519 identity key (public), base64
      spk_pub       – [E2E] X25519 signed pre-key (public), base64
      spk_sig       – [E2E] Ed25519 signature over spk_pub by ik_pub, base64
      password_hash – SHA-256 hex of the user's password (server auth only)
    """
    return pack(
        MSG_REGISTER,
        username=username,
        ik_pub=b64e(ik_pub),
        spk_pub=b64e(spk_pub),
        spk_sig=b64e(spk_sig),
        password_hash=password_hash,
    )


def make_login(username: str, password_hash: str) -> str:
    """LOGIN request — server checks credentials and grants a session token."""
    return pack(MSG_LOGIN, username=username, password_hash=password_hash)


def make_lookup(target_username: str) -> str:
    """LOOKUP request — ask the server for a peer's published public keys."""
    return pack(MSG_LOOKUP, target=target_username)


def make_send(sender: str,
              recipient: str,
              eph_pub: bytes,
              ciphertext: bytes,
              nonce: bytes,
              sender_ik_pub: bytes,
              sig: bytes,
              seq: int) -> str:
    """
    SEND request — deliver an encrypted message to a peer via the relay.

    Fields:
      sender        – sender's username (routing metadata, visible to server)
      recipient     – recipient's username (routing metadata, visible to server)
      eph_pub       – [E2E] sender's ephemeral X25519 public key, base64
      ciphertext    – [E2E] XSalsa20-Poly1305 ciphertext, base64
      nonce         – [E2E] 24-byte random nonce used for this message, base64
      sender_ik_pub – [E2E] sender's Ed25519 identity key (for verification), base64
      sig           – [E2E] Ed25519 signature over (nonce ‖ ciphertext), base64
      seq           – monotonically-increasing sequence number (replay protection)
    """
    return pack(
        MSG_SEND,
        sender=sender,
        recipient=recipient,
        eph_pub=b64e(eph_pub),
        ciphertext=b64e(ciphertext),
        nonce=b64e(nonce),
        sender_ik_pub=b64e(sender_ik_pub),
        sig=b64e(sig),
        seq=seq,
    )


def make_ack(detail: str = "OK") -> str:
    return pack(MSG_ACK, detail=detail)


def make_error(reason: str) -> str:
    return pack(MSG_ERROR, reason=reason)
