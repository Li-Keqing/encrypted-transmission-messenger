"""
client/keystore.py
==================
Local key management for the E2EE client.

Responsibilities:
  1. Generate and persist the user's long-term identity key (Ed25519 IK) and
     signed pre-key (X25519 SPK) across process restarts.
  2. Cache peers' public keys fetched from the relay server so that LOOKUP
     requests are not repeated unnecessarily within a session.
  3. Track per-sender sequence numbers to implement replay protection (SR4):
     each sender has a "highest seen seq" counter; incoming messages with seq ≤
     that value are rejected as replays.

Storage format:
  Keys are stored in a JSON file at ~/.e2ee-messenger/<username>.json.
  Private key material is stored as hex strings.  In a production system these
  would be encrypted at rest (e.g. using a passphrase-derived key), but plain
  storage is acceptable for this project.

  {
    "username":   "alice",
    "ik_priv":    "<hex>",   // Ed25519 private scalar (32 bytes)
    "spk_priv":   "<hex>",   // X25519 private key (32 bytes)
    "seq_out":    42,        // next outgoing sequence number
    "seq_in":     {          // highest accepted seq per peer username
      "bob": 7,
      ...
    }
  }

WARNING: Do not commit the keystore JSON file to source control.
"""

import json
import os
from pathlib import Path
from typing import Dict, Optional, Tuple

import nacl.signing
import nacl.public

from client.crypto import (
    generate_identity_key, generate_prekey,
    ik_to_bytes, ik_from_bytes,
    spk_to_bytes, spk_from_bytes,
    pub_verify_key_bytes, pub_x25519_bytes,
    sign_prekey,
)
from shared.messages import b64d, b64e


_KEYSTORE_DIR = Path.home() / ".e2ee-messenger"


def _keystore_path(username: str) -> Path:
    return _KEYSTORE_DIR / f"{username}.json"


# ---------------------------------------------------------------------------
# Keystore class
# ---------------------------------------------------------------------------

class KeyStore:
    """
    Holds a user's own key material and a runtime cache of peer public keys.

    Typical lifecycle:
      ks = KeyStore.load("alice")   # load from disk (or create on first run)
      ks.save()                     # persist any changes
    """

    def __init__(self,
                 username: str,
                 ik: nacl.signing.SigningKey,
                 spk: nacl.public.PrivateKey,
                 seq_out: int,
                 seq_in: Dict[str, int]):
        self.username = username
        self.ik  = ik    # Ed25519 signing key (private + public)
        self.spk = spk   # X25519 pre-key (private + public)
        self._seq_out  = seq_out          # outgoing sequence counter
        self._seq_in   = seq_in           # {peer_username: highest_seen_seq}

        # Runtime-only cache: {peer_username: (ik_verify_key, spk_pub_key)}
        # Populated lazily by the protocol layer after LOOKUP responses.
        self._peer_keys: Dict[str, Tuple[nacl.signing.VerifyKey,
                                          nacl.public.PublicKey]] = {}

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, username: str) -> "KeyStore":
        """
        Load an existing keystore from disk, or create a new one if none exists.

        On first run this generates fresh IK + SPK and writes them to disk.
        """
        _KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)
        path = _keystore_path(username)

        if path.exists():
            with open(path) as f:
                data = json.load(f)
            ik  = ik_from_bytes(bytes.fromhex(data["ik_priv"]))
            spk = spk_from_bytes(bytes.fromhex(data["spk_priv"]))
            seq_out = data.get("seq_out", 0)
            seq_in  = data.get("seq_in", {})
            return cls(username, ik, spk, seq_out, seq_in)
        else:
            ik  = generate_identity_key()
            spk = generate_prekey()
            ks  = cls(username, ik, spk, seq_out=0, seq_in={})
            ks.save()
            return ks

    def save(self) -> None:
        """Persist the keystore to disk."""
        _KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "username": self.username,
            "ik_priv":  bytes(self.ik).hex(),
            "spk_priv": bytes(self.spk).hex(),
            "seq_out":  self._seq_out,
            "seq_in":   self._seq_in,
        }
        path = _keystore_path(self.username)
        # Write to a temp file first, then rename — avoids partial writes.
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        tmp.replace(path)

    # ------------------------------------------------------------------
    # Own public key accessors (used by registration and SEND messages)
    # ------------------------------------------------------------------

    @property
    def ik_pub_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 public verify key."""
        return pub_verify_key_bytes(self.ik)

    @property
    def spk_pub_bytes(self) -> bytes:
        """Raw 32-byte X25519 public key."""
        return pub_x25519_bytes(self.spk)

    @property
    def spk_sig(self) -> bytes:
        """64-byte Ed25519 signature over spk_pub by ik (for REGISTER)."""
        return sign_prekey(self.ik, self.spk.public_key)

    # ------------------------------------------------------------------
    # Peer public key cache
    # ------------------------------------------------------------------

    def cache_peer_keys(self,
                        peer: str,
                        ik_pub_bytes: bytes,
                        spk_pub_bytes: bytes) -> None:
        """
        Store a peer's public keys in the runtime cache after a successful
        LOOKUP response.  The protocol layer is responsible for verifying the
        SPK signature before calling this method.
        """
        ik_verify = nacl.signing.VerifyKey(ik_pub_bytes)
        spk_pub   = nacl.public.PublicKey(spk_pub_bytes)
        self._peer_keys[peer] = (ik_verify, spk_pub)

    def get_peer_keys(self, peer: str) -> Optional[Tuple[nacl.signing.VerifyKey,
                                                          nacl.public.PublicKey]]:
        """
        Return (ik_verify_key, spk_pub_key) for *peer*, or None if not cached.
        """
        return self._peer_keys.get(peer)

    # ------------------------------------------------------------------
    # Sequence number management (SR4 — replay protection)
    # ------------------------------------------------------------------

    def next_seq(self) -> int:
        """
        Return and increment the outgoing sequence counter.

        The caller should persist the keystore after calling this method so
        that the counter survives process restarts and seq numbers are never
        reused.
        """
        seq = self._seq_out
        self._seq_out += 1
        return seq

    def accept_seq(self, peer: str, seq: int) -> bool:
        """
        Accept or reject an incoming sequence number from *peer*.

        Returns True (accept) if seq is strictly greater than the highest
        previously seen seq for this peer.  Returns False (reject) if seq is
        equal to or less than the highest seen value, which indicates a replay
        or duplicate.

        On first message from a peer (no history), any non-negative seq is
        accepted.
        """
        highest = self._seq_in.get(peer, -1)
        if seq > highest:
            self._seq_in[peer] = seq
            return True
        return False
