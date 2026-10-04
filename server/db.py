"""
server/db.py
============
SQLite database wrapper for the relay server.

Schema:

  CREATE TABLE users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    ik_pub        TEXT NOT NULL,   -- base64 Ed25519 public verify key
    spk_pub       TEXT NOT NULL,   -- base64 X25519 signed pre-key public key
    spk_sig       TEXT NOT NULL    -- base64 Ed25519 signature over spk_pub
  );

The server stores ONLY public keys and a password hash.
Private keys never leave the client.  The server is intentionally
ignorant of any cryptographic details — it treats ik_pub, spk_pub,
and spk_sig as opaque base64 blobs.
"""

import sqlite3
from pathlib import Path
from typing import Optional, Tuple


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    ik_pub        TEXT NOT NULL,
    spk_pub       TEXT NOT NULL,
    spk_sig       TEXT NOT NULL
);
"""


class Database:
    """Thread-safe (check_same_thread=False) SQLite wrapper."""

    def __init__(self, path: Path):
        self._path = path
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # User management
    # ------------------------------------------------------------------

    def user_exists(self, username: str) -> bool:
        """Return True if *username* is already registered."""
        row = self._conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
        return row is not None

    def add_user(self,
                 username: str,
                 password_hash: str,
                 ik_pub: str,
                 spk_pub: str,
                 spk_sig: str) -> None:
        """
        Insert a new user row.

        All key fields are stored as base64 strings exactly as received from
        the client — the server never parses or validates the key bytes.
        """
        self._conn.execute(
            "INSERT INTO users (username, password_hash, ik_pub, spk_pub, spk_sig) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, ik_pub, spk_pub, spk_sig),
        )
        self._conn.commit()

    def check_credentials(self, username: str, password_hash: str) -> bool:
        """
        Verify login credentials.

        Returns True if both the username exists and the stored password_hash
        matches the provided one.  Comparison is constant-time via HMAC to
        prevent timing attacks (though in a real system, use bcrypt/Argon2).
        """
        import hmac
        row = self._conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            return False
        # hmac.compare_digest prevents timing oracle
        return hmac.compare_digest(row[0], password_hash)

    def get_user_keys(self, username: str) -> Optional[Tuple[str, str, str]]:
        """
        Return (ik_pub, spk_pub, spk_sig) for *username*, or None if not found.

        These are returned verbatim to LOOKUP requesters; the requesting client
        is responsible for verifying the SPK signature before trusting the keys.
        """
        row = self._conn.execute(
            "SELECT ik_pub, spk_pub, spk_sig FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return row  # (ik_pub_b64, spk_pub_b64, spk_sig_b64) or None
