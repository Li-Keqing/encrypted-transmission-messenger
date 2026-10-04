"""
server/server.py
================
Relay server for the E2EE messaging system.

The server is honest-but-curious (A3 threat model): it faithfully routes
messages and stores public keys, but may inspect any data it handles.
By design, the server NEVER sees plaintext — only ciphertext envelopes and
routing metadata (sender username, recipient username).

Responsibilities:
  1. User registration  – store username, password hash, and public keys (IK, SPK).
  2. User login         – verify credentials and tag the WebSocket as authenticated.
  3. Key distribution   – respond to LOOKUP with ik_pub, spk_pub, and spk_sig.
  4. Message routing    – forward SEND envelopes to the named recipient as INCOMING.

What the server intentionally does NOT do:
  - Decrypt or inspect ciphertext (it has no keys).
  - Modify any field inside the E2EE envelope.
  - Generate or substitute cryptographic keys.

Storage:
  SQLite database at server/relay.db with two tables:
    users   (username, password_hash, ik_pub, spk_pub, spk_sig)
    -- No message storage in the base implementation (online-only delivery).

Transport:
  WebSocket (asyncio + websockets library) on 0.0.0.0:8765 by default.
"""

import asyncio
import json
import sqlite3
import argparse
from pathlib import Path
from typing import Dict, Optional

import websockets

from server.db import Database
from shared.messages import (
    unpack, pack,
    make_ack, make_error,
    MSG_REGISTER, MSG_LOGIN, MSG_LOOKUP, MSG_SEND, MSG_INCOMING,
    b64d, b64e,
)

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8765
DB_PATH = Path(__file__).parent / "relay.db"


class RelayServer:
    """
    Manages connected clients and routes encrypted messages.

    Attributes:
      db          – Database wrapper (SQLite)
      _sessions   – {websocket: username} for authenticated connections
      _online     – {username: websocket} for online user lookup
    """

    def __init__(self, db_path: Path):
        self.db = Database(db_path)
        self._sessions: Dict = {}    # websocket → username
        self._online:   Dict = {}    # username → websocket

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def handler(self, websocket) -> None:
        """
        Per-connection coroutine: process messages until the client disconnects.
        """
        try:
            async for raw in websocket:
                await self._dispatch(websocket, raw)
        except websockets.ConnectionClosed:
            pass
        finally:
            self._cleanup(websocket)

    def _cleanup(self, websocket) -> None:
        """Remove a disconnected client from session and online maps."""
        username = self._sessions.pop(websocket, None)
        if username and self._online.get(username) is websocket:
            del self._online[username]

    # ------------------------------------------------------------------
    # Message dispatcher
    # ------------------------------------------------------------------

    async def _dispatch(self, ws, raw: str) -> None:
        """Route an incoming raw JSON string to the appropriate handler."""
        try:
            msg = unpack(raw)
        except json.JSONDecodeError:
            await ws.send(make_error("Invalid JSON"))
            return

        msg_type = msg.get("type")

        if msg_type == MSG_REGISTER:
            await self._handle_register(ws, msg)
        elif msg_type == MSG_LOGIN:
            await self._handle_login(ws, msg)
        elif msg_type == MSG_LOOKUP:
            await self._handle_lookup(ws, msg)
        elif msg_type == MSG_SEND:
            await self._handle_send(ws, msg)
        else:
            await ws.send(make_error(f"Unknown message type: {msg_type!r}"))

    # ------------------------------------------------------------------
    # REGISTER handler
    # ------------------------------------------------------------------

    async def _handle_register(self, ws, msg: dict) -> None:
        """
        Store a new user's credentials and public keys.

        Stores:
          username      – unique identifier
          password_hash – SHA-256 hex (never the plaintext password)
          ik_pub        – base64 Ed25519 public verify key
          spk_pub       – base64 X25519 signed pre-key public key
          spk_sig       – base64 Ed25519 signature over spk_pub by ik

        Note: The server stores these opaque bytes without validating the
        signature — that is the recipient's job during LOOKUP processing.
        """
        try:
            username = msg["username"]
            ik_pub   = msg["ik_pub"]
            spk_pub  = msg["spk_pub"]
            spk_sig  = msg["spk_sig"]
            pw_hash  = msg["password_hash"]
        except KeyError as exc:
            await ws.send(make_error(f"Missing field: {exc}"))
            return

        if self.db.user_exists(username):
            await ws.send(make_error(f"Username '{username}' already taken."))
            return

        self.db.add_user(username, pw_hash, ik_pub, spk_pub, spk_sig)
        print(f"[+] Registered: {username}")
        await ws.send(make_ack(f"Registered as '{username}'"))

    # ------------------------------------------------------------------
    # LOGIN handler
    # ------------------------------------------------------------------

    async def _handle_login(self, ws, msg: dict) -> None:
        """
        Authenticate a user and mark their WebSocket as logged in.

        On success, maps username → websocket in _online so that incoming
        SEND messages can be delivered immediately.
        """
        try:
            username = msg["username"]
            pw_hash  = msg["password_hash"]
        except KeyError as exc:
            await ws.send(make_error(f"Missing field: {exc}"))
            return

        if not self.db.check_credentials(username, pw_hash):
            await ws.send(make_error("Invalid username or password."))
            return

        self._sessions[ws] = username
        self._online[username] = ws
        print(f"[+] Login: {username}")
        await ws.send(make_ack(f"Logged in as '{username}'"))

    # ------------------------------------------------------------------
    # LOOKUP handler
    # ------------------------------------------------------------------

    async def _handle_lookup(self, ws, msg: dict) -> None:
        """
        Return a peer's public keys (ik_pub, spk_pub, spk_sig) to the requester.

        The server returns these values exactly as stored at registration — it
        does not modify them.  The requesting client MUST verify the SPK
        signature against ik_pub before trusting the SPK (see protocol.py).

        This satisfies A3 (honest-but-curious): the server returns real keys
        because it is honest; but even if it were malicious (A5 bonus), the
        SPK signature check would catch a key substitution.
        """
        if ws not in self._sessions:
            await ws.send(make_error("Not authenticated."))
            return

        target = msg.get("target")
        if not target:
            await ws.send(make_error("Missing field: target"))
            return

        row = self.db.get_user_keys(target)
        if row is None:
            await ws.send(make_error(f"User '{target}' not found."))
            return

        ik_pub, spk_pub, spk_sig = row
        await ws.send(pack(
            "LOOKUP_RESPONSE",
            target=target,
            ik_pub=ik_pub,
            spk_pub=spk_pub,
            spk_sig=spk_sig,
        ))

    # ------------------------------------------------------------------
    # SEND / INCOMING handler
    # ------------------------------------------------------------------

    async def _handle_send(self, ws, msg: dict) -> None:
        """
        Forward a ciphertext envelope from sender to recipient.

        The server:
          - Checks that the sending WebSocket is authenticated.
          - Verifies the claimed sender matches the session username.
          - Looks up the recipient's active WebSocket.
          - Forwards the full envelope as an INCOMING message, unchanged.

        The server does NOT inspect, decrypt, or modify any E2EE fields
        (eph_pub, ciphertext, nonce, sender_ik_pub, sig, seq).
        """
        sender_session = self._sessions.get(ws)
        if not sender_session:
            await ws.send(make_error("Not authenticated."))
            return

        try:
            sender    = msg["sender"]
            recipient = msg["recipient"]
        except KeyError as exc:
            await ws.send(make_error(f"Missing field: {exc}"))
            return

        # Prevent sender spoofing: the session must match the claimed sender.
        if sender != sender_session:
            await ws.send(make_error("Sender identity mismatch."))
            return

        recipient_ws = self._online.get(recipient)
        if recipient_ws is None:
            await ws.send(make_error(f"User '{recipient}' is not online."))
            return

        # Build INCOMING envelope — identical fields, just a type change.
        incoming = pack(
            MSG_INCOMING,
            sender=sender,
            recipient=recipient,
            eph_pub=msg.get("eph_pub", ""),
            ciphertext=msg.get("ciphertext", ""),
            nonce=msg.get("nonce", ""),
            sender_ik_pub=msg.get("sender_ik_pub", ""),
            sig=msg.get("sig", ""),
            seq=msg.get("seq", -1),
        )
        try:
            await recipient_ws.send(incoming)
        except websockets.ConnectionClosed:
            self._cleanup(recipient_ws)
            await ws.send(make_error(f"'{recipient}' disconnected before delivery."))
            return

        await ws.send(make_ack("Delivered"))
        print(f"[>] {sender} → {recipient} (seq={msg.get('seq')})")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _serve(host: str, port: int, db_path: Path) -> None:
    relay = RelayServer(db_path)
    print(f"[*] Relay server listening on ws://{host}:{port}")
    async with websockets.serve(relay.handler, host, port):
        await asyncio.Future()   # run forever


def main():
    parser = argparse.ArgumentParser(description="E2EE Relay Server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--db",   default=str(DB_PATH))
    args = parser.parse_args()
    asyncio.run(_serve(args.host, args.port, Path(args.db)))


if __name__ == "__main__":
    main()
