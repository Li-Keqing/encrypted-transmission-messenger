"""
client/client.py
================
Command-line interface and WebSocket networking for the E2EE client.

Responsibilities:
  - Open a persistent WebSocket connection to the relay server.
  - Run an asynchronous receive loop that prints decrypted incoming messages.
  - Parse user commands and dispatch to the protocol layer.

Available commands (after login):
  /register <username> <password>   Create a new account on the relay.
  /login <username> <password>      Authenticate and open a session.
  /lookup <username>                Fetch and cache a peer's public keys.
  /msg <username> <text...>         Send an encrypted message.
  /quit                             Close the connection and exit.

Usage:
  python -m client.client [--host HOST] [--port PORT]

The client connects to ws://HOST:PORT by default (localhost:8765).
TLS (wss://) should be used in production; under the project's threat model the
network is adversarial (A1/A2), but E2EE security does NOT rely on TLS —
TLS is an optional transport hardening layer only.
"""

import asyncio
import json
import sys
import argparse
from typing import Optional

import websockets

from client.keystore import KeyStore
from client.protocol import (
    build_register, build_login, build_lookup, build_send,
    process_incoming, process_lookup_response,
    ProtocolError, SecurityError,
)
from shared.messages import unpack, MSG_ACK, MSG_ERROR, MSG_INCOMING


DEFAULT_HOST = "localhost"
DEFAULT_PORT = 8765


class Client:
    """
    Manages the WebSocket connection and coordinates protocol + UI.

    Attributes:
      ks  – KeyStore for the logged-in user (None until login succeeds)
      ws  – active WebSocket connection
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.ks: Optional[KeyStore] = None
        self.ws = None
        self._responses: asyncio.Queue[dict] = asyncio.Queue()

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the WebSocket connection to the relay server."""
        uri = f"ws://{self.host}:{self.port}"
        self.ws = await websockets.connect(uri)
        print(f"[*] Connected to relay at {uri}")

    async def disconnect(self) -> None:
        """Close the WebSocket connection gracefully."""
        if self.ws:
            await self.ws.close()
        print("[*] Disconnected.")

    # ------------------------------------------------------------------
    # Low-level send / receive
    # ------------------------------------------------------------------

    async def _send(self, msg: str) -> None:
        """Send a JSON string over the WebSocket."""
        await self.ws.send(msg)

    async def _recv(self) -> dict:
        """Receive one JSON message from the WebSocket and parse it."""
        raw = await self.ws.recv()
        return unpack(raw)

    async def _recv_response(self) -> dict:
        """Wait for the next server response enqueued by the receive loop."""
        return await self._responses.get()

    # ------------------------------------------------------------------
    # Protocol command handlers
    # ------------------------------------------------------------------

    async def cmd_register(self, username: str, password: str) -> None:
        """
        Register a new account.
        Generates keys (if not already on disk), sends REGISTER, waits for ACK.
        """
        self.ks = KeyStore.load(username)
        msg = build_register(self.ks, password)
        await self._send(msg)
        resp = await self._recv_response()
        if resp.get("type") == MSG_ACK:
            print(f"[+] Registered as '{username}'.")
        else:
            print(f"[-] Registration failed: {resp.get('reason', 'unknown error')}")
            self.ks = None

    async def cmd_login(self, username: str, password: str) -> None:
        """
        Authenticate with the relay server.
        On success, loads/creates the local keystore for *username*.
        """
        self.ks = KeyStore.load(username)
        msg = build_login(username, password)
        await self._send(msg)
        resp = await self._recv_response()
        if resp.get("type") == MSG_ACK:
            print(f"[+] Logged in as '{username}'.")
        else:
            print(f"[-] Login failed: {resp.get('reason', 'unknown error')}")
            self.ks = None

    async def cmd_lookup(self, target: str) -> None:
        """
        Fetch and cryptographically verify a peer's public keys from the relay.
        Keys are cached in the keystore for subsequent /msg calls.
        """
        if not self.ks:
            print("[-] Not logged in.")
            return
        await self._send(build_lookup(target))
        resp = await self._recv_response()
        ok = process_lookup_response(self.ks, resp, target)
        if ok:
            print(f"[+] Public keys for '{target}' verified and cached.")
        else:
            print(f"[-] LOOKUP failed or SPK signature invalid for '{target}'.")

    async def cmd_msg(self, recipient: str, text: str) -> None:
        """
        Encrypt *text* for *recipient* and deliver it via the relay.
        The caller must have run /lookup <recipient> beforehand.
        """
        if not self.ks:
            print("[-] Not logged in.")
            return
        try:
            wire = build_send(self.ks, recipient, text)
        except ProtocolError as exc:
            print(f"[-] {exc}")
            return
        await self._send(wire)
        resp = await self._recv_response()
        if resp.get("type") == MSG_ACK:
            print(f"[>] Message delivered to '{recipient}'.")
        else:
            print(f"[-] Delivery failed: {resp.get('reason', 'unknown error')}")

    # ------------------------------------------------------------------
    # Receive loop (runs concurrently with the input loop)
    # ------------------------------------------------------------------

    async def _receive_loop(self) -> None:
        """
        Continuously listen for INCOMING messages from the relay.

        For each message:
          1. Check replay (seq number).
          2. Verify Ed25519 signature.
          3. Derive session key via ECDH.
          4. Decrypt and print plaintext.

        Any SecurityError or ProtocolError is printed and the message discarded.
        """
        try:
            async for raw in self.ws:
                msg = unpack(raw)
                if msg.get("type") != MSG_INCOMING:
                    await self._responses.put(msg)
                    continue
                if not self.ks:
                    print("[!] Received message but not logged in — ignoring.")
                    continue
                try:
                    sender, plaintext = process_incoming(self.ks, raw)
                    print(f"\n[{sender}] {plaintext}")
                except SecurityError as exc:
                    print(f"\n[!] Security check failed, message discarded: {exc}")
                except ProtocolError as exc:
                    print(f"\n[!] Protocol error: {exc}")
        except websockets.ConnectionClosed:
            print("[*] Connection closed by server.")

    # ------------------------------------------------------------------
    # Input loop
    # ------------------------------------------------------------------

    async def _input_loop(self) -> None:
        """
        Read commands from stdin and dispatch them.

        Runs in the same event loop as _receive_loop() via asyncio.gather().
        """
        loop = asyncio.get_event_loop()
        while True:
            try:
                line = await loop.run_in_executor(None, sys.stdin.readline)
            except EOFError:
                break
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            cmd = parts[0].lower()

            if cmd == "/register" and len(parts) >= 3:
                await self.cmd_register(parts[1], parts[2])
            elif cmd == "/login" and len(parts) >= 3:
                await self.cmd_login(parts[1], parts[2])
            elif cmd == "/lookup" and len(parts) >= 2:
                await self.cmd_lookup(parts[1])
            elif cmd == "/msg" and len(parts) >= 3:
                recipient = parts[1]
                text = " ".join(parts[2:])
                await self.cmd_msg(recipient, text)
            elif cmd == "/quit":
                await self.disconnect()
                break
            else:
                print("Commands: /register <u> <p>  /login <u> <p>  "
                      "/lookup <u>  /msg <u> <text>  /quit")

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Connect, then run the receive and input loops concurrently."""
        await self.connect()
        print("Commands: /register <u> <p>  /login <u> <p>  "
              "/lookup <u>  /msg <u> <text>  /quit")
        await asyncio.gather(self._receive_loop(), self._input_loop())


def main():
    parser = argparse.ArgumentParser(description="E2EE Messaging Client")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    client = Client(args.host, args.port)
    asyncio.run(client.run())


if __name__ == "__main__":
    main()
