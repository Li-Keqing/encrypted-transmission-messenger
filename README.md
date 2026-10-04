# E2EE Messenger — COMP 5355 Project (Task 1)

End-to-End Encrypted one-to-one messaging system.  
Plaintext exists only at the two communicating endpoints; the relay server and the network handle ciphertext only.

This project is a command-line application, not a web app. You run a relay server plus one client process per user, then type chat commands in the terminal. When messages arrive, the recipient sees decrypted plaintext printed directly in the client terminal.

---

## Table of Contents

1. [What the Project Does](#1-what-the-project-does)
2. [Technical Stack](#2-technical-stack)
3. [Project Structure](#3-project-structure)
4. [Code Segment Guide](#4-code-segment-guide)
5. [Security Design](#5-security-design)
6. [Run in VS Code](#6-run-in-vs-code)
7. [Build and Run Instructions](#7-build-and-run-instructions)
8. [Scripted Demo](#8-scripted-demo)
9. [Publish to GitHub](#9-publish-to-github)

---

## 1. What the Project Does

This project implements a small end-to-end encrypted messenger with three pieces:

- A relay server that handles registration, login, public-key lookup, and message forwarding.
- A command-line client that lets each user register, log in, fetch a peer's public keys, and send encrypted messages.
- Local key storage in `~/.e2ee-messenger/<user>.json` so each user keeps their own identity keys and replay counters.

What you can observe when it runs:

- The server prints connection and routing events in its terminal.
- Each client terminal shows the command prompt and any decrypted incoming messages.
- There is no browser UI. The visible demonstration is the terminal conversation itself.

---

## 2. Technical Stack

### Mandated by the course

| Requirement | Choice | Reason |
|---|---|---|
| **Vetted cryptographic library** | **PyNaCl 1.5.0** (libsodium bindings) | The course prohibits implementing raw primitives; PyNaCl wraps the production-grade libsodium library, which provides Ed25519, X25519, and XSalsa20-Poly1305. |
| **No home-made primitives** | All crypto ops call PyNaCl | We compose standard primitives into a protocol; no custom ciphers or MACs. |
| **No secrets in network traffic** | All key material stays at endpoints | The relay server stores only public keys and password hashes; private keys never leave the client process. |

### Optional choices (free design decisions)

| Choice | Decision | Rationale |
|---|---|---|
| **Programming language** | Python 3.11+ | Readable, easy to audit, PyNaCl available. |
| **Transport protocol** | WebSocket (asyncio + `websockets` 12.0) | Full-duplex, real-time delivery with a simple API; fits the online-delivery model. |
| **Message encoding** | JSON | Human-readable wire format; easy to inspect during development and in the report. |
| **Server storage** | SQLite 3 (stdlib `sqlite3`) | Zero-dependency, sufficient for a demo; stores only public keys and password hashes. |
| **User interface** | Command-line (CLI) | A minimal CLI clearly demonstrates the protocol with no extra complexity. |
| **Key storage** | Local JSON file (`~/.e2ee-messenger/<user>.json`) | Simple; acceptable for a course project. |

---

## 3. Project Structure

```
e2ee-messenger/
├── shared/
│   ├── __init__.py
│   └── messages.py          # Wire-format definitions (JSON schemas)
├── client/
│   ├── __init__.py
│   ├── crypto.py            # All cryptographic primitives (PyNaCl)
│   ├── keystore.py          # Key persistence and replay-protection counters
│   ├── protocol.py          # Protocol logic: build and process messages
│   └── client.py            # CLI entry point and WebSocket networking
├── server/
│   ├── __init__.py
│   ├── db.py                # SQLite database wrapper
│   └── server.py            # Relay server: registration, login, key lookup, routing
├── requirements.txt
└── README.md                # This file
```

---

## 4. Code Segment Guide

Each file has a single, well-defined responsibility.  The table below explains
what each code segment does and which security requirements it satisfies.

---

### `shared/messages.py` — Wire-format definitions

**Purpose:** Defines every JSON message type exchanged between client and server.  
Provides `pack()` / `unpack()` helpers and typed constructors for each message type.

| Function / Constant | What it does |
|---|---|
| `MSG_REGISTER`, `MSG_LOGIN`, … | String constants for the `"type"` field in every envelope. |
| `pack(msg_type, **fields)` | Serialise a dict to a JSON string ready to send over the wire. |
| `unpack(raw)` | Parse an incoming JSON string back to a dict. |
| `b64e(data)` / `b64d(s)` | Encode/decode raw bytes to URL-safe base64 for JSON transport. |
| `make_register(…)` | Build a `REGISTER` envelope with the user's public keys. |
| `make_login(…)` | Build a `LOGIN` envelope with username and password hash. |
| `make_lookup(target)` | Build a `LOOKUP` request. |
| `make_send(…)` | Build a `SEND` envelope containing all E2EE fields: `eph_pub`, `ciphertext`, `nonce`, `sender_ik_pub`, `sig`, `seq`. |
| `make_ack(…)` / `make_error(…)` | Build server response envelopes. |

**Security note:** Fields marked `[E2E]` in the docstring are opaque base64 blobs to the server.  The server routes but never reads them.

---

### `client/crypto.py` — Cryptographic primitives

**Purpose:** Wraps PyNaCl to implement every cryptographic operation needed by the protocol.  No crypto logic exists anywhere else.

| Function | What it does | Security requirement |
|---|---|---|
| `generate_identity_key()` | Generate a fresh Ed25519 signing key pair (IK). | SR3 — sender authenticity |
| `generate_prekey()` | Generate an X25519 signed pre-key pair (SPK). | SR1, SR5 — confidentiality, forward secrecy |
| `generate_ephemeral_key()` | Generate a one-shot X25519 ephemeral key (EK). | SR5 — forward secrecy (key is discarded after derivation) |
| `sign_prekey(ik, spk_pub)` | Ed25519 signature over SPK public bytes by IK. | SR3, SR6 — SPK authenticity, malicious-server resistance |
| `verify_prekey_sig(ik_verify, spk_pub, sig)` | Verify the SPK signature before trusting it. | SR3, SR6 |
| `derive_session_key(ek_priv, peer_spk_pub)` | X25519 ECDH + BLAKE2b-256 KDF → 32-byte session key. | SR1 — session key confidentiality |
| `encrypt_message(session_key, plaintext)` | XSalsa20-Poly1305 encryption; returns `(nonce, ciphertext)`. | SR1, SR2 — confidentiality and integrity |
| `decrypt_message(session_key, nonce, ciphertext)` | XSalsa20-Poly1305 decryption; raises `CryptoError` on bad MAC. | SR2 — integrity check |
| `sign_message(ik, nonce, ciphertext)` | Ed25519 signature over `nonce ‖ ciphertext`. | SR3 — sender authenticity |
| `verify_message_sig(ik_verify, nonce, ciphertext, sig)` | Verify the per-message signature. | SR3 |
| `hash_password(password)` | SHA-256 hex of password (server auth only, not E2EE). | Server authentication |
| `ik_to_bytes` / `ik_from_bytes` / `spk_to_bytes` / `spk_from_bytes` | Key serialisation helpers for the keystore. | — |

**Key derivation detail:**
```
shared_dh   = X25519(EK_priv,  SPK_pub_peer)      # Diffie-Hellman
session_key = BLAKE2b-256(shared_dh, key=b"e2ee-msg-v1")   # KDF
```
The `b"e2ee-msg-v1"` salt provides domain separation — the same DH output cannot be reused for a different protocol.

---

### `client/keystore.py` — Key persistence and replay protection

**Purpose:** Loads/saves the user's key material from disk and manages per-sender sequence number counters for replay protection.

| Method | What it does | Security requirement |
|---|---|---|
| `KeyStore.load(username)` | Load keystore from `~/.e2ee-messenger/<user>.json`, or generate fresh keys on first run. | Key management |
| `KeyStore.save()` | Atomically write keystore to disk (write-then-rename). | Key persistence |
| `ks.ik_pub_bytes` | Return raw 32-byte Ed25519 public verify key. | SR3 — sent in REGISTER and SEND |
| `ks.spk_pub_bytes` | Return raw 32-byte X25519 public key. | SR1 — published for ECDH |
| `ks.spk_sig` | Return 64-byte SPK signature for REGISTER. | SR3, SR6 |
| `cache_peer_keys(peer, ik_pub, spk_pub)` | Store a peer's verified public keys for the current session. | SR3 |
| `get_peer_keys(peer)` | Return cached `(ik_verify, spk_pub)` for a peer. | SR3, SR1 |
| `next_seq()` | Return the next outgoing sequence number and increment the counter. | SR4 — replay protection |
| `accept_seq(peer, seq)` | Accept `seq` only if strictly greater than the highest seen from `peer`. | SR4 — rejects replays and duplicates |

**Replay protection logic:**
- Outgoing: each message carries a monotonically increasing `seq`.  The counter persists across restarts so that restarting the client does not reset the counter.
- Incoming: the highest accepted `seq` per sender is stored in `seq_in`; any `seq ≤ highest` is silently rejected before any decryption work is done.

---

### `client/protocol.py` — Protocol operations

**Purpose:** Composes crypto primitives into the full send and receive protocol steps.

| Function | What it does | Security requirement |
|---|---|---|
| `build_register(ks, password)` | Assemble a `REGISTER` wire message from the keystore. | Key publication |
| `build_login(username, password)` | Assemble a `LOGIN` wire message. | Server authentication |
| `build_lookup(target)` | Assemble a `LOOKUP` wire message. | Key distribution |
| `build_send(ks, recipient, plaintext)` | Full send protocol: generate EK → ECDH → discard EK → encrypt → sign → sequence → serialise. | SR1, SR2, SR3, SR4, SR5 |
| `process_incoming(ks, raw)` | Full receive protocol: replay check → sig verify → ECDH → decrypt → return plaintext. | SR1, SR2, SR3, SR4 |
| `process_lookup_response(ks, response, target)` | Parse LOOKUP response, verify SPK sig, cache keys. | SR3, SR6 |

**`build_send` step-by-step:**
1. Retrieve recipient's cached `(ik_verify, spk_pub)`.
2. Generate fresh ephemeral X25519 key pair (EK).
3. Compute `session_key = BLAKE2b(X25519(EK_priv, SPK_pub))`.
4. `del ek` — discard the ephemeral private key immediately.
5. Encrypt plaintext with XSalsa20-Poly1305.
6. Sign `(nonce ‖ ciphertext)` with sender's Ed25519 IK.
7. Increment outgoing sequence counter and persist.
8. Pack into `SEND` JSON.

**`process_incoming` step-by-step:**
1. Parse JSON; raise `ProtocolError` on malformed input.
2. Call `ks.accept_seq(sender, seq)` — raise `SecurityError` on replay.
3. Retrieve sender's cached `(ik_verify, spk_pub)`.
4. Cross-check `sender_ik_pub` in message against cached key — raise on mismatch.
5. Verify Ed25519 signature over `(nonce ‖ ciphertext)`.
6. Compute `session_key = BLAKE2b(X25519(SPK_priv, EK_pub))`.
7. Decrypt with XSalsa20-Poly1305 — raise `SecurityError` on MAC failure.
8. Return `(sender, plaintext)`.

---

### `client/client.py` — CLI entry point and WebSocket I/O

**Purpose:** Runs the user-facing command loop and manages the WebSocket connection to the relay server.

| Component | What it does |
|---|---|
| `Client.__init__` | Store host/port; initialise keystore and WebSocket slots to `None`. |
| `Client.connect()` | Open the WebSocket to `ws://HOST:PORT`. |
| `Client.cmd_register(u, p)` | Call `build_register`, send to server, print result. |
| `Client.cmd_login(u, p)` | Call `build_login`, send to server, load keystore on success. |
| `Client.cmd_lookup(target)` | Call `build_lookup`, send, call `process_lookup_response`. |
| `Client.cmd_msg(recipient, text)` | Call `build_send`, send, confirm ACK. |
| `Client._receive_loop()` | Async loop: receive INCOMING frames, call `process_incoming`, print decrypted text. Silently discards messages that fail security checks. |
| `Client._input_loop()` | Async loop: read stdin, parse commands (`/register`, `/login`, `/lookup`, `/msg`, `/quit`). |
| `Client.run()` | `asyncio.gather(_receive_loop, _input_loop)` — both loops run concurrently. |
| `main()` | Parse `--host` / `--port` CLI args, run `Client.run()`. |

---

### `server/db.py` — SQLite database wrapper

**Purpose:** All database access for the relay server.  The server stores only public-key material and password hashes; it has no access to any private keys.

| Method | What it does |
|---|---|
| `Database.__init__(path)` | Open SQLite connection, create `users` table if absent. |
| `user_exists(username)` | Return `True` if the username is already registered. |
| `add_user(username, pw_hash, ik_pub, spk_pub, spk_sig)` | Insert a new user row with their public keys (all as base64 strings). |
| `check_credentials(username, pw_hash)` | Constant-time comparison of stored vs. provided password hash. |
| `get_user_keys(username)` | Return `(ik_pub, spk_pub, spk_sig)` for LOOKUP responses, or `None`. |

---

### `server/server.py` — Relay server

**Purpose:** Accepts WebSocket connections, handles registration/login/lookup, and routes encrypted envelopes between online users.

| Component | What it does |
|---|---|
| `RelayServer.__init__` | Initialise DB, `_sessions` map (ws → username), `_online` map (username → ws). |
| `RelayServer.handler(ws)` | Per-connection coroutine: dispatch messages, clean up on disconnect. |
| `_handle_register(ws, msg)` | Store username, password hash, and public keys; send ACK. |
| `_handle_login(ws, msg)` | Verify credentials; add to `_online`; send ACK. |
| `_handle_lookup(ws, msg)` | Return stored `(ik_pub, spk_pub, spk_sig)` to requester verbatim. |
| `_handle_send(ws, msg)` | Check session auth, verify sender matches session, forward envelope to recipient's WebSocket as `INCOMING`. |
| `main()` | Parse `--host` / `--port` / `--db` args; run `websockets.serve`. |

**What the server never does:**  
The server never parses `eph_pub`, `ciphertext`, `nonce`, `sender_ik_pub`, or `sig` — these fields are forwarded as opaque strings.  This is architecturally enforced: `server.py` has no import of any crypto library.

---

## 5. Security Design

### Threat model

| Adversary | What they can do | How the system resists |
|---|---|---|
| A1 — Passive network attacker | Observe all traffic | All payloads are ciphertext; nonce and routing metadata leak only message timing and approximate size. |
| A2 — Active network attacker | Modify, replay, or inject messages | Ed25519 signature over `(nonce ‖ ciphertext)` detects injection.  Poly1305 MAC detects modification.  Seq numbers detect replays. |
| A3 — Honest-but-curious server | Read everything it stores and routes | Server only ever sees ciphertext and base64 public keys.  Private keys and plaintext never reach the server. |

### Security requirements

| Requirement | Mechanism |
|---|---|
| SR1 Confidentiality | XSalsa20-Poly1305 encryption; session key derived via X25519 ECDH — only the two endpoints can derive it. |
| SR2 Integrity | Poly1305 MAC built into every ciphertext; `decrypt_message` raises `CryptoError` on any modification. |
| SR3 Authenticity | Ed25519 signature over `(nonce ‖ ciphertext)` by sender's IK; verified before decryption using the IK fetched during LOOKUP. |
| SR4 Replay protection | Monotonically increasing `seq` counter per sender; duplicates/replays rejected before any crypto work. |
| SR5 Forward secrecy (bonus) | Fresh ephemeral X25519 key per message; private key deleted immediately after ECDH.  Compromise of long-term IK or SPK does not expose past session keys. |

### Key-exchange diagram

```
Alice                           Relay Server                      Bob
  |                                 |                               |
  |-- REGISTER (ik_pub, spk_pub, spk_sig) ----------------------->|
  |                                 | (stores public keys)          |
  |-- LOOKUP(bob) ---------------->|                               |
  |<-- (ik_pub_bob, spk_pub_bob, spk_sig_bob) -------------------|
  |   [verify spk_sig_bob vs ik_pub_bob]                          |
  |                                 |                               |
  |   generate EK (ephemeral)       |                               |
  |   session_key = BLAKE2b(        |                               |
  |     X25519(EK_priv, spk_pub_bob)|                               |
  |   )                             |                               |
  |   del EK_priv                   |                               |
  |   (nonce, ct) = Encrypt(session_key, plaintext)               |
  |   sig = Ed25519_sign(ik_alice, nonce ‖ ct)                    |
  |                                 |                               |
  |-- SEND(ct, nonce, EK_pub, sig, seq) -->|                      |
  |                                 |-- INCOMING(…) ------------->|
  |                                 |          [replay check: seq] |
  |                                 |          [verify sig vs ik_alice cached] |
  |                                 |          session_key = BLAKE2b(X25519(spk_priv_bob, EK_pub)) |
  |                                 |          plaintext = Decrypt(session_key, nonce, ct) |
```

---

## 5. Build and Run Instructions

### Prerequisites

- Python 3.11 or later
- `pip`

### Install dependencies

```bash
cd e2ee-messenger
pip install -r requirements.txt
```

### Start the relay server

## 6. Run in VS Code

If you are using VS Code on Windows, open the integrated terminal with `Ctrl+Shift+`` or from the menu Terminal > New Terminal. Run all commands from the project root.

Recommended local environment:

- Use the existing virtual environment at `.venv`.
- If VS Code asks for an interpreter, point it to `.venv\Scripts\python.exe`.

Example PowerShell commands:

```powershell
Set-Location 'e:\PolyU\sem3\Cyber\project\e2ee-messenger'
& '.\.venv\Scripts\python.exe' -m server.server
```

Open a second and third terminal for clients:

```powershell
& '.\.venv\Scripts\python.exe' -m client.client
```

---

## 7. Build and Run Instructions

### Prerequisites

- Python 3.11 or later
- `pip`

### Install dependencies

```bash
cd e2ee-messenger
pip install -r requirements.txt
```

If you already have the included `.venv`, you can skip installation and use that interpreter directly.

### Start the relay server

```bash
python -m server.server
# optional: --host 0.0.0.0 --port 8765 --db server/relay.db
```

### Start a client

Open a new terminal for each user:

```bash
python -m client.client
# optional: --host localhost --port 8765
```

---

## 8. Scripted Demo

Open three terminals: one for the server, one for Alice, and one for Bob.

### Recommended screenshot points

If you are recording a report video or taking screenshots for a portfolio, capture these moments:

1. Right after the server starts and prints `[*] Relay server listening on ws://...`.
2. Right after Alice completes `/register`, `/login`, `/lookup`, and `/msg`.
3. Right after Bob receives the decrypted line `[alice_fix] ...` in the terminal.

If you want one clean demo clip, start recording before the server launch, then keep the three terminals visible side by side and stop after Bob's plaintext appears.

### Terminal 1 - Relay server

```bash
python -m server.server
```

Expected output:

```text
[*] Relay server listening on ws://0.0.0.0:8765
```

### Terminal 2 - Alice

```text
/register alice password123
/login alice password123
/lookup bob
/msg bob Hello Bob! This message is end-to-end encrypted.
```

### Terminal 3 - Bob

```text
/register bob password456
/login bob password456
/lookup alice
```

When Bob is online, he will see Alice's message printed in his client terminal:

```text
[alice] Hello Bob! This message is end-to-end encrypted.
```

Bob can reply with:

```text
/msg alice Hi Alice! Got your message.
```

To exit either client:

```text
/quit
```

---

## 9. Publish to GitHub

This project can be published from VS Code or from PowerShell. Because this workspace is now a Git repository, the normal flow is:

1. Open the project folder in VS Code.
2. Open the Source Control view from the left sidebar.
3. Stage the files you want to publish.
4. Enter a commit message such as `Initial commit` and commit.
5. Create a new empty repository on GitHub.
6. Add the GitHub remote and push the branch.

If you prefer the VS Code UI, the usual path is:

1. Click the Source Control icon.
2. Use the `...` menu if you need to initialize or publish the repository.
3. If VS Code shows `Publish to GitHub`, click it and follow the prompts.
4. If VS Code only shows Git commands, create the GitHub repository first and then push.

Equivalent PowerShell flow from the project root:

```powershell
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin <your-github-repo-url>
git push -u origin main
```

If your GitHub repository already exists, you only need to add the remote once. After that, future updates are:

```powershell
git add .
git commit -m "Update README"
git push
```

Do not commit these generated or local-only files:

- `.venv/`
- `venv/`
- `server/relay.db`
- `~/.e2ee-messenger/*.json`

The included `.gitignore` already excludes the local virtual environment and database file.

If you want a clean terminal screenshot for the README or your report, use the server startup line and the final Bob message line as the two key images. Those two screens show both sides of the demo: the relay server running and the encrypted message successfully arriving.
---

*No private keys, passwords, or secrets are committed to this repository.  
The keystore files (`~/.e2ee-messenger/*.json`) are local only and must not be shared.*
