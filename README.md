# FreeFlow Windows Client

Standalone Windows GUI client for the FreeFlow DNS-based covert messaging protocol. Built with Go + Fyne — produces a single `.exe` with **no external dependencies** (no .NET, no C++ Redistributable).

## Features

- **Chats** — Messenger-style E2E encrypted messaging with blue/gray bubbles, delivery status, inbox sync
- **Contacts** — Add/remove contacts by name + X25519 public key, view fingerprint, copy keys
- **Bulletins** — Ed25519-signed broadcasts from the Oracle with verification badges
- **Connection** — Connect/disconnect, ping, DNS cache test, discover, live connection and dev query logs
- **Settings** — Oracle config, DNS encoding picker (proquint/hex/lexical), HTTP relay, identity management, dev mode

## Cryptography

| Component | Algorithm |
|-----------|-----------|
| Key Agreement | X25519 ECDH |
| Session Keys | HKDF-SHA256 (info: `freeflow-v2-session`) |
| E2E Keys | HKDF-SHA256 (info: `freeflow-e2e-v1`) |
| Symmetric Cipher | ChaCha20-Poly1305 |
| Session Tokens | HMAC-SHA256 rotating per query |
| Fingerprints | SHA-256(pubkey)[0:8] |
| Bulletins | Ed25519 signatures |

## Protocol

Implements FreeFlow Protocol v2.1:
- 4-query HELLO handshake with ephemeral X25519 keys
- Single 40-byte REGISTER with 3x retry and fingerprint verification
- SEND_MSG with per-fragment recipient fingerprint, 4B ciphertext for proquint
- GET_MSG CHECK/FETCH/ACK sub-protocol
- Proquint DNS encoding (CVCVC pattern) for censored networks
- Per-query `q-<nonce>` subdomain for cache isolation
- Even byte-length frames for proquint compatibility
- 0xFF error response checking

## Build

```bash
# Native (requires Go 1.21+)
go build -o FreeFlow.exe .

# Cross-compile from Linux
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -o FreeFlow.exe -ldflags="-s -w -H windowsgui" .
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o FreeFlow-arm64.exe -ldflags="-s -w" .
```

## Project Structure

```
main.go                — App entry, Fyne window + tabs
protocol/
  frame.go             — 8-byte header, build/parse
  commands.go          — Command codes 0x01-0x08, 0xFF
  proquint.go          — Proquint encoding/decoding
  aaaa.go              — AAAA response decoding
crypto/
  keys.go              — X25519 key generation with clamping
  session.go           — HKDF, HELLO mask, HMAC tokens
  e2e.go               — E2E ChaCha20-Poly1305 encryption
client/
  connection.go        — Full protocol client
identity/
  identity.go          — Identity, fingerprints, contacts
ui/
  app_context.go       — Shared UI state
  chats.go             — Chats tab
  contacts.go          — Contacts tab
  bulletins.go         — Bulletins tab
  connection.go        — Connection tab
  settings.go          — Settings tab
data/
  state.go             — App state, persistence
```
