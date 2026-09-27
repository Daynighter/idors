# iDors

iDors is a web-first P2P messenger foundation using WebRTC and WebSocket signaling.

## Structure

- `apps/web` — browser client
- `apps/signaling` — WebSocket signaling service
- `packages/protocol` — shared protocol contracts
- `packages/crypto` — future identity/encryption layer
- `packages/idors-client` — future reusable client SDK
- `docs` — architecture and roadmap

## Run

```bash
npm install
npm start
```

Open `http://localhost:8787`.

This is an MVP foundation, not a full Telegram replacement. TURN, authentication, persistence, encrypted identities, files and calls are planned layers.
