# Architecture

The browser connects to the signaling service through WebSocket. The service assigns temporary peer IDs and relays WebRTC negotiation metadata. Once connected, chat messages use an RTCDataChannel.

Production additions: authenticated identities, persistent encrypted history, TURN fallback, files/media, calls, push notifications, rate limits and observability.
