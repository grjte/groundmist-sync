# Bluesky Personal Sync Server

A production-grade service that provides a Bluesky user with a personal sync server for Automerge documents in any local‑first application they use. Each personal server instance is tied to a Bluesky DID, ensuring that only authenticated peers can sync with the server.

## Features

- **OAuth Authentication:** Uses the ATProto OAuth client to authenticate users via Bluesky.
- **WebSocket Sync:** Provides a secure WebSocket endpoint (`/sync`) for real‑time document synchronization.
- **Automerge Integration:** Accepts all document changes from authenticated peers, applying and broadcasting them.
- **Production‑Grade Practices:** Robust error handling, logging with Morgan, and secure session management.

## Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/bluesky-personal-sync-server.git
   cd bluesky-personal-sync-server