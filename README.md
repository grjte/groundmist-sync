# Groundmist Personal Sync Server

A personal sync server that enables secure document synchronization across devices using [Automerge](https://automerge.org/) and ATProto (Bluesky) identity for authentication. The server allows you to maintain synchronized, conflict-free documents across multiple devices while ensuring only authorized users can access their data.

## How It Works

### Authentication Flow
1. Initial Authentication:
   - User logs in via OAuth in a client application
   - The client application obtains an ATProto access token and DPoP proof
   - The client uses the ATProto OAuth session fetch handler to connect to this sync server

2. Server Verification:
   - The server verifies the DPoP proof and access token provided by the client
   - The server validates that the user's DID matches the configured ATPROTO_DID
   - Upon successful verification, the server issues a sync token for WebSocket connections

3. WebSocket Authentication:
   - The client uses the issued sync token to establish WebSocket connections
   - Each WebSocket connection is authenticated using the sync token
   - Only connections with valid sync tokens can participate in document synchronization

### Document Synchronization
1. The server uses Automerge for conflict-free document synchronization:
   - Documents are stored in a local filesystem using `@automerge/automerge-repo-storage-nodefs`
   - Real-time sync is handled via WebSocket connections using `@automerge/automerge-repo-network-websocket`
   - Each lexicon (document type) group has its own storage directory and sync network

### Security Model
- Authentication is required for all WebSocket connections
- Each session gets a unique token for WebSocket authentication
- Documents are organized by lexicon authority domains for isolation
- Only the configured Bluesky DID can access the server

## Setup

1. Clone this repository
2. Install dependencies:
   ```
   npm install
   ```
3. Copy the example environment file and update it with your settings:
   ```
   cp .env.example .env
   ```
4. Configure your `.env` file:
   ```
   ATPROTO_DID=did:plc:your-bluesky-did
   GROUNDMIST_SYNC_SECRET_KEY=your-secret-key # generate with 'openssl rand -hex 64'
   PORT=3030 # Optional, defaults to 3031
   DATA_DIR=.data # Optional, defaults to .data
   ```

## Running the Application

1. Ensure your server is accessible via a public URL (required for Bluesky OAuth)

2. Build and start the server:
   ```
   npm run build
   npm start
   ```

3. The server will be running at `http://localhost:3031` (or your configured PORT)

## Environment Variables

- `ATPROTO_DID`: Your Bluesky DID (only this DID will be allowed to sync)
- `GROUNDMIST_SYNC_SECRET_KEY`: A secret key for signing sync tokens
- `PORT`: (Optional) The port to run the server on (default: 3031)
- `DATA_DIR`: (Optional) Directory to store synchronized documents (default: .data)

## License

MIT