# Groundmist Personal Sync Server

A personal sync server that enables secure document synchronization across devices using [Automerge](https://automerge.org/) and ATProto (Bluesky) identity for authentication. The server allows you to maintain synchronized, conflict-free documents across multiple devices while ensuring only authorized users can access their data.

> ⚠️ **Security Warning: this is a prototype with INCOMPLETE & INSECURE AUTHENTICATION**
> 
> The purpose of this prototype is to demonstrate the possibilities of the personal sync server (PSS) model. It demonstrates a pattern for authentication, but auth is not fully implemented for the following reasons, and **unverified connections are allowed for demonstration purposes.**
>
> - Self-hosted PDSes: this sync server does not currently authenticate opaque atproto access tokens, which are the default format for access tokens of self-hosted atproto PDSes. All requests are approved without authentication. There is currently no straightforward way to validate both the DID ownership and the `client_id` of the application attempting to open a WebSocket connection. We expect this to change in the future, and the purpose of this prototype is to demonstrate the possibilities of the PSS paradigm, so we allow all connection requests that match the DID of the PSS.
> - PDSes hosted by `bsky.social`: at the time of writing, `bsky.social` has switched to the did `did:web:bsky.social` but there is no DID document published at the `.well-known` endpoint (`https://bsky.social/.well-known/did.json`), so we do not perform signature verification of the JWT access token.

## Quick Installation (Self-hosted)

The self-hosting instructions are similar to setting up a self-hosted PDS. This process will:
1. Install the Groundmist Sync Server with SSL certificates
2. Set up the server to run automatically on boot
3. Configure HTTPS with a Let's Encrypt certificate
4. Publish the sync server location to your atproto PDS (with your authorization) so applications can find it

### 1. [Preparation for self-hosting your Groundmist personal sync server (PSS)](https://atproto.com/guides/self-hosting#preparation-for-self-hosting-pds)

### 2. [Open your cloud firewall for HTTP and HTTPS](https://atproto.com/guides/self-hosting#open-your-cloud-firewall-for-http-and-https)

### 3. [Configure DNS for your domain](https://atproto.com/guides/self-hosting#configure-dns-for-your-domain)

Note: only one `A` record is required for your Groundmist PSS, e.g. `sync.example.com`

### 4. [Check that DNS is working as expected](https://atproto.com/guides/self-hosting#configure-dns-for-your-domain)

### 5. Installer on Ubuntu 20.04/22.04 and Debian 11/12

On your server via ssh, download the installer script using wget:

```bash
wget https://raw.githubusercontent.com/grjte/groundmist-sync/main/installer.sh
```

or download it using curl:

```bash
curl https://raw.githubusercontent.com/grjte/groundmist-sync/main/installer.sh >installer.sh
```

And then run the installer using bash:

```bash
sudo bash installer.sh
```

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
> ⚠️ **Security Warning: this is a prototype with INCOMPLETE & INSECURE AUTHENTICATION**
- Authentication is required for all WebSocket connections (note: not fully implemented)
- Each session gets a unique token for WebSocket authentication
- Documents are organized by lexicon authority domains for isolation enabling granular access control (note: unimplemented)
- Only the configured Bluesky DID which owns the personal sync server should be able to access (note: not fully implemented)

## Manual Setup

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

## Running the Application Locally

1. Ensure your server is accessible via a public URL (required for Bluesky OAuth)

2. Build and start the server:
   ```
   npm run build
   npm start
   ```

3. The server will be running at `http://localhost:3031` (or your configured PORT)


## Docker Deployment

You can also run the sync server using Docker:

```bash
docker build -t groundmist-sync .

docker run -d \
  --name groundmist-sync \
  -e GROUNDMIST_SYNC_SECRET_KEY="your-secret-key" \
  -e ATPROTO_DID="did:plc:your-bluesky-did" \
  -p 3031:3031 \
  -v ./data:/app/data \
  --restart unless-stopped \
  groundmist-sync
```

## Publishing to Your Bluesky Account

If you do not use the installer script to set up your sync server (for example, you're running it locally), then you'll need to publish the sync server host to your Bluesky account.

Notes: 
- if your PSS is running locally, you will need to use a proxy for the host.
- When saving the host in your PDS, the protocol should be excluded (e.g. "sync.example.com", not "https://sync.example.com")

```bash
# Set your credentials
export PDS_URL=https://bsky.social # or your self-hosted PDS URL
export HANDLE=your-handle.bsky.social
export PASSWORD=your-password

# Publish your sync server (replace with your actual server URL)
node publishPSS.js sync.example.com
```

## License

MIT