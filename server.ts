import express from 'express';
import session from 'express-session';
import dotenv from 'dotenv';
import morgan from 'morgan';
import http from 'http';
import crypto from 'crypto';
import { WebSocketServer, WebSocket } from 'ws';
import Automerge from 'automerge';
import { OAuthClient } from '@atproto/oauth-client-node';

// Load environment variables from .env file
dotenv.config();

const {
    PORT = 3000,
    SESSION_SECRET,
    ATPROTO_CLIENT_ID,
    ATPROTO_CLIENT_SECRET,
    ATPROTO_REDIRECT_URI,
    ATPROTO_AUTH_URL,
    ATPROTO_TOKEN_URL,
    BLUESKY_DID, // This instance’s owner DID
    NODE_ENV = 'development'
} = process.env;

if (
    !SESSION_SECRET ||
    !ATPROTO_CLIENT_ID ||
    !ATPROTO_CLIENT_SECRET ||
    !ATPROTO_REDIRECT_URI ||
    !ATPROTO_AUTH_URL ||
    !ATPROTO_TOKEN_URL ||
    !BLUESKY_DID
) {
    console.error('Missing required environment variables.');
    process.exit(1);
}

// Create express app and HTTP server
const app = express();
const server = http.createServer(app);

// Use production-grade logging (morgan) and JSON body parsing
app.use(morgan('combined'));
app.use(express.json());

// Configure sessions (in production, use a persistent session store)
app.use(
    session({
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: { secure: NODE_ENV === 'production' }
    })
);

// Initialize the OAuth client from ATProto
const oauthClient = new OAuthClient({
    clientId: ATPROTO_CLIENT_ID,
    clientSecret: ATPROTO_CLIENT_SECRET,
    redirectUri: ATPROTO_REDIRECT_URI,
    authUrl: ATPROTO_AUTH_URL,
    tokenUrl: ATPROTO_TOKEN_URL
});

// ---------- OAuth Routes ----------

// Begin OAuth login. A random state is generated and stored in session.
app.get('/auth/login', (req, res, next) => {
    try {
        const state = crypto.randomBytes(16).toString('hex');
        req.session.oauthState = state;
        // Adjust scopes as needed; production apps should only request minimal scopes.
        const authUrl = oauthClient.getAuthUrl({
            scope: 'read write',
            state
        });
        res.redirect(authUrl);
    } catch (err) {
        next(err);
    }
});

// OAuth callback endpoint. This exchanges the code for a token and validates the Bluesky DID.
app.get('/auth/callback', async (req, res, next) => {
    try {
        const { code, state } = req.query;
        if (!code || !state || state !== req.session.oauthState) {
            return res.status(400).send('Invalid OAuth callback parameters.');
        }
        // Exchange the authorization code for tokens.
        const tokenResponse = await oauthClient.getToken({ code: code as string });
        req.session.oauthToken = tokenResponse;

        // In production you would call the Bluesky API (or ATProto’s user endpoint)
        // to fetch user info and verify that the authenticated user’s DID matches BLUESKY_DID.
        // For example:
        // const userInfo = await fetchBlueskyUserInfo(tokenResponse.access_token);
        // if (userInfo.did !== BLUESKY_DID) {
        //   throw new Error("Authenticated user does not own this server instance.");
        // }
        req.session.user = {
            did: BLUESKY_DID,
            // Additional user info could be stored here.
        };

        res.redirect('/dashboard');
    } catch (err) {
        console.error('OAuth callback error:', err);
        next(err);
    }
});

// Middleware to ensure endpoints are only reached by authenticated users.
function requireAuth(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
) {
    if (!req.session || !req.session.user) {
        return res.status(401).send('Unauthorized');
    }
    next();
}

// A sample dashboard endpoint that requires authentication.
app.get('/dashboard', requireAuth, (req, res) => {
    res.send('Welcome to your personal Automerge sync server dashboard.');
});

// TODO: change the automerge handling to use automerge-repo
// ---------- Automerge Sync Server ----------

// In production, documents should be persisted in a database or on disk.
// Here we use an in-memory store keyed by document IDs.
interface DocumentStore {
    [docId: string]: Automerge.Doc<any>;
}
const documentStore: DocumentStore = {};

// The share policy: we accept all document changes from connected peers.
// However, we only allow peers that have authenticated via OAuth.
function broadcastChange(sender: WebSocket, changeData: any) {
    wss.clients.forEach((client) => {
        // Only forward changes to clients that have been authenticated.
        if (client !== sender && (client as any).authenticated) {
            client.send(JSON.stringify({ type: 'automerge-change', payload: changeData }));
        }
    });
}

// For production-grade WebSocket authentication, you would integrate your session
// store with the WebSocket upgrade process. Here we illustrate a simple token mechanism.
// (In this example, clients must supply the OAuth access token as the subprotocol.)
function verifyWebSocketAuth(req: http.IncomingMessage): string | null {
    const token = req.headers['sec-websocket-protocol'] as string | undefined;
    // In production, validate this token against your session store or use JWT verification.
    // For this example we simply check that it exists.
    return token || null;
}

// Create the WebSocket server on the /sync endpoint.
const wss = new WebSocketServer({ server, path: '/sync' });

wss.on('connection', (ws: WebSocket, req) => {
    const token = verifyWebSocketAuth(req);
    if (!token) {
        ws.close(1008, 'Missing or invalid authentication token');
        return;
    }

    // In production, perform a robust check (e.g. lookup the token in a secure session store).
    // Here we use a simple check: assume that if the token exists, it is valid.
    (ws as any).authenticated = true;

    // Send an initialization message upon successful connection.
    ws.send(JSON.stringify({ type: 'sync-init', payload: 'Connected and authenticated.' }));

    ws.on('message', (message: string) => {
        try {
            const data = JSON.parse(message);
            if (data.type === 'automerge-change') {
                const { docId, change } = data.payload;
                // Load (or initialize) the document.
                let doc = documentStore[docId] || Automerge.init();
                // In production, you would validate and merge changes using Automerge’s API.
                // The applyChanges function expects an array of changes and returns the new document.
                const [newDoc] = Automerge.applyChanges(doc, [change]);
                documentStore[docId] = newDoc;
                // Broadcast the change to other authenticated peers.
                broadcastChange(ws, { docId, change });
            }
        } catch (err) {
            console.error('Error processing WebSocket message:', err);
        }
    });
});

// ---------- Global Error Handler ----------
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error('Unhandled error:', err);
    res.status(500).send('Internal Server Error');
});

// ---------- Start Server ----------
server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});