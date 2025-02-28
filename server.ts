'use strict';

import session from 'express-session';
import express, { Request, Response } from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'http';
import { Agent } from '@atproto/api';
import { NodeOAuthClient, NodeSavedSession, NodeSavedState } from '@atproto/oauth-client-node';
import dotenv from 'dotenv';
dotenv.config();

// Define session interface
declare module 'express-session' {
    interface Session {
        did?: string;
    }
}

const app = express();
const map = new Map<string, WebSocket>();

// In-memory stores for OAuth state and sessions
const stateMap = new Map<string, NodeSavedState>();
const sessionMap = new Map<string, NodeSavedSession>();

// Initialize session middleware
const sessionParser = session({
    saveUninitialized: false,
    secret: '$eCuRiTy',
    resave: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true
    }
});

// Get base URL from environment or use default
const BASE_URL = process.env.BASE_URL || 'http://localhost:3030';

// Initialize OAuth client
const client = new NodeOAuthClient({
    // This object will be used to build the payload of the /client-metadata.json
    // endpoint metadata, exposing the client metadata to the OAuth server.
    clientMetadata: {
        // Must be a URL that will be exposing this metadata
        client_id: `${BASE_URL}/client-metadata.json`,
        client_name: 'ATProto Local Sync Server',
        client_uri: BASE_URL,
        redirect_uris: [`${BASE_URL}/callback`],
        scope: "atproto transition:generic",
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        // token_endpoint_auth_method: 'private_key_jwt',
        "token_endpoint_auth_method": "none",
        application_type: 'web',
        dpop_bound_access_tokens: true,
    },

    // Interface to store authorization state data (during authorization flows)
    stateStore: {
        async set(key: string, internalState: NodeSavedState): Promise<void> {
            stateMap.set(key, internalState);
            console.log(`State stored with key: ${key}`);
        },
        async get(key: string): Promise<NodeSavedState | undefined> {
            const state = stateMap.get(key);
            console.log(`State retrieved for key: ${key}`, state ? 'found' : 'not found');
            return state;
        },
        async del(key: string): Promise<void> {
            stateMap.delete(key);
            console.log(`State deleted for key: ${key}`);
        },
    },

    // Interface to store authenticated session data
    sessionStore: {
        async set(sub: string, session: NodeSavedSession): Promise<void> {
            sessionMap.set(sub, session);
            console.log(`Session stored for sub: ${sub}`);
        },
        async get(sub: string): Promise<NodeSavedSession | undefined> {
            const session = sessionMap.get(sub);
            console.log(`Session retrieved for sub: ${sub}`, session ? 'found' : 'not found');
            return session;
        },
        async del(sub: string): Promise<void> {
            sessionMap.delete(sub);
            console.log(`Session deleted for sub: ${sub}`);
        },
    },
})

//
// Serve static files from the 'public' folder.
//
app.use(express.static('public'));
app.use(sessionParser);

// Serve client metadata
app.get('/client-metadata.json', (req: Request, res: Response) => {
    res.json(client.clientMetadata)
})

// Start OAuth flow
app.get('/login', async (req: Request, res: Response) => {
    try {
        const handle = req.query.handle as string || 'rocksfall.bsky.social';

        console.log(`Starting OAuth flow for handle: ${handle}`);
        console.log(`Using BASE_URL: ${BASE_URL}`);

        // Revoke any pending authentication requests if the connection is closed (optional)
        const ac = new AbortController();
        req.on('close', () => ac.abort());

        const url = await client.authorize(handle);
        console.log(`Generated authorization URL: ${url.toString()}`);

        res.redirect(url.toString());
    } catch (error) {
        console.error('Failed to create auth URL:', error);
        res.status(500).send(`Authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
});

// Handle OAuth callback
app.get('/callback', async (req: Request, res: Response, next: Function) => {
    try {
        const params = new URLSearchParams(req.url.split('?')[1]);
        console.log('Received callback with params:', Object.fromEntries(params.entries()));

        if (params.has('error')) {
            throw new Error(`OAuth server returned error: ${params.get('error')}, description: ${params.get('error_description')}`);
        }

        if (!params.has('code') || !params.has('state')) {
            throw new Error('Missing required parameters: code or state');
        }

        console.log('Attempting to exchange code for tokens...');
        const { session, state } = await client.callback(params);

        // Process successful authentication here
        console.log('OAuth flow completed successfully!');
        console.log('authorize() was called with state:', state);
        console.log('User authenticated as:', session.did);

        // Store session did in express session
        req.session.did = session.did;

        const agent = new Agent(session);

        // Make Authenticated API calls
        console.log('Fetching user profile...');
        const profile = await agent.getProfile({ actor: agent.did! });
        console.log('Bsky profile:', profile.data);

        res.redirect('/');
    } catch (error) {
        console.error('Failed to exchange auth code:', error);
        res.status(500).send(`Authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
});

app.delete('/logout', (req: Request, res: Response) => {
    const ws = map.get(req.session.did!);
    // TODO: Sign out of ATProto session

    console.log('Destroying session');
    req.session.destroy(() => {
        if (ws) ws.close();
        res.send({ result: 'OK', message: 'Session destroyed' });
    });
});

// Check if user is authenticated
app.get('/check-auth', (req: Request, res: Response) => {
    if (req.session.did) {
        res.json({
            authenticated: true,
            did: req.session.did
        });
    } else {
        res.json({
            authenticated: false
        });
    }
});

//
// Create an HTTP server.
//
const server = http.createServer(app);

//
// Create a WebSocket server completely detached from the HTTP server.
//

// Define error handler type
const onSocketError = (err: Error) => {
    console.error(err);
};

const wss = new WebSocketServer({ clientTracking: false, noServer: true });

// Handle WebSocket upgrade using session
server.on('upgrade', (request: any, socket: any, head: any) => {
    console.log('Handling upgrade request');
    socket.on('error', onSocketError);

    console.log('Parsing session from request...');

    sessionParser(request, {} as Response, () => {
        // TODO: Check if token is expired
        if (!request.session.did) {
            console.error('Session is unauthorized');
            socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
            socket.destroy();
            return;
        }

        console.log('Session is parsed!');
        socket.removeListener('error', onSocketError);

        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    });
});

wss.on('connection', (ws: WebSocket, request: any) => {
    const did = request.session.did;

    map.set(did, ws);

    ws.on('error', console.error);

    ws.on('message', (message: Buffer) => {
        console.log(`Received message ${message} from user ${did}`);
    });

    ws.on('close', () => {
        map.delete(did);
    });
});

//
// Start the server.
//
server.listen(3030, () => {
    console.log('Listening on http://localhost:3030');
});