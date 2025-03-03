'use strict';

import session from 'express-session';
import express, { Request, Response } from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'http';
import axios from 'axios';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { createHash, createPublicKey, KeyObject } from 'crypto';
import { exportSPKI, importJWK } from 'jose';
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

// Add a middleware to handle CORS for the specific routes
app.options('/authenticate', (req: Request, res: Response) => {
    const allowedOrigin = req.headers.origin || '';
    console.log(allowedOrigin);

    // TODO: whitelist allowed origins?
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, DPoP');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours

    // End preflight request
    res.status(204).end();
});

app.post('/authenticate', async (req, res) => {
    // Set CORS headers for the actual request
    const allowedOrigin = req.headers.origin || '';

    // Set proper CORS headers
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'POST');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, DPoP');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    try {
        const did = await verifyBlueskyAccessToken(req);
        console.log("did:", did);
        req.session.did = did;

        // TODO: issue sync token
        // const syncToken = issueSyncServerToken(did);
        // res.json({ syncToken });
        res.json({ result: 'OK', message: 'success' });
    } catch (error) {
        res.status(401).json({ error: error instanceof Error ? error.message : 'Authentication failed' });
    }
});

/**
 * Interface for a DID Document Verification Method
 */
interface VerificationMethod {
    id: string;
    type: string;
    publicKeyJwk: JsonWebKey;
}

/**
 * Interface for a DID Document
 */
interface DidDocument {
    verificationMethod: VerificationMethod[];
}

/**
 * Verifies the DPoP proof and access token from a request.
 *
 * @param {Request} req - The incoming HTTP request object.
 * @returns {Promise<string>} - The user's DID if valid.
 * @throws {Error} - If verification fails.
 */
export async function verifyBlueskyAccessToken(req: Request): Promise<string> {
    const authorizationHeader = Array.isArray(req.headers['authorization'])
        ? req.headers['authorization'][0]
        : req.headers['authorization'];
    if (!authorizationHeader || !authorizationHeader.startsWith('DPoP ')) {
        throw new Error('Missing or invalid Authorization header.');
    }

    const dpopHeader = Array.isArray(req.headers['dpop'])
        ? req.headers['dpop'][0]
        : req.headers['dpop'];
    if (!dpopHeader) {
        throw new Error('Missing DPoP header.');
    }

    // Remove "DPoP " prefix to get the access token string
    const accessToken = authorizationHeader.slice(5);

    // Decode DPoP proof to extract the public key
    const dpopDecoded = jwt.decode(dpopHeader, { complete: true }) as jwt.Jwt | null;
    console.log("dpopDecoded:", dpopDecoded);
    if (!dpopDecoded || !dpopDecoded.header) {
        throw new Error('Invalid DPoP token.');
    }

    const publicKey = (dpopDecoded.header as { jwk?: JsonWebKey }).jwk;
    if (!publicKey) throw new Error('Missing JWK in DPoP proof.');

    console.log("publicKey:", publicKey);
    const nodeKey = await jwkToNodeKey(publicKey);

    const { header: dpopHeaderDecoded, payload: dpopPayload } = dpopDecoded;
    const { htm, htu, jti, iat } = dpopPayload as JwtPayload;

    // Verify DPoP proof signature
    try {
        console.log("verifying DPoP proof signature");
        jwt.verify(dpopHeader, nodeKey, { algorithms: ['ES256'] });
        console.log("DPoP proof signature verified");
    } catch (err) {
        throw new Error('Invalid DPoP proof signature.');
    }

    // Verify DPoP claims
    if (htm !== req.method) {
        throw new Error(`HTTP method mismatch in DPoP proof. Proof claim was ${htm}, but actual was ${req.method}`);
    }
    // TODO: temporarily disable because of localhost ngrok mismatch
    // if (htu !== `${req.protocol}://${req.get('host')}${req.originalUrl}`) {
    //     throw new Error(`HTTP URI mismatch in DPoP proof. Proof claim was ${htu}, but actual was ${req.protocol}://${req.get('host')}${req.originalUrl}`);
    // }
    if (iat! > Math.floor(Date.now() / 1000)) {
        throw new Error('DPoP proof issued in the future.');
    }
    console.log("DPoP claims verified");

    // Decode access token to verify cnf claim
    console.log("decoding access token");
    const accessTokenDecoded = jwt.decode(accessToken, { complete: true }) as jwt.Jwt | null;
    if (!accessTokenDecoded) {
        throw new Error('Invalid access token.');
    }
    console.log("access token decoded");

    const { payload: accessTokenPayload } = accessTokenDecoded;
    const { cnf, exp, iss, sub } = accessTokenPayload as JwtPayload;
    console.log("access token payload:", accessTokenPayload);

    // Verify token expiration
    console.log("verifying token expiration");
    if (exp! < Math.floor(Date.now() / 1000)) {
        throw new Error('Access token has expired.');
    }
    console.log("token expiration verified");

    // Verify that the DPoP proof’s public key thumbprint matches the "cnf" claim in the token.
    console.log("verifying cnf claim");
    const dpopThumbprint = calculateJwkThumbprint(publicKey);
    console.log("dpopThumbprint:", dpopThumbprint);
    // TODO: look at the ATProto / Bluesky docs for what's supposed to happen here
    // if (cnf?.jkt !== dpopThumbprint) {
    //     throw new Error('DPoP proof key does not match access token cnf claim.');
    // }
    // console.log("cnf claim verified");

    // Verify the access token’s signature.
    // Since the issuer ("iss") is "https://bsky.social" (a did:web issuer is not used here),
    // and there is no JWKS endpoint, we use a statically configured public key.
    // TODO: look at the ATProto / Bluesky docs for what's supposed to happen here
    // try {
    //     jwt.verify(accessToken, BLUESKY_PUBLIC_KEY_PEM, { algorithms: ['ES256'] });
    // // what about when the issuer isn't bluesky.social?
    // } catch (err) {
    //     throw new Error('Invalid access token signature.');
    // }

    return sub as string; // Return the DID of the user
}

/**
 * Converts a JWK to a Node.js `KeyObject` compatible with `jsonwebtoken.verify`.
 *
 * @param {JsonWebKey} jwk - The JSON Web Key.
 * @returns {Promise<KeyObject>} - The converted Node.js KeyObject.
 * @throws {Error} - If the conversion fails.
 */
async function jwkToNodeKey(jwk: JsonWebKey): Promise<KeyObject> {
    try {
        // Import JWK as a KeyLike (CryptoKey or KeyObject)
        const keyLike = await importJWK(jwk, 'ES256');

        // Ensure key is valid before proceeding
        if (!(keyLike instanceof Object)) {
            throw new Error('Failed to import JWK: invalid key format.');
        }

        // Export the CryptoKey as an SPKI PEM string
        const pem = await exportSPKI(keyLike as CryptoKey);

        // Convert PEM to a Node.js KeyObject
        return createPublicKey(pem);
    } catch (error) {
        throw new Error(`Failed to convert JWK to Node.js KeyObject: ${(error as Error).message}`);
    }
}

/**
 * Fetches the public key of the issuer to verify the access token.
 *
 * @param {string} issuer - The issuer from the access token (`iss` claim).
 * @returns {Promise<JsonWebKey>} - The public key in JWK format.
 * @throws {Error} - If the public key cannot be fetched or parsed.
 */
async function fetchIssuerPublicKey(issuer: string): Promise<JsonWebKey> {
    try {
        let jwksUrl: string;

        if (issuer.startsWith('did:plc:')) {
            // The issuer is a DID → Fetch DID document from PLC Directory
            jwksUrl = `https://plc.directory/${issuer}`;
        } else if (issuer.startsWith('https://')) {
            // The issuer is a URL → Fetch JWKS from {issuer}/.well-known/jwks.json
            jwksUrl = `${issuer}/.well-known/jwks.json`;
        } else {
            throw new Error(`Unsupported issuer format: ${issuer}`);
        }

        console.log("jwksUrl:", jwksUrl);
        const response = await axios.get(jwksUrl);
        console.log("response:", response.data);

        if (issuer.startsWith('did:plc:')) {
            // Extract the public key associated with '#atproto'
            const verificationMethod = response.data.verificationMethod.find(
                (vm: { id: string }) => vm.id === `${issuer}#atproto`
            );

            if (!verificationMethod) {
                throw new Error(`Public key '#atproto' not found in DID Document for issuer ${issuer}`);
            }

            return verificationMethod.publicKeyJwk;
        } else {
            // Extract the first key from the JWKS response
            if (!response.data.keys || response.data.keys.length === 0) {
                throw new Error(`No keys found in JWKS for issuer ${issuer}`);
            }

            return response.data.keys[0]; // Return the first public key from JWKS
        }
    } catch (error) {
        throw new Error(`Failed to fetch issuer public key: ${(error as Error).message}`);
    }
}

/**
 * Calculates the JWK thumbprint (RFC 7638).
 *
 * @param {JsonWebKey} jwk - The JSON Web Key.
 * @returns {string} - The base64url-encoded thumbprint.
 */
function calculateJwkThumbprint(jwk: JsonWebKey): string {
    // Construct the canonical JSON representation of the JWK
    const canonicalJwk = JSON.stringify({
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
    });

    // Compute the SHA-256 hash of the canonical JWK
    const encoder = new TextEncoder();
    const data = encoder.encode(canonicalJwk);
    const hashBuffer = createHash('sha256').update(data).digest();

    // Convert hash to base64url format
    return hashBuffer.toString('base64url');
}

// TODO: issue sync token
function issueSyncServerToken(did: string) {
    return jwt.sign(
        { user: did },
        "YOUR_SECRET_KEY",  // Replace with a secure key
        { expiresIn: "1h" } // Short-lived token
    );
}

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