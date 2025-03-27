'use strict';
import fs from 'fs';
import os from 'os';
// authenticated server connection
import session from 'express-session';
import express, { Request, Response } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { verifyBlueskyAccessToken, issueSyncServerToken } from './auth.js';
// automerge websocket sync server
import WebSocket, { WebSocketServer } from 'ws';
import { AutomergeUrl, Repo } from "@automerge/automerge-repo"
import { NodeWSServerAdapter } from "@automerge/automerge-repo-network-websocket"
import { NodeFSStorageAdapter } from "@automerge/automerge-repo-storage-nodefs"
// environment variables
import dotenv from 'dotenv';
dotenv.config();

// Define session interface
declare module 'express-session' {
    interface Session {
        did?: string;
        client_id?: string;
        session_id?: string;
        lexiconAuthorityDomain?: string;
    }
}

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

// Add CORS middleware
const cors = (req: Request, res: Response, next: Function) => {
    // TODO: whitelist allowed origins?
    const allowedOrigin = req.headers.origin || '';

    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, DPoP');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours

    next();
};

export class Server {
    /** @type WebSocketServer */
    #socket

    /** @type ReturnType<import("express").Express["listen"]> */
    #server

    /** @type {((value: any) => void)[]} */
    #readyResolvers: ((value: any) => void)[] = []

    #isReady = false

    /** @type Map<string, Repo> */
    #repoMap: Map<string, Repo> = new Map();

    /** @type Map<string, NodeWSServerAdapter> */
    #networkAdapterMap: Map<string, NodeWSServerAdapter> = new Map();

    /** @type Map<string, WebSocket> */
    #map

    /** @type Map<string; AutomergeUrl> */
    // rootDocUrlMap key: {did}-{client_id}
    #rootDocUrlMap: Map<string, AutomergeUrl> = new Map();

    constructor() {
        const dir =
            process.env.DATA_DIR !== undefined ? process.env.DATA_DIR : ".amrg"
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir)
        }
        const hostname = os.hostname()
        const PORT =
            process.env.PORT !== undefined ? parseInt(process.env.PORT) : 3031

        // === Initialize the express app =========================================================
        const app = express()

        // === Add the middlewares =================================================================
        // Serve static files from the 'public' folder.
        app.use(express.static('public'));
        app.use(sessionParser);
        app.use(cors);
        app.use(express.json());

        // === Create an HTTP server ===============================================================
        // TODO: is this necessary?
        // this.#server = http.createServer(app);

        // === Create a WebSocket server completely detached from the HTTP server. =================
        this.#socket = new WebSocketServer({ clientTracking: true, noServer: true })
        this.#map = new Map<string, WebSocket>();

        // === Add the home route ==================================================================
        app.get("/", (req, res) => {
            res.send(`👍 atproto-local-sync is running`)
        })

        // === Add the authentication route ========================================================
        app.post('/authenticate', async (req: Request, res: Response) => {
            console.log("request body:", req.body);
            try {
                const { client_id, did } = await verifyBlueskyAccessToken(req);
                console.log("did:", did);
                if (did !== process.env.ATPROTO_DID) {
                    console.error('Session is unauthorized');
                    throw new Error("HTTP/1.1 401 Unauthorized\r\n\r\n");
                }

                // this specifies the directory path for storing documents from this connection
                const lexiconAuthorityDomain = req.body.lexiconAuthorityDomain;
                const lexiconAuthorityPath = lexiconAuthorityDomain.split('.').join('/');
                const docDir = `${dir}/${lexiconAuthorityPath}`;
                if (!fs.existsSync(docDir)) {
                    fs.mkdirSync(docDir, { recursive: true });
                }
                console.log(`docDir: ${docDir}`);

                // Get or create repo for this lexicon group
                let repo = this.#repoMap.get(lexiconAuthorityDomain);
                if (!repo) {
                    // Create new network adapter for this group
                    const networkAdapter = new NodeWSServerAdapter(this.#socket as any);
                    this.#networkAdapterMap.set(lexiconAuthorityDomain, networkAdapter);

                    // === Initialize the repo =====================================================
                    const config = {
                        network: [networkAdapter],
                        storage: new NodeFSStorageAdapter(docDir),
                        peerId: `storage-server-${hostname}-${lexiconAuthorityDomain}`,
                        sharePolicy: async () => true,
                    };

                    /** @ts-ignore @type {(import("@automerge/automerge-repo").PeerId)}  */
                    repo = new Repo(config);
                    this.#repoMap.set(lexiconAuthorityDomain, repo);
                }

                // Store the lexiconAuthorityDomain in the session for WebSocket routing
                req.session.lexiconAuthorityDomain = lexiconAuthorityDomain;

                // manage the root doc for this (did, client_id) pair, if one exists
                let rootDocUrl = null;
                if (req.body.rootDocUrl) {
                    // store the root doc url for this (did, client_id) pair if there isn't one stored already
                    let rootDocKey = `${did}-${client_id}`;
                    rootDocUrl = req.body.rootDocUrl;
                    console.log(`rootDocKey: ${rootDocKey}, rootDocUrl: ${rootDocUrl}`);
                    if (!this.#rootDocUrlMap.has(rootDocKey)) {
                        this.#rootDocUrlMap.set(rootDocKey, rootDocUrl);
                    } else {
                        // Otherwise, tell the new peer to use the existing root doc url
                        rootDocUrl = this.#rootDocUrlMap.get(rootDocKey);
                    }
                }

                // issue sync server token
                const syncToken = await issueSyncServerToken(client_id, did);
                res.json({ result: 'OK', token: syncToken, rootDocUrl });
            } catch (error) {
                res.status(401).json({ error: error instanceof Error ? error.message : 'Authentication failed' });
            }
        });

        // === Start the server ====================================================================
        this.#server = app.listen(PORT, () => {
            console.log(`Listening on port ${PORT}`)
            this.#isReady = true
            this.#readyResolvers.forEach((resolve) => resolve(true))
        })

        // === Handle WebSocket upgrade using session ==============================================
        this.#server.on('upgrade', (request: any, socket: any, head: any) => {
            console.log('Handling upgrade request');
            socket.on('error', console.error);

            console.log('Parsing session from request...');

            sessionParser(request, {} as Response, () => {
                const token = new URL(request.url, "http://localhost").searchParams.get("token");
                if (!token) {
                    console.error('Session is unauthorized');
                    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
                    socket.destroy();
                    return;
                }
                console.log('token:', token);

                try {
                    const payload = jwt.verify(token, process.env.SYNC_SERVER_SECRET_KEY!);
                    // TODO: Check if token is expired
                    const { did, client_id, session_id } = payload as JwtPayload;
                    if (!did || did !== process.env.ATPROTO_DID) {
                        console.error('Session is unauthorized');
                        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
                        socket.destroy();
                        return;
                    }
                    request.session.did = did;
                    request.session.client_id = client_id;
                    request.session.session_id = session_id;

                    console.log(`Session is parsed! User ${did} at client ${client_id} with session_id ${session_id} is authenticated`);
                    // socket.removeListener('error', console.error);

                    this.#socket.handleUpgrade(request, socket, head, (socket) => {
                        console.log("WebSocket connection established")
                        this.#socket.emit('connection', socket, request);
                    });
                } catch (err) {
                    console.error(err)
                    this.#socket.close();  // Reject unauthorized connections
                }
            });
        });


        this.#socket.on('connection', (socket: WebSocket, request: any) => {
            const did = request.session.did;
            const client_id = request.session.client_id;
            const session_id = request.session.session_id;

            this.#map.set(session_id, socket);

            socket.on('error', console.error);

            socket.on('message', (message: Buffer) => {
                console.log(`Received message from user ${did} on client ${client_id} with session_id ${session_id}. Repo located at ${request.session.lexiconAuthorityDomain}`);
            });

            socket.on('close', () => {
                this.#map.delete(session_id);
            });
        });
    }

    async ready() {
        if (this.#isReady) {
            return true
        }

        return new Promise((resolve) => {
            this.#readyResolvers.push(resolve)
        })
    }

    close() {
        this.#socket.close()
        this.#server.close()
    }
}
