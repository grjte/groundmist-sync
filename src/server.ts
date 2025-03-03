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
import { Repo } from "@automerge/automerge-repo"
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

    /** @type Repo */
    #repo

    /** @type Map<string, WebSocket> */
    #map

    constructor() {
        const dir =
            process.env.DATA_DIR !== undefined ? process.env.DATA_DIR : ".amrg"
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir)
        }
        const hostname = os.hostname()
        const PORT =
            process.env.PORT !== undefined ? parseInt(process.env.PORT) : 3030

        // === Initialize the express app =========================================================
        const app = express()

        // === Add the middlewares =================================================================
        // Serve static files from the 'public' folder.
        app.use(express.static('public'));
        app.use(sessionParser);
        app.use(cors);

        // === Create an HTTP server ===============================================================
        // TODO: is this necessary?
        // this.#server = http.createServer(app);

        // === Create a WebSocket server completely detached from the HTTP server. =================
        this.#socket = new WebSocketServer({ clientTracking: true, noServer: true })
        this.#map = new Map<string, WebSocket>();

        // === Initialize the repo =================================================================
        const config = {
            network: [new NodeWSServerAdapter(this.#socket as any)],
            storage: new NodeFSStorageAdapter(dir),
            peerId: `storage-server-${hostname}`,
            // Share all documents between clients
            sharePolicy: async () => true,
        }
        /** @ts-ignore @type {(import("@automerge/automerge-repo").PeerId)}  */
        this.#repo = new Repo(config)

        // === Add the home route ==================================================================
        app.get("/", (req, res) => {
            res.send(`👍 atproto-local-sync is running`)
        })

        // === Add the authentication route ========================================================
        app.post('/authenticate', async (req: Request, res: Response) => {
            try {
                const { client_id, did } = await verifyBlueskyAccessToken(req);
                console.log("did:", did);

                // issue sync server token
                const syncToken = await issueSyncServerToken(client_id, did);
                res.json({ result: 'OK', token: syncToken });
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
                    if (!did) {
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
                console.log(`Received message from user ${did} on client ${client_id} with session_id ${session_id}`);
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
