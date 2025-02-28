'use strict';

import session from 'express-session';
import express, { Request, Response } from 'express';
import * as uuid from 'uuid';
import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'http';

// Define session interface to extend Express.Session
declare module 'express-session' {
    interface Session {
        userId?: string;
    }
}

// Define error handler type
const onSocketError = (err: Error) => {
    console.error(err);
};

const app = express();
const map = new Map<string, WebSocket>();

//
// We need the same instance of the session parser in express and
// WebSocket server.
//
const sessionParser = session({
    saveUninitialized: false,
    secret: '$eCuRiTy',
    resave: false
});

//
// Serve static files from the 'public' folder.
//
app.use(express.static('public'));
app.use(sessionParser);

app.post('/login', (req: Request, res: Response) => {
    //
    // "Log in" user and set userId to session        .
    //
    const id = uuid.v4();

    console.log(`Updating session for user ${id}`);
    req.session.userId = id;
    res.send({ result: 'OK', message: 'Session updated' });
});

app.delete('/logout', (req: Request, res: Response) => {
    const ws = map.get(req.session.userId!);

    console.log('Destroying session');
    req.session.destroy(() => {
        if (ws) ws.close();
        res.send({ result: 'OK', message: 'Session destroyed' });
    });
});

//
// Create an HTTP server.
//
const server = http.createServer(app);

//
// Create a WebSocket server completely detached from the HTTP server.
//
const wss = new WebSocketServer({ clientTracking: false, noServer: true });

server.on('upgrade', (request: any, socket: any, head: any) => {
    socket.on('error', onSocketError);

    console.log('Parsing session from request...');

    sessionParser(request, {} as express.Response, () => {
        if (!request.session.userId) {
            console.log('Session is unauthorized!');
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
    const userId = request.session.userId;

    map.set(userId, ws);

    ws.on('error', console.error);

    ws.on('message', (message: Buffer) => {
        //
        // Here we can now use session parameters.
        //
        console.log(`Received message ${message} from user ${userId}`);
    });

    ws.on('close', () => {
        map.delete(userId);
    });
});

//
// Start the server.
//
server.listen(3030, () => {
    console.log('Listening on http://localhost:3030');
});