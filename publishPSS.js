#!/usr/bin/env node

import { Agent } from '@atproto/api';
import dotenv from 'dotenv';
dotenv.config();

async function publishPSS(agent, host) {
    try {
        console.log(`Publishing sync server location: ${host}`);
        const response = await agent.api.com.atproto.repo.putRecord({
            repo: agent.session.did,
            collection: 'xyz.groundmist.sync',
            record: {
                host: host,
            },
            rkey: agent.session.did
        });

        console.log(`Published sync server location successfully!`);
        console.log(`URI: ${response.data.uri}`);
        console.log(`CID: ${response.data.cid}`);
        console.log(`Validation status: ${response.data.validationStatus}`);
    } catch (err) {
        console.error(`Error publishing sync server location: ${host}`, err);
    }
}

async function main() {
    // Expect the sync server host as the first argument.
    const host = process.argv[2];
    if (!host) {
        console.error('Please provide the host server where your sync server is located as the first argument.');
        process.exit(1);
    }

    // Check environment variables.
    const service = process.env.PDS_URL;
    const handle = process.env.HANDLE;
    const password = process.env.PASSWORD;
    if (!service || !handle || !password) {
        console.error('Please set PDS_URL, HANDLE, and PASSWORD environment variables.');
        process.exit(1);
    }

    // Initialize the AT Protocol agent.
    const agent = new Agent({ service });

    try {
        await agent.login({ identifier: handle, password });
        console.log(`Logged in as ${handle}`);
    } catch (err) {
        console.error('Login failed:', err);
        process.exit(1);
    }

    try {
        await publishPSS(agent, host);
    } catch (err) {
        console.error('Error reading lexicons directory:', err);
        process.exit(1);
    }
}

main();