#!/usr/bin/env node

import { AtpAgent } from '@atproto/api';
import { execSync } from 'child_process';
import { randomBytes } from 'crypto';
import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import password from '@inquirer/password';

// Helper function to execute shell commands and handle errors
function executeCommand(command) {
    try {
        return execSync(command, { encoding: 'utf8' });
    } catch (error) {
        console.error('Command execution failed:', error.message);
        process.exit(1);
    }
}

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
    } catch (err) {
        console.error(`Error publishing sync server location: ${host}`, err);
        process.exit(1);
    }
}

async function promptForCredentials() {
    const rl = readline.createInterface({ input, output });

    let pdsUrl;
    const selfHostedResponse = await rl.question('Is your PDS self-hosted? (y/N): ');
    const isSelfHosted = selfHostedResponse.toLowerCase() === 'y';

    console.log('\nPlease enter your ATProto credentials:');
    console.log('-------------------------------------');

    let handle;
    if (isSelfHosted) {
        pdsUrl = await rl.question('PDS URL (e.g., https://pds.example.com): ');
        handle = await rl.question('Handle (e.g., example.com): ');
    } else {
        pdsUrl = 'https://bsky.social';
        console.log('Using default PDS: https://bsky.social');
        handle = await rl.question('Handle (e.g., user.bsky.social): ');
    }

    rl.close();

    const pwd = await password({ message: 'Password:' });
    return { pdsUrl, handle, password: pwd };
}

async function main() {
    // Get credentials interactively
    const credentials = await promptForCredentials();

    // Initialize the AT Protocol agent and login
    console.log('\nLogging in to ATProto...');
    const agent = new AtpAgent({ service: credentials.pdsUrl });

    try {
        await agent.login({
            identifier: credentials.handle,
            password: credentials.password
        });
        console.log(`Logged in successfully as ${credentials.handle}`);
    } catch (err) {
        console.error('Login failed:', err);
        process.exit(1);
    }

    // Generate deployment configuration
    const secretKey = randomBytes(32).toString('hex');
    const deploymentName = `groundmist-sync-${agent.session.did.replace(/[:\.]/g, '-')}`;

    console.log('\nBuilding and deploying Docker container...');

    // Build Docker image
    executeCommand('docker build -t groundmist-sync .');

    // Deploy container
    executeCommand(`docker run -d \
        --name "${deploymentName}" \
        -e GROUNDMIST_SYNC_SECRET_KEY="${secretKey}" \
        -e ATPROTO_DID="${agent.session.did}" \
        -p 3031:3031 \
        --restart unless-stopped \
        groundmist-sync`);

    // Wait for container to start
    console.log('Waiting for container to start...');
    executeCommand('sleep 5');

    // Verify container is running
    const containerCheck = executeCommand('docker ps');
    if (!containerCheck.includes(deploymentName)) {
        console.error('Error: Container failed to start');
        console.log('Container logs:');
        console.log(executeCommand(`docker logs ${deploymentName}`));
        process.exit(1);
    }

    // Get container port and public IP
    const port = executeCommand(`docker port "${deploymentName}" 3031/tcp`).split(':')[1].trim();
    const hostIp = executeCommand('curl -s ifconfig.me').trim();
    const fullHost = `${hostIp}:${port}`;

    // Output deployment information
    console.log('\nPersonal Sync Server Deployment Information:');
    console.log('-----------------------------------');
    console.log(`Host: ${hostIp}`);
    console.log(`Port: ${port}`);
    console.log(`Full Location: ${fullHost}`);
    console.log(`Secret Key: ${secretKey}`);
    console.log(`DID: ${agent.session.did}`);

    // Publish the sync server location
    console.log('\nPublishing sync server location...');
    await publishPSS(agent, fullHost);

    console.log('\nDeployment and publishing completed successfully!');
}

main().catch(err => {
    console.error('Unexpected error:', err);
    process.exit(1);
}); 