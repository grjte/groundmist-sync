#!/bin/bash
set -e

# Groundmist Sync Server Installer
# This script installs and configures the Groundmist Sync Server with SSL

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
RED="\033[0;31m"
NC="\033[0m" # No Color

print_step() {
  echo -e "${BLUE}${BOLD}==>${NC}${BOLD} $1${NC}"
}

print_success() {
  echo -e "${GREEN}${BOLD}✓${NC}${BOLD} $1${NC}"
}

print_error() {
  echo -e "${RED}${BOLD}✗${NC}${BOLD} $1${NC}"
}

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
  print_error "This script must be run as root (use sudo)"
  exit 1
fi

# Check for required commands
for cmd in docker docker-compose curl jq; do
  if ! command -v $cmd &> /dev/null; then
    print_error "$cmd is required but not installed. Please install it first."
    exit 1
  fi
done

# Check for DNS tools (we'll try multiple options)
DNS_TOOL=""
if command -v host &> /dev/null; then
  DNS_TOOL="host"
elif command -v dig &> /dev/null; then
  DNS_TOOL="dig"
elif command -v nslookup &> /dev/null; then
  DNS_TOOL="nslookup"
fi

# Get domain name
if [ -z "$1" ]; then
  read -p "Enter your domain name for the sync server (e.g., sync.example.com): " DOMAIN
else
  DOMAIN=$1
fi

# Validate domain
if [ -z "$DOMAIN" ]; then
  print_error "Domain name is required"
  exit 1
fi

# Verify DNS resolution for the domain
print_step "Verifying DNS resolution for domain: $DOMAIN"

# Get server IP for comparison
SERVER_IP=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me)

# Function to check DNS resolution using available tools
check_dns() {
  local domain="$1"
  local resolved_ip=""
  
  if [ "$DNS_TOOL" = "host" ]; then
    if host "$domain" &> /dev/null; then
      resolved_ip=$(host "$domain" | grep "has address" | head -1 | awk '{print $4}')
      if [ -n "$resolved_ip" ]; then
        echo "$resolved_ip"
        return 0
      fi
    fi
    return 1
  elif [ "$DNS_TOOL" = "dig" ]; then
    if dig +short "$domain" A &> /dev/null; then
      resolved_ip=$(dig +short "$domain" A | head -1)
      if [ -n "$resolved_ip" ]; then
        echo "$resolved_ip"
        return 0
      fi
    fi
    return 1
  elif [ "$DNS_TOOL" = "nslookup" ]; then
    if nslookup "$domain" &> /dev/null; then
      resolved_ip=$(nslookup "$domain" | grep -A1 "Name:" | grep "Address:" | head -1 | awk '{print $2}')
      if [ -n "$resolved_ip" ]; then
        echo "$resolved_ip"
        return 0
      fi
    fi
    return 1
  else
    # If no DNS tools available, try a ping test (not ideal but better than nothing)
    if ping -c 1 "$domain" &> /dev/null; then
      resolved_ip=$(ping -c 1 "$domain" | grep PING | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
      if [ -n "$resolved_ip" ]; then
        echo "$resolved_ip"
        return 0
      fi
    fi
    return 1
  fi
  
  # Return the resolved IP
  echo "$resolved_ip"
}

DNS_CHECK=$(check_dns "$DOMAIN")
DNS_STATUS=$?

if [ $DNS_STATUS -ne 0 ] || [ -z "$DNS_CHECK" ]; then
  print_error "DNS resolution failed for $DOMAIN. Please ensure your domain points to this server's IP address."
  echo -e "${BOLD}Your server's public IP address is${NC}: $SERVER_IP"
  echo -e "${BOLD}Please set up an A record for${NC} $DOMAIN ${BOLD}pointing to${NC} $SERVER_IP"
  
  read -p "Do you want to continue anyway? (y/N): " CONTINUE
  if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
    exit 1
  fi
  print_step "Continuing with installation despite DNS issues..."
else
  RESOLVED_IP="$DNS_CHECK"
  
  if [ "$RESOLVED_IP" != "$SERVER_IP" ]; then
    print_error "Domain $DOMAIN resolves to $RESOLVED_IP, but this server's IP is $SERVER_IP"
    echo -e "${BOLD}Your server's public IP address is${NC}: $SERVER_IP"
    echo -e "${BOLD}Please update your DNS A record for${NC} $DOMAIN ${BOLD}to point to${NC} $SERVER_IP"
    
    read -p "Do you want to continue anyway? (y/N): " CONTINUE
    if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
      exit 1
    fi
    print_step "Continuing with installation despite DNS mismatch..."
  else
    print_success "DNS verification successful! Domain $DOMAIN correctly points to $SERVER_IP"
  fi
fi

print_step "Setting up Groundmist Sync Server at domain: $DOMAIN"

# Generate a secret key
SECRET_KEY=$(openssl rand -hex 32)

# Create directory structure
INSTALL_DIR="/opt/groundmist-sync"
print_step "Creating installation directory: $INSTALL_DIR"
mkdir -p $INSTALL_DIR
mkdir -p $INSTALL_DIR/data
mkdir -p $INSTALL_DIR/nginx

# Create docker-compose.yml
print_step "Creating Docker Compose configuration"
cat > $INSTALL_DIR/docker-compose.yml << EOL
version: '3.8'

services:
  sync:
    image: ghcr.io/groundmist/groundmist-sync:latest
    container_name: groundmist-sync
    restart: unless-stopped
    environment:
      - GROUNDMIST_SYNC_SECRET_KEY=${SECRET_KEY}
      - PORT=3031
      - DATA_DIR=/data
    volumes:
      - ./data:/data
    networks:
      - sync_network

  nginx:
    image: nginx:stable-alpine
    container_name: groundmist-sync-nginx
    restart: unless-stopped
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./certbot/conf:/etc/letsencrypt:ro
      - ./certbot/www:/var/www/certbot:ro
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - sync
    networks:
      - sync_network

  certbot:
    image: certbot/certbot
    container_name: groundmist-sync-certbot
    volumes:
      - ./certbot/conf:/etc/letsencrypt
      - ./certbot/www:/var/www/certbot
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait \$\${!}; done;'"
    networks:
      - sync_network

networks:
  sync_network:
    driver: bridge
EOL

# Create nginx configuration
print_step "Creating Nginx configuration"
mkdir -p $INSTALL_DIR/nginx/conf.d
mkdir -p $INSTALL_DIR/certbot/conf
mkdir -p $INSTALL_DIR/certbot/www

# Main nginx.conf
cat > $INSTALL_DIR/nginx/nginx.conf << EOL
user nginx;
worker_processes auto;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    include /etc/nginx/conf.d/*.conf;
}
EOL

# Domain specific configuration
cat > $INSTALL_DIR/nginx/conf.d/sync.conf << EOL
server {
    listen 80;
    server_name ${DOMAIN};
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name ${DOMAIN};
    
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Other security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";
    
    location / {
        proxy_pass http://sync:3031;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOL

# Create PDS authentication script
print_step "Creating PDS authentication utility"
cat > $INSTALL_DIR/publish-sync.js << EOL
#!/usr/bin/env node

import { AtpAgent } from '@atproto/api';
import dotenv from 'dotenv';
import fs from 'fs';
dotenv.config();

async function publishPSS(agent, host) {
    try {
        console.log(\`Publishing sync server location: \${host}\`);
        const response = await agent.api.com.atproto.repo.putRecord({
            repo: agent.session.did,
            collection: 'xyz.groundmist.sync',
            record: {
                host: host,
            },
            rkey: agent.session.did
        });

        console.log(\`Published sync server location successfully!\`);
        console.log(\`URI: \${response.data.uri}\`);
        console.log(\`CID: \${response.data.cid}\`);
        return true;
    } catch (err) {
        console.error(\`Error publishing sync server location: \${host}\`, err);
        return false;
    }
}

async function main() {
    // Read configuration
    const configPath = './config.json';
    if (!fs.existsSync(configPath)) {
        console.error('Config file not found. Please run setup first.');
        process.exit(1);
    }
    
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    
    // Check required fields
    if (!config.pdsUrl || !config.handle || !config.host) {
        console.error('Missing required configuration. Please run setup again.');
        process.exit(1);
    }
    
    // Check for password
    if (!process.env.ATP_PASSWORD) {
        console.error('ATP_PASSWORD environment variable not set. Please provide your ATP password.');
        process.exit(1);
    }
    
    console.log(\`Logging in to \${config.pdsUrl} as \${config.handle}...\`);
    
    // Initialize the AT Protocol agent
    const agent = new AtpAgent({ service: config.pdsUrl });
    
    try {
        await agent.login({
            identifier: config.handle,
            password: process.env.ATP_PASSWORD
        });
        console.log(\`Logged in successfully as \${config.handle}\`);
        
        // Store DID for the server
        config.did = agent.session.did;
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
        
        // Update environment file
        const envPath = './.env';
        let envContent = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
        
        // Update ATPROTO_DID value
        if (envContent.includes('ATPROTO_DID=')) {
            envContent = envContent.replace(/ATPROTO_DID=.*\\n/g, \`ATPROTO_DID=\${agent.session.did}\\n\`);
        } else {
            envContent += \`\\nATPROTO_DID=\${agent.session.did}\`;
        }
        
        fs.writeFileSync(envPath, envContent);
        
        // Update Docker environment
        const command = \`docker compose -f "\${process.cwd()}/docker-compose.yml" exec -T sync sh -c "echo 'ATPROTO_DID=\${agent.session.did}' >> /app/.env"\`;
        try {
            const { execSync } = require('child_process');
            execSync(command);
        } catch (err) {
            console.warn('Could not update Docker environment. You may need to restart the container.');
        }
        
        // Publish sync server location
        await publishPSS(agent, config.host);
        
        console.log('Sync server published successfully!');
    } catch (err) {
        console.error('Login failed:', err);
        process.exit(1);
    }
}

main();
EOL

# Create setup script
print_step "Creating setup script"
cat > $INSTALL_DIR/setup.js << EOL
#!/usr/bin/env node

import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import fs from 'fs';

async function main() {
    const rl = readline.createInterface({ input, output });
    const config = {};
    
    console.log('Groundmist Sync Server Setup');
    console.log('----------------------------');
    
    const selfHostedResponse = await rl.question('Is your PDS self-hosted? (y/N): ');
    const isSelfHosted = selfHostedResponse.toLowerCase() === 'y';
    
    if (isSelfHosted) {
        config.pdsUrl = await rl.question('PDS URL (e.g., https://pds.example.com): ');
        config.handle = await rl.question('Handle (e.g., example.com): ');
    } else {
        config.pdsUrl = 'https://bsky.social';
        console.log('Using default PDS: https://bsky.social');
        config.handle = await rl.question('Handle (e.g., user.bsky.social): ');
    }
    
    // Get the host
    const host = process.env.DOMAIN || await rl.question('Sync server domain (e.g., sync.example.com): ');
    config.host = \`https://\${host}\`;
    
    // Save configuration
    fs.writeFileSync('./config.json', JSON.stringify(config, null, 2));
    
    console.log('\\nConfiguration saved.');
    console.log('\\nNext steps:');
    console.log('1. Set your ATP_PASSWORD environment variable: export ATP_PASSWORD="your_password"');
    console.log('2. Run: node publish-sync.js');
    
    rl.close();
}

main();
EOL

# Create package.json for scripts
print_step "Creating package.json for scripts"
cat > $INSTALL_DIR/package.json << EOL
{
  "name": "groundmist-sync-installer",
  "type": "module",
  "private": true,
  "dependencies": {
    "@atproto/api": "^0.14.7",
    "dotenv": "^16.4.7"
  }
}
EOL

# Make scripts executable
chmod +x $INSTALL_DIR/publish-sync.js
chmod +x $INSTALL_DIR/setup.js

# Set up auto-renewal for SSL
print_step "Setting up SSL certificates and nginx"

# Start nginx for initial certificate acquisition
cd $INSTALL_DIR
docker-compose up -d nginx

# Obtain SSL certificate
print_step "Obtaining SSL certificate for $DOMAIN"
docker-compose run --rm certbot certonly --webroot -w /var/www/certbot -d $DOMAIN --agree-tos --no-eff-email --force-renewal --email admin@$DOMAIN

# Restart nginx to load SSL config
docker-compose restart nginx

# Pull and start all services
print_step "Starting Groundmist Sync Server"
cd $INSTALL_DIR
docker-compose up -d

print_step "Installing script dependencies"
cd $INSTALL_DIR
docker run --rm -v "$INSTALL_DIR:/app" -w /app node:20-slim npm install

# Create .env file with the secret key 
cat > $INSTALL_DIR/.env << EOL
GROUNDMIST_SYNC_SECRET_KEY=${SECRET_KEY}
EOL

# Add domain to config
cat > $INSTALL_DIR/config.json << EOL
{
  "host": "https://${DOMAIN}"
}
EOL

print_success "Installation complete!"
echo ""
echo -e "${BOLD}Your Groundmist Sync Server is now running at${NC}: https://$DOMAIN"
echo -e "${BOLD}Sync Server Secret Key${NC}: $SECRET_KEY"
echo ""
echo -e "${BOLD}Next steps${NC}:"
echo "1. Go to the installation directory: cd $INSTALL_DIR"
echo "2. Run the setup script: node setup.js"
echo "3. Publish your sync server to your PDS:"
echo "   export ATP_PASSWORD=\"your_password\""
echo "   node publish-sync.js"
echo ""
echo "Your sync server data is stored in: $INSTALL_DIR/data"
echo "To update the server, run: docker-compose pull && docker-compose up -d"