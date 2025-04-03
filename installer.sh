#!/bin/bash
set -e

# Groundmist Sync Server Installer
# This script installs and configures the Groundmist Sync Server with SSL

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
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

print_warning() {
  echo -e "${YELLOW}${BOLD}!${NC}${BOLD} $1${NC}"
}

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
  print_error "This script must be run as root (use sudo)"
  exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS=$ID
  VERSION_ID=$VERSION_ID
elif type lsb_release >/dev/null 2>&1; then
  OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
  VERSION_ID=$(lsb_release -sr)
elif [ -f /etc/lsb-release ]; then
  . /etc/lsb-release
  OS=$DISTRIB_ID
  VERSION_ID=$DISTRIB_RELEASE
else
  OS=$(uname -s)
fi

# Function to install Docker and Docker Compose
install_docker() {
  print_step "Installing Docker and Docker Compose"
  
  # Install Docker based on OS
  case "$OS" in
    "ubuntu"|"debian")
      # Update package lists
      apt-get update
      
      # Install prerequisites
      apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release
      
      # Add Docker's official GPG key
      mkdir -p /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      
      # Add Docker repository
      echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS \
        $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
      
      # Install Docker Engine
      apt-get update
      apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
      
      # Install Docker Compose
      if ! command -v docker compose &> /dev/null; then
        COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
        curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
      fi
      ;;
      
    "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
      # Install prerequisites
      yum install -y yum-utils device-mapper-persistent-data lvm2
      
      # Add Docker repository
      yum-config-manager --add-repo https://download.docker.com/linux/$OS/docker-ce.repo
      
      # Install Docker Engine
      yum install -y docker-ce docker-ce-cli containerd.io
      
      # Start and enable Docker service
      systemctl start docker
      systemctl enable docker
      
      # Install Docker Compose
      if ! command -v docker compose &> /dev/null; then
        COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
        curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
      fi
      ;;
      
    "amzn")
      # Install Docker on Amazon Linux
      amazon-linux-extras install docker -y
      systemctl start docker
      systemctl enable docker
      
      # Install Docker Compose
      if ! command -v docker compose &> /dev/null; then
        COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
        curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
      fi
      ;;
      
    *)
      print_error "Unsupported operating system: $OS"
      print_warning "Please install Docker and Docker Compose manually according to your OS instructions:"
      print_warning "Docker: https://docs.docker.com/engine/install/"
      print_warning "Docker Compose: https://docs.docker.com/compose/install/"
      exit 1
      ;;
  esac
  
  # Add current user to the docker group
  if [ -n "$SUDO_USER" ]; then
    usermod -aG docker $SUDO_USER
    print_warning "Added user $SUDO_USER to the docker group. You may need to log out and back in for this to take effect."
  fi
  
  print_success "Docker and Docker Compose have been installed"
}

# Install curl and jq if not present
print_step "Checking for required packages"
if ! command -v curl &> /dev/null; then
  print_step "Installing curl"
  if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    apt-get update && apt-get install -y curl
  elif [[ "$OS" == "centos" || "$OS" == "rhel" || "$OS" == "fedora" || "$OS" == "rocky" || "$OS" == "almalinux" ]]; then
    yum install -y curl
  elif [[ "$OS" == "amzn" ]]; then
    yum install -y curl
  else
    print_error "Could not install curl. Please install it manually."
    exit 1
  fi
fi

if ! command -v jq &> /dev/null; then
  print_step "Installing jq"
  if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    apt-get update && apt-get install -y jq
  elif [[ "$OS" == "centos" || "$OS" == "rhel" || "$OS" == "fedora" || "$OS" == "rocky" || "$OS" == "almalinux" ]]; then
    yum install -y jq
  elif [[ "$OS" == "amzn" ]]; then
    yum install -y jq
  else
    print_error "Could not install jq. Please install it manually."
    exit 1
  fi
fi

# Check for Docker and install if needed
if ! command -v docker &> /dev/null; then
  print_step "Docker not found, installing..."
  install_docker
else
  print_success "Docker is already installed"
fi

# Check for docker-compose and install if needed
if ! command -v docker-compose &> /dev/null && ! command -v "docker compose" &> /dev/null; then
  print_step "Docker Compose not found, installing..."
  COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
  curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
else
  print_success "Docker Compose is already installed"
fi

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

# Ask user if they self-host their PDS
read -p "Do you self-host your PDS? (y/N): " SELF_HOSTED

if [[ "$SELF_HOSTED" =~ ^[Yy]$ ]]; then
    # Get user input for service URL
    read -p "Enter your PDS URL (e.g., https://pds.example.com): " PDS_URL
    # Get user input for handle
    read -p "Enter your handle (e.g., example.com): " HANDLE
else
    # Use default service URL
    PDS_URL="https://bsky.social"
    # Get user input for handle
    read -p "Enter your handle (e.g., user.bsky.social): " HANDLE
fi

# Fetch the user's DID from their handle using pds.groundmist.xyz
ATPROTO_DID=$(curl -s "https://pds.groundmist.xyz/xrpc/com.atproto.identity.resolveHandle?handle=$HANDLE" | jq -r '.did')
echo -e "ATProto DID: $ATPROTO_DID"

# Generate a secret key
SECRET_KEY=$(openssl rand -hex 32)

# Create directory structure
INSTALL_DIR="/opt/groundmist-sync"
print_step "Creating installation directory: $INSTALL_DIR"
mkdir -p $INSTALL_DIR
mkdir -p $INSTALL_DIR/data
mkdir -p $INSTALL_DIR/nginx
mkdir -p $INSTALL_DIR/log/nginx
mkdir -p $INSTALL_DIR/log/certbot

# Create docker-compose.yml
print_step "Creating Docker Compose configuration"
cat > $INSTALL_DIR/docker-compose.yml << EOL
services:
  sync:
    image: ghcr.io/grjte/groundmist-sync:latest
    platform: linux/amd64
    container_name: groundmist-sync
    restart: unless-stopped
    environment:
      - GROUNDMIST_SYNC_SECRET_KEY=${SECRET_KEY}
      - ATPROTO_DID=${ATPROTO_DID}
      - PORT=3031
      - DATA_DIR=/data
      - TZ=UTC
    volumes:
      - ./data:/data
    # TODO: Add healthcheck
    # healthcheck:
    #   test: ["CMD", "wget", "--spider", "-q", "http://localhost:3031"]
    #   interval: 30s
    #   timeout: 10s
    #   retries: 3
    #   start_period: 10s
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
      - ./log/nginx:/var/log/nginx
    ports:
      - "0.0.0.0:80:80"
      - "0.0.0.0:443:443"
    depends_on:
      - sync
      # TODO: restore dependency when groundmist-sync healthcheck is working
      # sync:
      #   condition: service_healthy
    healthcheck:
      test: ["CMD", "nginx", "-t"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - sync_network

  certbot:
    image: certbot/certbot
    container_name: groundmist-sync-certbot
    volumes:
      - ./certbot/conf:/etc/letsencrypt
      - ./certbot/www:/var/www/certbot
      - ./log/certbot:/var/log/letsencrypt
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

# Initial configuration for certificate acquisition
cat > $INSTALL_DIR/nginx/conf.d/sync.conf << EOL
server {
    listen 80;
    server_name ${DOMAIN};
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    
    location / {
        return 200 'Nginx is working!';
        add_header Content-Type text/plain;
    }
}
EOL

# Create bash script for publishing sync server to atproto PDS
print_step "Creating atproto PDS publish script for future use"
cat > $INSTALL_DIR/publish.sh << 'EOL'
#!/bin/bash
set -e

BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
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

print_warning() {
  echo -e "${YELLOW}${BOLD}!${NC}${BOLD} $1${NC}"
}

# Load configuration
DOMAIN="{{DOMAIN}}"
PDS_URL="{{PDS_URL}}"
HANDLE="{{HANDLE}}"

# Check if the sync server is running
SYNC_CONTAINER=$(docker-compose ps -q sync)
if [ -z "$SYNC_CONTAINER" ]; then
  print_error "Error: Sync server container is not running"
  echo "Please make sure the server is running with: docker-compose up -d"
  exit 1
fi

RUNNING=$(docker inspect --format='{{.State.Running}}' $SYNC_CONTAINER 2>/dev/null || echo "false")
if [ "$RUNNING" != "true" ]; then
  print_error "Error: Sync server container is not running"
  echo "Please make sure the server is running with: docker-compose up -d"
  exit 1
fi

print_step "Publishing sync server location to your ATProto PDS so it can be found by applications"
echo "This will publish your sync server address ($DOMAIN) to your ATProto account"
echo "Log in to publish your sync server address to your PDS"
echo "-----------------------------------------------------------------"
echo "Logging in to $PDS_URL as $HANDLE..."

# Get password securely
read -sp "Enter your password: " PASSWORD
echo

if [ -z "$PASSWORD" ]; then
  print_error "Password cannot be empty"
  exit 1
fi

# Step 1: Create a session (login)
print_step "Authenticating with $PDS_URL..."
AUTH_RESPONSE=$(curl -s -X POST "$PDS_URL/xrpc/com.atproto.server.createSession" \
  -H "Content-Type: application/json" \
  -d "{\"identifier\":\"$HANDLE\",\"password\":\"$PASSWORD\"}")

# Check for error in authentication
if echo "$AUTH_RESPONSE" | grep -q "error"; then
  ERROR_MESSAGE=$(echo "$AUTH_RESPONSE" | grep -o '"message":"[^"]*' | sed 's/"message":"//')
  print_error "Authentication failed: $ERROR_MESSAGE"
  exit 1
fi

# Extract access token and DID
ACCESS_TOKEN=$(echo "$AUTH_RESPONSE" | grep -o '"accessJwt":"[^"]*' | sed 's/"accessJwt":"//g')
DID=$(echo "$AUTH_RESPONSE" | grep -o '"did":"[^"]*' | sed 's/"did":"//g')

if [ -z "$ACCESS_TOKEN" ] || [ -z "$DID" ]; then
  print_error "Failed to extract authentication information from response"
  exit 1
fi

print_success "Authentication successful for $HANDLE"

# Step 2: Publish the sync server record
print_step "Publishing sync server location: $DOMAIN"

PUBLISH_RESPONSE=$(curl -s -X POST "$PDS_URL/xrpc/com.atproto.repo.putRecord" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d "{
    \"repo\": \"$DID\",
    \"collection\": \"xyz.groundmist.sync\",
    \"rkey\": \"$DID\",
    \"record\": {
      \"host\": \"$DOMAIN\"
    }
  }")

# Check for error in publishing
if echo "$PUBLISH_RESPONSE" | grep -q "error"; then
  ERROR_MESSAGE=$(echo "$PUBLISH_RESPONSE" | grep -o '"message":"[^"]*' | sed 's/"message":"//')
  print_error "Publishing failed: $ERROR_MESSAGE"
  exit 1
fi

URI=$(echo "$PUBLISH_RESPONSE" | grep -o '"uri":"[^"]*' | sed 's/"uri":"//g')
CID=$(echo "$PUBLISH_RESPONSE" | grep -o '"cid":"[^"]*' | sed 's/"cid":"//g')

print_success "Sync server location published successfully!"
echo "URI: $URI"
echo "CID: $CID"
echo
echo "Your Groundmist Sync Server is ready at: https://$DOMAIN"
echo "Your ATProto DID is: $DID"
EOL

# Make script executable and ensure permissions
chmod +x $INSTALL_DIR/publish.sh

# Update placeholders in the script with actual values
sed -i "s|{{DOMAIN}}|$DOMAIN|g" $INSTALL_DIR/publish.sh
sed -i "s|{{PDS_URL}}|$PDS_URL|g" $INSTALL_DIR/publish.sh
sed -i "s|{{HANDLE}}|$HANDLE|g" $INSTALL_DIR/publish.sh

# Create .env file with the secret key 
cat > $INSTALL_DIR/.env << EOL
DOMAIN=${DOMAIN}
GROUNDMIST_SYNC_SECRET_KEY=${SECRET_KEY}
ATPROTO_DID=${ATPROTO_DID}
EOL

# Add domain to config
cat > $INSTALL_DIR/config.json << EOL
{
  "host": "https://${DOMAIN}"
}
EOL

# Set up auto-renewal for SSL
print_step "Setting up SSL certificates and nginx"

# Start nginx for initial certificate acquisition
cd $INSTALL_DIR
docker-compose up -d nginx

# Ensure nginx container is running properly
print_step "Waiting for nginx to start..."
sleep 10  # Increased wait time to ensure nginx is fully up

# Create test file to verify web server is accessible
mkdir -p $INSTALL_DIR/certbot/www/.well-known/acme-challenge
echo "Nginx is working properly" > $INSTALL_DIR/certbot/www/.well-known/acme-challenge/test-file

# Test if the challenge path is accessible
print_step "Testing if the ACME challenge path is accessible..."
curl -v http://$DOMAIN/.well-known/acme-challenge/test-file || true

# Obtain SSL certificate with more verbose output
print_step "Obtaining SSL certificate for $DOMAIN"
docker-compose run --rm --entrypoint "\
  certbot certonly --webroot \
  --webroot-path=/var/www/certbot \
  --email admin@$DOMAIN \
  --agree-tos --no-eff-email \
  --force-renewal \
  -d $DOMAIN" certbot

  # If the certificate still isn't generated, try standalone mode
if [ ! -d "$INSTALL_DIR/certbot/conf/live/$DOMAIN" ]; then
  print_warning "Webroot mode failed, trying standalone mode..."
  
  # Stop nginx to free up port 80
  docker-compose stop nginx
  
  # Try standalone mode
  docker-compose run --rm --entrypoint "\
    certbot certonly --standalone \
    --email admin@$DOMAIN \
    --agree-tos --no-eff-email \
    --force-renewal \
    -d $DOMAIN" certbot
    
  # Start nginx again
  docker-compose start nginx
fi

# If the above fails, try with staging environment
if [ $? -ne 0 ]; then
  print_warning "Certificate issuance failed, trying with staging environment to debug..."
  docker-compose run --rm certbot certonly --webroot -w /var/www/certbot \
    -d $DOMAIN --agree-tos --no-eff-email --force-renewal \
    --email admin@$DOMAIN --verbose --debug --staging
fi

# Create SSL-enabled nginx configuration
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

# Restart nginx to load SSL config
docker-compose restart nginx

# Pull and start all services
print_step "Starting Groundmist Sync Server"
cd $INSTALL_DIR
docker-compose up -d

# Create a system service for automatic startup (if systemd is available)
if command -v systemctl &> /dev/null; then
  print_step "Creating systemd service for automatic startup"
  
  # Check for docker-compose command path
  DOCKER_COMPOSE_CMD="docker-compose"
  if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
  elif command -v "docker" &> /dev/null && docker compose version &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker compose"
  fi
  
  cat > /etc/systemd/system/groundmist-sync.service << EOL
[Unit]
Description=Groundmist Sync Server
After=docker.service network.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
ExecStart=$DOCKER_COMPOSE_CMD up -d
ExecStop=$DOCKER_COMPOSE_CMD down
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
EOL

  # Enable and start the service
  systemctl daemon-reload
  systemctl enable groundmist-sync
  print_success "Created systemd service: groundmist-sync"
fi

# Ask the user if they want to publish now
print_step "Publishing to atproto PDS"
read -p "Would you like to publish your sync server location to your atproto PDS now? (Y/n): " PUBLISH_NOW
if [[ -z "$PUBLISH_NOW" || "$PUBLISH_NOW" =~ ^[Yy]$ ]]; then
  # Check if the sync server is running
  SYNC_CONTAINER=$(docker-compose ps -q sync)
  if [ -z "$SYNC_CONTAINER" ]; then
    print_error "Error: Sync server container is not running"
    echo "Skipping publishing step. You can publish later by running: cd $INSTALL_DIR && ./publish.sh"
    PUBLISH_FAILED=true
  else
    RUNNING=$(docker inspect --format='{{.State.Running}}' $SYNC_CONTAINER 2>/dev/null || echo "false")
    if [ "$RUNNING" != "true" ]; then
      print_error "Error: Sync server container is not running"
      echo "Skipping publishing step. You can publish later by running: cd $INSTALL_DIR && ./publish.sh"
      PUBLISH_FAILED=true
    fi
  fi

  if [ -z "$PUBLISH_FAILED" ]; then
    print_step "Publishing sync server location to ATProto"
    echo "This will publish your sync server address ($DOMAIN) to your ATProto account"
    echo "-----------------------------------------------------------------"
    echo "Logging in to $PDS_URL as $HANDLE..."

    # Get password securely
    read -sp "Enter your password: " PASSWORD
    echo

    if [ -z "$PASSWORD" ]; then
      print_error "Password cannot be empty"
      echo "Skipping publishing step. You can publish later by running: cd $INSTALL_DIR && ./publish.sh"
    else
      # Step 1: Create a session (login)
      print_step "Authenticating with $PDS_URL..."
      AUTH_RESPONSE=$(curl -s -X POST "$PDS_URL/xrpc/com.atproto.server.createSession" \
        -H "Content-Type: application/json" \
        -d "{\"identifier\":\"$HANDLE\",\"password\":\"$PASSWORD\"}")

      # Check for error in authentication
      if echo "$AUTH_RESPONSE" | grep -q "error"; then
        ERROR_MESSAGE=$(echo "$AUTH_RESPONSE" | grep -o '"message":"[^"]*' | sed 's/"message":"//')
        print_error "Authentication failed: $ERROR_MESSAGE"
        echo "Skipping publishing step. You can publish later by running: cd $INSTALL_DIR && ./publish.sh"
      else
        # Extract access token and DID
        ACCESS_TOKEN=$(echo "$AUTH_RESPONSE" | grep -o '"accessJwt":"[^"]*' | sed 's/"accessJwt":"//g')
        DID=$(echo "$AUTH_RESPONSE" | grep -o '"did":"[^"]*' | sed 's/"did":"//g')

        if [ -z "$ACCESS_TOKEN" ] || [ -z "$DID" ]; then
          print_error "Failed to extract authentication information from response"
          echo "Skipping publishing step. You can publish later by running: cd $INSTALL_DIR && ./publish.sh"
        else
          print_success "Authentication successful for $HANDLE"

          # Step 2: Publish the sync server record
          print_step "Publishing sync server location: $DOMAIN"

          PUBLISH_RESPONSE=$(curl -s -X POST "$PDS_URL/xrpc/com.atproto.repo.putRecord" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            -d "{
              \"repo\": \"$DID\",
              \"collection\": \"xyz.groundmist.sync\",
              \"rkey\": \"$DID\",
              \"record\": {
                \"host\": \"$DOMAIN\"
              }
            }")

          # Check for error in publishing
          if echo "$PUBLISH_RESPONSE" | grep -q "error"; then
            ERROR_MESSAGE=$(echo "$PUBLISH_RESPONSE" | grep -o '"message":"[^"]*' | sed 's/"message":"//')
            print_error "Publishing failed: $ERROR_MESSAGE"
            echo "You can try again later by running: cd $INSTALL_DIR && ./publish.sh"
          else
            URI=$(echo "$PUBLISH_RESPONSE" | grep -o '"uri":"[^"]*' | sed 's/"uri":"//g')
            CID=$(echo "$PUBLISH_RESPONSE" | grep -o '"cid":"[^"]*' | sed 's/"cid":"//g')

            print_success "Sync server location published successfully!"
            echo "URI: $URI"
            echo "CID: $CID"
          fi
        fi
      fi
    fi
  fi
fi

# Final success message
print_success "Installation complete!"
echo ""
echo -e "${BOLD}Your Groundmist Sync Server is now running at${NC}: https://$DOMAIN"
echo -e "${BOLD}Sync Server Secret Key${NC}: $SECRET_KEY"
echo ""
echo -e "${BOLD}Commands${NC}:"
echo "Update: cd $INSTALL_DIR && docker-compose pull && docker-compose up -d"
echo "Check status: cd $INSTALL_DIR && docker-compose ps"
echo "View logs: cd $INSTALL_DIR && docker-compose logs -f"
echo "Publish to your atproto PDS (if not already done): cd $INSTALL_DIR && ./publish.sh"
echo ""
echo "Your sync server data is stored in: $INSTALL_DIR/data"