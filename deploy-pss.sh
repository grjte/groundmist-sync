#!/bin/bash

# Check if DID is provided
if [ -z "$1" ]; then
    echo "Error: Please provide an atproto DID as an argument"
    echo "Usage: ./deploy-pss.sh did:plc:example123..."
    exit 1
fi

# Store DID argument
ATPROTO_DID="$1"

# Generate random secret key
PSS_SECRET_KEY=$(openssl rand -hex 64)

# Create unique deployment name based on DID
DEPLOYMENT_NAME="pss-$(echo $ATPROTO_DID | tr ':' '-' | tr '.' '-')"

# Build the Docker image
docker build -t atproto-pss .

# Deploy using the local image and wait for it to start
docker run -d \
    --name "$DEPLOYMENT_NAME" \
    -e PSS_SECRET_KEY="$PSS_SECRET_KEY" \
    -e ATPROTO_DID="$ATPROTO_DID" \
    -p 3031:3031 \
    --restart unless-stopped \
    atproto-pss

# Wait for container to be running
echo "Waiting for container to start..."
sleep 5

# Check if container is running
if ! docker ps | grep -q "$DEPLOYMENT_NAME"; then
    echo "Error: Container failed to start"
    echo "Container logs:"
    docker logs "$DEPLOYMENT_NAME"
    exit 1
fi

# Get the assigned port with error checking
PORT=$(docker port "$DEPLOYMENT_NAME" 3031/tcp | cut -d ':' -f 2)
if [ -z "$PORT" ]; then
    echo "Error: Failed to get assigned port"
    echo "Please check container status with: docker ps -a"
    exit 1
fi

# Get host machine's public IP
HOST_IP=$(curl -s ifconfig.me)

# Output deployment information
echo "Personal Sync Server Deployment Information:"
echo "-----------------------------------"
echo "Host: $HOST_IP"
echo "Port: $PORT"
echo "Full Location: $HOST_IP:$PORT"
echo "Secret Key: $PSS_SECRET_KEY"
echo "DID: $ATPROTO_DID"
echo ""
echo "Save these credentials securely!" 