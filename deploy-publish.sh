#!/bin/bash
set -e

# Groundmist Sync Server Remote Deployment Script

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

# Create a GitHub release with the installer script
create_release() {
  local VERSION=$1
  
  print_step "Creating GitHub release v$VERSION"
  
  # Create a tag for the release
  git tag -a "v$VERSION" -m "Groundmist Sync Server v$VERSION"
  
  # Push the tag
  git push origin "v$VERSION"
  
  # Create a GitHub release
  gh release create "v$VERSION" \
    --title "Groundmist Sync Server v$VERSION" \
    --notes "Release notes for v$VERSION" \
    installer.sh
  
  # Get the raw URL for the installer script
  INSTALLER_URL=$(gh release view "v$VERSION" --json assets -q '.assets[0].url')
  
  print_success "Release created successfully"
  echo "Installer URL: $INSTALLER_URL"
  
  # Create a short install command for README
  echo -e "${BOLD}One-line installation command:${NC}"
  echo "curl -fsSL $INSTALLER_URL | sudo bash -s sync.example.com"
}

# Prompt for version
if [ -z "$1" ]; then
  read -p "Enter version number (e.g., 0.1.0): " VERSION
else
  VERSION=$1
fi

# Update package.json version
print_step "Updating package.json version to $VERSION"
npm version $VERSION --no-git-tag-version

# Check if installer.sh exists
if [ ! -f "installer.sh" ]; then
  print_error "installer.sh not found. Please create it first."
  exit 1
fi

# Make the installer executable
chmod +x installer.sh

# Build and publish Docker image to GitHub Container Registry
print_step "Building and publishing Docker image to ghcr.io"

# Login to GitHub Container Registry
echo "Logging in to GitHub Container Registry..."
echo $GITHUB_TOKEN_GROUNDMIST_SYNC | docker login ghcr.io -u $GITHUB_USERNAME --password-stdin

# Build the Docker image
docker build -t ghcr.io/grjte/groundmist-sync:$VERSION -t ghcr.io/grjte/groundmist-sync:latest .

# Push the Docker image
docker push ghcr.io/grjte/groundmist-sync:$VERSION
docker push ghcr.io/grjte/groundmist-sync:latest

print_success "Docker image published successfully"

# Commit changes
print_step "Committing changes"
git add package.json package-lock.json
git commit -m "chore: release v$VERSION"
git push origin main

# Create a GitHub release
create_release $VERSION

print_success "Deployment and publishing completed successfully!"
echo ""
echo -e "${BOLD}Installation instructions:${NC}"
echo "Run this command on your server:"
echo "curl -fsSL $INSTALLER_URL | sudo bash -s your-domain.com"