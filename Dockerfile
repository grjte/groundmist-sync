# Builder stage
FROM node:20-slim AS builder

WORKDIR /app

# Copy package files and tsconfig.json
COPY package*.json tsconfig.json ./

# Install all dependencies (including devDependencies)
RUN npm ci

# Copy source code
COPY src/ ./src/

# Build TypeScript
RUN npm run build

# Production stage
FROM node:20-slim

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --omit=dev

# Copy built files from builder stage
COPY --from=builder /app/dist ./dist

# Expose the default port
EXPOSE 3031

# Start the server
CMD ["node", "dist/index.js"] 