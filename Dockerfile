FROM node:20-slim

WORKDIR /app

# Copy package files and tsconfig.json
COPY package*.json tsconfig.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY src/ ./src/

# Build TypeScript
RUN npm run build

# Expose the default port
EXPOSE 3031

# Start the server
CMD ["node", "dist/index.js"] 