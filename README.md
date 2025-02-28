# ATProto Local Sync

A local server for syncing with the AT Protocol (Bluesky) using OAuth authentication.

## Setup

1. Clone this repository
2. Install dependencies:
   ```
   npm install
   ```
3. Copy the example environment file and update it with your settings:
   ```
   cp .env.example .env
   ```
4. Update the `.env` file with your ngrok URL or other public URL:
   ```
   BASE_URL=https://your-ngrok-subdomain.ngrok.app
   ```

## Running the Application

1. Start ngrok to expose your local server (if using ngrok):
   ```
   ngrok http 3030
   ```

2. Update your `.env` file with the ngrok URL from the previous step.

3. Build and start the server:
   ```
   npm run build
   npm start
   ```

4. Open your browser and navigate to `http://localhost:3030` to use the application.

## OAuth Flow

This application implements the AT Protocol OAuth flow:

1. User enters their Bluesky handle
2. User is redirected to Bluesky to authorize the application
3. Bluesky redirects back to the application with an authorization code
4. The application exchanges the code for access and refresh tokens
5. The application uses the tokens to make authenticated API calls

## Troubleshooting

### "Unknown authorization session" Error

If you encounter an "Unknown authorization session" error, it may be due to:

1. Your ngrok URL has changed since you started the OAuth flow
2. The state parameter is not being properly stored or retrieved
3. The OAuth client configuration is incorrect

Make sure your BASE_URL in the .env file matches the URL you're accessing the application from.

### CORS Issues

If you encounter CORS issues, make sure your ngrok URL is correctly set in the .env file and that you're accessing the application through that URL.

## License

MIT 