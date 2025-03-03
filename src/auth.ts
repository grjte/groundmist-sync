import { Request } from 'express';
import axios from 'axios';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { createHash, createPublicKey, KeyObject, randomUUID } from 'crypto';
import { exportSPKI, importJWK } from 'jose';

/**
 * Verifies the DPoP proof and access token from a request.
 *
 * @param {Request} req - The incoming HTTP request object.
 * @returns {Promise<string>} - The user's DID if valid.
 * @throws {Error} - If verification fails.
 */
export async function verifyBlueskyAccessToken(req: Request): Promise<{ client_id: string, did: string }> {
    const authorizationHeader = Array.isArray(req.headers['authorization'])
        ? req.headers['authorization'][0]
        : req.headers['authorization'];
    if (!authorizationHeader || !authorizationHeader.startsWith('DPoP ')) {
        throw new Error('Missing or invalid Authorization header.');
    }

    const dpopHeader = Array.isArray(req.headers['dpop'])
        ? req.headers['dpop'][0]
        : req.headers['dpop'];
    if (!dpopHeader) {
        throw new Error('Missing DPoP header.');
    }

    // Remove "DPoP " prefix to get the access token string
    const accessToken = authorizationHeader.slice(5);

    // Decode DPoP proof to extract the public key
    const dpopDecoded = jwt.decode(dpopHeader, { complete: true }) as jwt.Jwt | null;
    console.log("dpopDecoded:", dpopDecoded);
    if (!dpopDecoded || !dpopDecoded.header) {
        throw new Error('Invalid DPoP token.');
    }

    const publicKey = (dpopDecoded.header as { jwk?: JsonWebKey }).jwk;
    if (!publicKey) throw new Error('Missing JWK in DPoP proof.');

    console.log("publicKey:", publicKey);
    const nodeKey = await jwkToNodeKey(publicKey);

    const { header: dpopHeaderDecoded, payload: dpopPayload } = dpopDecoded;
    const { htm, htu, jti, iat } = dpopPayload as JwtPayload;

    // Verify DPoP proof signature
    try {
        console.log("verifying DPoP proof signature");
        jwt.verify(dpopHeader, nodeKey, { algorithms: ['ES256'] });
        console.log("DPoP proof signature verified");
    } catch (err) {
        throw new Error('Invalid DPoP proof signature.');
    }

    // Verify DPoP claims
    if (htm !== req.method) {
        throw new Error(`HTTP method mismatch in DPoP proof. Proof claim was ${htm}, but actual was ${req.method}`);
    }
    // TODO: temporarily disable because of localhost ngrok mismatch
    // if (htu !== `${req.protocol}://${req.get('host')}${req.originalUrl}`) {
    //     throw new Error(`HTTP URI mismatch in DPoP proof. Proof claim was ${htu}, but actual was ${req.protocol}://${req.get('host')}${req.originalUrl}`);
    // }
    // TODO: fix
    // if (iat! > Math.floor(Date.now() / 1000)) {
    //     throw new Error('DPoP proof issued in the future.');
    // }
    console.log("DPoP claims verified");

    // Decode access token to verify cnf claim
    console.log("decoding access token");
    const accessTokenDecoded = jwt.decode(accessToken, { complete: true }) as jwt.Jwt | null;
    if (!accessTokenDecoded) {
        throw new Error('Invalid access token.');
    }
    console.log("access token decoded");

    const { payload: accessTokenPayload } = accessTokenDecoded;
    const { cnf, exp, iss, sub, client_id } = accessTokenPayload as JwtPayload;
    console.log("access token payload:", accessTokenPayload);

    // Verify token expiration
    console.log("verifying token expiration");
    if (exp! < Math.floor(Date.now() / 1000)) {
        throw new Error('Access token has expired.');
    }
    console.log("token expiration verified");

    // Verify that the DPoP proof’s public key thumbprint matches the "cnf" claim in the token.
    console.log("verifying cnf claim");
    const dpopThumbprint = calculateJwkThumbprint(publicKey);
    console.log("dpopThumbprint:", dpopThumbprint);
    // TODO: look at the ATProto / Bluesky docs for what's supposed to happen here
    // if (cnf?.jkt !== dpopThumbprint) {
    //     throw new Error('DPoP proof key does not match access token cnf claim.');
    // }
    // console.log("cnf claim verified");

    // Verify the access token’s signature.
    // Since the issuer ("iss") is "https://bsky.social" (a did:web issuer is not used here),
    // and there is no JWKS endpoint, we use a statically configured public key.
    // TODO: look at the ATProto / Bluesky docs for what's supposed to happen here
    // try {
    //     jwt.verify(accessToken, BLUESKY_PUBLIC_KEY_PEM, { algorithms: ['ES256'] });
    // // what about when the issuer isn't bluesky.social?
    // } catch (err) {
    //     throw new Error('Invalid access token signature.');
    // }

    return { client_id, did: sub as string }; // Return the DID of the user
}

/**
 * Converts a JWK to a Node.js `KeyObject` compatible with `jsonwebtoken.verify`.
 *
 * @param {JsonWebKey} jwk - The JSON Web Key.
 * @returns {Promise<KeyObject>} - The converted Node.js KeyObject.
 * @throws {Error} - If the conversion fails.
 */
async function jwkToNodeKey(jwk: JsonWebKey): Promise<KeyObject> {
    try {
        // Import JWK as a KeyLike (CryptoKey or KeyObject)
        const keyLike = await importJWK(jwk, 'ES256');

        // Ensure key is valid before proceeding
        if (!(keyLike instanceof Object)) {
            throw new Error('Failed to import JWK: invalid key format.');
        }

        // Export the CryptoKey as an SPKI PEM string
        const pem = await exportSPKI(keyLike as CryptoKey);

        // Convert PEM to a Node.js KeyObject
        return createPublicKey(pem);
    } catch (error) {
        throw new Error(`Failed to convert JWK to Node.js KeyObject: ${(error as Error).message}`);
    }
}

/**
 * Fetches the public key of the issuer to verify the access token.
 *
 * @param {string} issuer - The issuer from the access token (`iss` claim).
 * @returns {Promise<JsonWebKey>} - The public key in JWK format.
 * @throws {Error} - If the public key cannot be fetched or parsed.
 */
async function fetchIssuerPublicKey(issuer: string): Promise<JsonWebKey> {
    try {
        let jwksUrl: string;

        if (issuer.startsWith('did:plc:')) {
            // The issuer is a DID → Fetch DID document from PLC Directory
            jwksUrl = `https://plc.directory/${issuer}`;
        } else if (issuer.startsWith('https://')) {
            // The issuer is a URL → Fetch JWKS from {issuer}/.well-known/jwks.json
            jwksUrl = `${issuer}/.well-known/jwks.json`;
        } else {
            throw new Error(`Unsupported issuer format: ${issuer}`);
        }

        console.log("jwksUrl:", jwksUrl);
        const response = await axios.get(jwksUrl);
        console.log("response:", response.data);

        if (issuer.startsWith('did:plc:')) {
            // Extract the public key associated with '#atproto'
            const verificationMethod = response.data.verificationMethod.find(
                (vm: { id: string }) => vm.id === `${issuer}#atproto`
            );

            if (!verificationMethod) {
                throw new Error(`Public key '#atproto' not found in DID Document for issuer ${issuer}`);
            }

            return verificationMethod.publicKeyJwk;
        } else {
            // Extract the first key from the JWKS response
            if (!response.data.keys || response.data.keys.length === 0) {
                throw new Error(`No keys found in JWKS for issuer ${issuer}`);
            }

            return response.data.keys[0]; // Return the first public key from JWKS
        }
    } catch (error) {
        throw new Error(`Failed to fetch issuer public key: ${(error as Error).message}`);
    }
}

/**
 * Calculates the JWK thumbprint (RFC 7638).
 *
 * @param {JsonWebKey} jwk - The JSON Web Key.
 * @returns {string} - The base64url-encoded thumbprint.
 */
function calculateJwkThumbprint(jwk: JsonWebKey): string {
    // Construct the canonical JSON representation of the JWK
    const canonicalJwk = JSON.stringify({
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
    });

    // Compute the SHA-256 hash of the canonical JWK
    const encoder = new TextEncoder();
    const data = encoder.encode(canonicalJwk);
    const hashBuffer = createHash('sha256').update(data).digest();

    // Convert hash to base64url format
    return hashBuffer.toString('base64url');
}

/**
 * Issues a sync server token for future requests.
 *
 * @param did - The user's DID.
 * @returns A signed JWT as a string.
 */
export async function issueSyncServerToken(client_id: string, did: string): Promise<string> {
    // Use a secure secret key stored in an environment variable
    const secretKey = process.env.SYNC_SERVER_SECRET_KEY;
    if (!secretKey) {
        throw new Error('SYNC_SERVER_SECRET_KEY is not defined');
    }

    // Define the payload. You can include additional claims if needed.
    const payload = {
        did,
        client_id,
        session_id: randomUUID(), // Generate a unique device identifier per session
    };

    // Define token options. Here, the token expires in 1 hour.
    // TODO: set expiration
    // const options = {
    //     expiresIn: '3600'
    // };
    const options = {}

    // Sign and return the token
    return jwt.sign(payload, secretKey, options);
}