import { Request } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import {
    jwtVerify, calculateJwkThumbprint,
    importJWK, decodeProtectedHeader
} from 'jose'

// 2 minutes clock skew, 5 min max age for DPoP proofs
const CLOCK = 120
const MAX_AGE = 300

export async function verifyBlueskyAccessToken(
    req: Request,
): Promise<{ client_id: string; did: string }> {
    /*  Headers & helpers */
    const auth = req.header('authorization') ?? ''
    const proof = req.header('dpop')
    if (!auth.startsWith('DPoP ') || !proof) throwError(401, 'Invalid authorization header')

    const token = auth.slice(5) // bearer string
    const { jwk: dpopJwk, alg: dpopAlg } = decodeProtectedHeader(proof);
    if (!dpopJwk || !dpopAlg) throwError(401, 'Invalid DPoP proof: malformed header')
    const key = await importJWK(dpopJwk, dpopAlg)

    /*  1. Verify DPoP proof (sig + claims) */
    const result = await jwtVerify(
        proof,
        key,
        {
            clockTolerance: CLOCK,
            maxTokenAge: `${MAX_AGE}s`,
            typ: 'dpop+jwt',
        },
    )
    const dpopPayload = result.payload
    if (dpopPayload.htm !== req.method) throwError(401, 'Invalid DPoP proof')
    if (process.env.NODE_ENV !== 'development') {
        const expected = new URL(req.originalUrl, `${req.protocol}://${req.get('host')}`).href
        if (dpopPayload.htu !== expected) throwError(401, 'Invalid DPoP proof')
    }

    /*  2. Verify access-token
       – If the token is a JWT we verify it here.
       – Otherwise, we throw an error, because we can't support opaque tokens yet.  
       */
    if (token.startsWith('ey')) {
        const decodedToken = jwt.decode(token, { complete: true }) as jwt.Jwt | null;
        if (!decodedToken) {
            throw new Error('Invalid access token.');
        }

        const { payload: claims } = decodedToken;
        const { cnf, exp, sub, client_id, iss } = claims as JwtPayload;

        /* 3. Binding check - DPoP proof's public key thumbprint matches the token's "cnf" claim. */
        const jkt = await calculateJwkThumbprint(dpopJwk, 'sha256')
        if (cnf?.jkt && cnf.jkt !== jkt) throwError(401, 'DPoP proof key does not match access token cnf claim.')


        // TODO: verify JWT signature
        // DID document resolution for https://bsky.social to obtain the public key currently fails,
        // because the associated DID "did:web:bsky.social" doesn't have public jwks at the 
        // .well-known endpoint.

        // /* 4. client_id / sub / exp checks */
        if (!client_id || client_id !== dpopPayload.iss) throwError(403, 'Access token client_id does not match DPoP proof iss claim.')
        if (sub != process.env.ATPROTO_DID) throwError(403, 'Access token sub does not match server DID.')
        if ((exp ?? 0) < Math.floor(Date.now() / 1000)) throwError(401, 'Access token has expired.')

        return { client_id: client_id, did: sub as string };
    } else {
        // Note: the atproto spec allows for opaque tokens, and the default for self-hosted PDSes is
        // now to return these instead of JWTs, but there is no straightforward way to 
        // introspect these from this server and to verify that all of the following are true:
        // 1. the user has a valid token
        // 2. the valid token is associated with a particular client_id
        // Both of these requirements must be met, because what we are really trying to verify here
        //is that the _application_ (client) trying to connect is doing so with the approval of the 
        // user that owns the DID associated with this personal sync server.
        return { client_id: process.env.ATPROTO_CLIENT_ID as string, did: process.env.ATPROTO_DID as string };
        throwError(401, 'Unsupported access token format.');
    }
}

function throwError(code: number, message: string): never {
    const err: any = new Error(message)
    err.statusCode = code
    throw err
}

/**
 * Issues a sync server token for future requests.
 *
 * @param did - The user's DID.
 * @returns A signed JWT as a string.
 */
export async function issueSyncServerToken(client_id: string, did: string, lexiconAuthorityDomain: string): Promise<string> {
    // Use a secure secret key stored in an environment variable
    const secretKey = process.env.GROUNDMIST_SYNC_SECRET_KEY;
    if (!secretKey) {
        throw new Error('GROUNDMIST_SYNC_SECRET_KEY is not defined');
    }

    // Define the payload. You can include additional claims if needed.
    const payload = {
        did,
        client_id,
        session_id: randomUUID(), // Generate a unique device identifier per session
        lexiconAuthorityDomain,
    };

    // TODO: set expiration
    // const options = {
    //     expiresIn: '3600'
    // };
    const options = {}

    // Sign and return the token
    return jwt.sign(payload, secretKey, options);
}