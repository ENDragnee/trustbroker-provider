import axios, { AxiosInstance } from 'axios';
import { Request, Response, NextFunction } from 'express';

// --- Type Definitions ---

/**
 * Configuration for initializing the TrustBrokerProvider client.
 */
export interface TrustBrokerProviderConfig {
  /** Your institution's unique client ID. */
  clientId: string;
  /** Your institution's secret key. */
  clientSecret: string;
  /** The base URL of the TrustBroker API. Defaults to production. */
  apiBaseUrl?: string;
}

/**
 * The shape of the verified payload attached to the request object
 * after successful authentication by the middleware.
 */
export interface VerifiedTrustBrokerToken {
  active: true;
  requestId: string;
  requesterId: string;
  providerId: string;
  schemaId: string;
  fields?: string[];
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

// This uses TypeScript's module augmentation to add a new property
// to the Express Request object, so you can access it in a type-safe way.
declare global {
  namespace Express {
    export interface Request {
      trustbroker?: VerifiedTrustBrokerToken;
    }
  }
}

// --- The Main Provider Client Class ---

export class TrustBrokerProvider {
  private readonly axiosInstance: AxiosInstance;
  private readonly clientId: string;
  private readonly clientSecret: string;

  constructor(config: TrustBrokerProviderConfig) {
    if (!config.clientId || !config.clientSecret) {
      throw new Error('TrustBrokerProvider Error: clientId and clientSecret are required.');
    }
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;

    this.axiosInstance = axios.create({
      baseURL: config.apiBaseUrl || 'https://api.yourplatform.com/api/v1',
      headers: {
        'Content-Type': 'application/json',
        'x-client-id': this.clientId,
        'x-client-secret': this.clientSecret,
      },
    });
  }

  /**
   * Creates an Express-style middleware function that validates the TrustBroker accessToken.
   * If the token is valid, it attaches the decoded payload to `req.trustbroker`.
   * If invalid, it ends the request with an appropriate error.
   *
   * @returns {Function} An Express middleware function.
   */
  public createAuthMiddleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: Missing or malformed Bearer token.' });
      }

      const token = authHeader.split(' ')[1];

      try {
        const response = await this.axiosInstance.post<VerifiedTrustBrokerToken>('/tokens/introspect', {
          token,
        });

        const introspectionResult = response.data;

        if (introspectionResult.active === true) {
          // Success! Attach the verified payload to the request object.
          req.trustbroker = introspectionResult;
          // Pass control to the next handler in the chain (your main API logic).
          next();
        } else {
          // Token is validly formed but not active (e.g., for another provider, expired).
          return res.status(403).json({ error: 'Forbidden: Invalid token.' });
        }
      } catch (error) {
        console.error('TrustBroker Provider Middleware Error:', error);
        // This catches network errors or if the introspection endpoint itself returns an error.
        return res.status(500).json({ error: 'Failed to verify authentication token.' });
      }
    };
  }
}
