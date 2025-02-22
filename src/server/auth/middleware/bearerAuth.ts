import { RequestHandler } from "express";
import { InsufficientScopeError, InvalidTokenError, OAuthError, ServerError } from "../errors.js";
import { OAuthServerProvider } from "../provider.js";
import { AuthInfo } from "../types.js";

export type BearerAuthMiddlewareOptions = {
  /**
   * Optional scopes that the token must have.
   * @default []
   */
  requiredScopes?: string[];
} & (
  | {
      /**
       * A provider used to verify tokens and handle OAuth operations
       */
      provider: OAuthServerProvider;
    }
  | {
      /**
       * A function to verify access tokens directly
       * Must return AuthInfo or throw appropriate OAuth errors
       */
      verifyToken: OAuthServerProvider['verifyAccessToken'];
    }
);

declare module "express-serve-static-core" {
  interface Request {
    /**
     * Information about the validated access token, if the `requireBearerAuth` middleware was used.
     */
    auth?: AuthInfo;
  }
}

/**
 * Middleware that requires a valid Bearer token in the Authorization header.
 * 
 * This will validate the token with the auth provider and add the resulting auth info to the request object.
 */
export function requireBearerAuth(options: BearerAuthMiddlewareOptions): RequestHandler {
  const verifyToken = 'provider' in options
    ? (token: string) => options.provider.verifyAccessToken(token)
    : options.verifyToken;

  const requiredScopes = options.requiredScopes ?? [];
  
  return async (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        throw new InvalidTokenError("Missing Authorization header");
      }

      const [type, token] = authHeader.split(' ');
      if (type.toLowerCase() !== 'bearer' || !token) {
        throw new InvalidTokenError("Invalid Authorization header format, expected 'Bearer TOKEN'");
      }

      const authInfo = await verifyToken(token);

      // Check if token has the required scopes (if any)
      if (requiredScopes.length > 0) {
        const hasAllScopes = requiredScopes.every(scope =>
          authInfo.scopes.includes(scope)
        );

        if (!hasAllScopes) {
          throw new InsufficientScopeError("Insufficient scope");
        }
      }

      req.auth = authInfo;
      next();
    } catch (error) {
      if (error instanceof InvalidTokenError) {
        res.set("WWW-Authenticate", `Bearer error="${error.errorCode}", error_description="${error.message}"`);
        res.status(401).json(error.toResponseObject());
      } else if (error instanceof InsufficientScopeError) {
        res.set("WWW-Authenticate", `Bearer error="${error.errorCode}", error_description="${error.message}"`);
        res.status(403).json(error.toResponseObject());
      } else if (error instanceof ServerError) {
        res.status(500).json(error.toResponseObject());
      } else if (error instanceof OAuthError) {
        res.status(400).json(error.toResponseObject());
      } else {
        console.error("Unexpected error authenticating bearer token:", error);
        const serverError = new ServerError("Internal Server Error");
        res.status(500).json(serverError.toResponseObject());
      }
    }
  };
}