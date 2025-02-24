import express, { RequestHandler } from "express";
import { clientRegistrationHandler, ClientRegistrationHandlerOptions } from "./handlers/register.js";
import { tokenHandler, TokenHandlerOptions } from "./handlers/token.js";
import { authorizationHandler, AuthorizationHandlerOptions } from "./handlers/authorize.js";
import { revocationHandler, RevocationHandlerOptions } from "./handlers/revoke.js";
import { metadataHandler } from "./handlers/metadata.js";
import { OAuthServerProvider } from "./provider.js";

export const DEFAULT_AUTHORIZATION_ENDPOINT = "/authorize";
export const DEFAULT_TOKEN_ENDPOINT = "/token";
export const DEFAULT_REGISTRATION_ENDPOINT = "/register";
export const DEFAULT_REVOCATION_ENDPOINT = "/revoke";
export const DEFAULT_METADATA_ENDPOINT = "/.well-known/oauth-authorization-server";

export type AuthRouterOptions = {
  /**
   * A provider implementing the actual authorization logic for this router.
   */
  provider: OAuthServerProvider;

  /**
   * The authorization server's issuer identifier, which is a URL that uses the "https" scheme and has no query or fragment components.
   */
  issuerUrl: URL;

  /**
   * An optional URL of a page containing human-readable information that developers might want or need to know when using the authorization server.
   */
  serviceDocumentationUrl?: URL;

  // Individual options per route
  authorizationOptions?: Omit<AuthorizationHandlerOptions, "provider">;
  clientRegistrationOptions?: Omit<ClientRegistrationHandlerOptions, "clientsStore">;
  revocationOptions?: Omit<RevocationHandlerOptions, "provider">;
  tokenOptions?: Omit<TokenHandlerOptions, "provider">;
};

/**
 * Installs standard MCP authorization endpoints, including dynamic client registration and token revocation (if supported). Also advertises standard authorization server metadata, for easier discovery of supported configurations by clients.
 * 
 * By default, rate limiting is applied to all endpoints to prevent abuse.
 * 
 * This router MUST be installed at the application root, like so:
 * 
 *  const app = express();
 *  app.use(mcpAuthRouter(...));
 */
export function mcpAuthRouter(options: AuthRouterOptions): RequestHandler {
  const issuer = options.issuerUrl;
  const provider = options.provider;
  const serviceDocumentationUrl = options.serviceDocumentationUrl;

  // Technically RFC 8414 does not permit a localhost HTTPS exemption, but this will be necessary for ease of testing
  if (issuer.protocol !== "https:" && issuer.hostname !== "localhost" && issuer.hostname !== "127.0.0.1") {
    throw new Error("Issuer URL must be HTTPS");
  }
  if (issuer.hash) {
    throw new Error("Issuer URL must not have a fragment");
  }
  if (issuer.search) {
    throw new Error("Issuer URL must not have a query string");
  }

  const router = express.Router();

  router.use(
    DEFAULT_AUTHORIZATION_ENDPOINT,
    authorizationHandler({ provider, ...options.authorizationOptions })
  );

  router.use(
    DEFAULT_TOKEN_ENDPOINT,
    tokenHandler({ provider, ...options.tokenOptions })
  );

  router.use(
    DEFAULT_METADATA_ENDPOINT,
    metadataHandler({ provider, issuer, serviceDocumentationUrl })
  );

  if (provider.clientsStore.registerClient) {
    router.use(
      DEFAULT_REGISTRATION_ENDPOINT,
      clientRegistrationHandler({
        clientsStore: provider.clientsStore,
        ...options,
      })
    );
  }

  if (provider.revokeToken) {
    router.use(
      DEFAULT_REVOCATION_ENDPOINT,
      revocationHandler({ provider: provider, ...options.revocationOptions })
    );
  }

  return router;
}