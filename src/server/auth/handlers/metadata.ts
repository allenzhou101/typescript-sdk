import express, { RequestHandler } from "express";
import cors from 'cors';
import { allowedMethods } from "../middleware/allowedMethods.js";
import { OAuthServerProvider } from "../provider.js";
import { DEFAULT_AUTHORIZATION_ENDPOINT, DEFAULT_TOKEN_ENDPOINT, DEFAULT_REVOCATION_ENDPOINT, DEFAULT_REGISTRATION_ENDPOINT } from "../router.js";

/**
 * Implements RFC 8414 OAuth 2.0 Authorization Server Metadata
 * @see https://datatracker.ietf.org/doc/html/rfc8414
 */
export function metadataHandler({ provider, issuer, serviceDocumentationUrl }: { provider: OAuthServerProvider, issuer: URL, serviceDocumentationUrl?: URL }): RequestHandler {

  // // Helper function to build URLs
  const buildUrl = (path: string) => new URL(path, issuer).href;

  const metadata = {
    issuer: issuer.href,
    service_documentation: serviceDocumentationUrl?.href,

    authorization_endpoint: buildUrl(DEFAULT_AUTHORIZATION_ENDPOINT),
    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256"],

    token_endpoint: buildUrl(DEFAULT_TOKEN_ENDPOINT),
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    grant_types_supported: ["authorization_code", "refresh_token"],

    revocation_endpoint: provider.revokeToken ? buildUrl(DEFAULT_REVOCATION_ENDPOINT) : undefined,
    revocation_endpoint_auth_methods_supported: provider.revokeToken ? ["client_secret_post"] : undefined,

    registration_endpoint: provider.clientsStore.registerClient ? buildUrl(DEFAULT_REGISTRATION_ENDPOINT) : undefined ,
  };

  // Nested router so we can configure middleware and restrict HTTP method
  const router = express.Router();

  // Configure CORS to allow any origin, to make accessible to web-based MCP clients
  router.use(cors());

  router.use(allowedMethods(['GET']));
  router.get("/", (req, res) => {
    res.status(200).json(metadata);
  });

  return router;
}