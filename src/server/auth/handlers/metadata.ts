import express, { RequestHandler } from "express";
import cors from 'cors';
import { allowedMethods } from "../middleware/allowedMethods.js";
import { OAuthServerProvider } from "../provider.js";
import { ProxyOAuthServerProvider } from "../providers/proxyProvider.js";
import { DEFAULT_AUTHORIZATION_ENDPOINT, DEFAULT_TOKEN_ENDPOINT, DEFAULT_REVOCATION_ENDPOINT, DEFAULT_REGISTRATION_ENDPOINT } from "../router.js";

/**
 * Implements RFC 8414 OAuth 2.0 Authorization Server Metadata
 * @see https://datatracker.ietf.org/doc/html/rfc8414
 */
export function metadataHandler({ provider, issuer, serviceDocumentationUrl }: { provider: OAuthServerProvider, issuer: URL, serviceDocumentationUrl?: URL }): RequestHandler {
  const isProxy = provider instanceof ProxyOAuthServerProvider;

  // Helper function to build URLs
  const buildUrl = (path: string) => new URL(path, issuer).href;

  // Get endpoints based on provider type
  // By default, construct from issuer URL and endpoint paths
  // If proxy provider and url is provided, use that instead
  let authorization_endpoint = buildUrl(DEFAULT_AUTHORIZATION_ENDPOINT);
  if (isProxy && provider.authorizationUrl) {
    authorization_endpoint = provider.authorizationUrl;
  } 

  let token_endpoint = buildUrl(DEFAULT_TOKEN_ENDPOINT);
  if (isProxy && provider.tokenUrl) {
    token_endpoint = provider.tokenUrl;
  }

  let revocation_endpoint = undefined;
  if (provider.revokeToken) {
    if (isProxy && provider.revocationUrl) {
      revocation_endpoint = provider.revocationUrl;
    } else {
      revocation_endpoint = buildUrl(DEFAULT_REVOCATION_ENDPOINT);
    }
  }

  let registration_endpoint = undefined;
  if (provider.clientsStore.registerClient) {
    if (isProxy && provider.registrationUrl) {
      registration_endpoint = provider.registrationUrl;
    } else {
      registration_endpoint = buildUrl(DEFAULT_REGISTRATION_ENDPOINT);
    }
  }
  const metadata = {
    issuer: issuer.href,
    service_documentation: serviceDocumentationUrl?.href,

    authorization_endpoint,
    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256"],

    token_endpoint,
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    grant_types_supported: ["authorization_code", "refresh_token"],

    revocation_endpoint,
    revocation_endpoint_auth_methods_supported: revocation_endpoint ? ["client_secret_post"] : undefined,

    registration_endpoint,
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