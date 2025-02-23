import express, { RequestHandler } from "express";
import { createProxyMiddleware } from "http-proxy-middleware";

/**
 * Options for proxying specific OAuth endpoints
 */
type EndpointProxyOptions = Partial<Record<"authorize" | "token" | "revoke" | "register", URL>>;

/**
 * Proxy options including metadata and specific endpoints
 */
type ProxyOptions = {
  metadataUrl?: URL; // Upstream for metadata
  endpoints?: EndpointProxyOptions; // Specific OAuth endpoints
};

/**
 * Creates an OAuth2 Proxy Router
 */
export function mcpAuthProxyRouter({ metadataUrl, endpoints = {} }: ProxyOptions): RequestHandler {
  if (!metadataUrl && Object.keys(endpoints).length === 0) {
    throw new Error("At least one of metadataUrl or an endpoint must be provided.");
  }

  const router = express.Router();

  // Proxy metadata if provided
  if (metadataUrl) {
    router.use(
      "/.well-known/oauth-authorization-server",
      createProxyMiddleware({
        target: metadataUrl.origin,
        changeOrigin: true,
        pathRewrite: { "^/.well-known/oauth-authorization-server": "/.well-known/oauth-authorization-server" },
      })
    );
  }

  // Proxy configured OAuth endpoints
  Object.entries(endpoints).forEach(([key, url]) => {
    if (url) {
      router.use(`/${key}`, createProxyMiddleware({ target: url.origin, changeOrigin: true }));
    }
  });

  return router;
}