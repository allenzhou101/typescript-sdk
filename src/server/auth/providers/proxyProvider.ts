import { Response } from "express";
import { OAuthRegisteredClientsStore } from "../clients.js";
import { 
  OAuthClientInformationFull, 
  OAuthTokenRevocationRequest, 
  OAuthTokens,
  OAuthMetadata 
} from "../../../shared/auth.js";
import { AuthInfo } from "../types.js";
import { AuthorizationParams, OAuthServerProvider } from "../provider.js";
import { ServerError } from "../errors.js";

export type ProxyEndpoints = {
  authorizationUrl?: string;
  tokenUrl?: string;
  revokeUrl?: string;
  registerUrl?: string;
};

export type ProxyOptions = {
  /**
   * string to the upstream OAuth server's metadata endpoint
   */
  metadataUrl?: string;

  /**
   * Individual endpoint URLs for proxying specific OAuth operations
   */
  endpoints?: ProxyEndpoints;

   /**
   * Function to verify access tokens and return auth info
   */
   verifyToken: (token: string) => Promise<AuthInfo>;
};

/**
 * Implements an OAuth server that proxies requests to another OAuth server.
 */
export class ProxyOAuthServerProvider implements OAuthServerProvider {
  private readonly _metadataUrl?: string;
  private readonly _endpoints: ProxyEndpoints;
  private _metadata?: OAuthMetadata;
  private readonly _verifyToken: (token: string) => Promise<AuthInfo>;

  constructor(options: ProxyOptions) {
    if (!options.metadataUrl && !options.endpoints) {
      throw new Error("Either metadataUrl or at least one endpoint must be provided");
    }

    this._metadataUrl = options.metadataUrl;
    this._endpoints = options.endpoints || {};
    this._verifyToken = options.verifyToken;
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: async () => {
        // Base implementation returns undefined - can be overridden by subclasses
        return undefined;
      },
      registerClient: async (client: OAuthClientInformationFull) => {
        // Try upstream registration if available
        const metadata = await this.getMetadata();
        const registerUrl = this._endpoints.registerUrl || 
                          metadata?.registration_endpoint;

        if (registerUrl) {
          const response = await fetch(registerUrl, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify(client),
          });

          if (!response.ok) {
            throw new ServerError(`Client registration failed: ${response.status}`);
          }

          return response.json();
        }

        throw new Error("Client registration not supported");
      }
    };
  }

  private async getMetadata(): Promise<OAuthMetadata | undefined> {
    if (!this._metadataUrl) return undefined;
    
    if (!this._metadata) {
      const response = await fetch(this._metadataUrl);
      if (!response.ok) {
        throw new ServerError(`Failed to fetch OAuth metadata: ${response.status}`);
      }
      this._metadata = await response.json();
    }
    
    return this._metadata;
  }

  async authorize(
    client: OAuthClientInformationFull, 
    params: AuthorizationParams, 
    res: Response
  ): Promise<void> {
    const metadata = await this.getMetadata();
    const authorizationUrl = this._endpoints.authorizationUrl || 
                            metadata?.authorization_endpoint;

    if (!authorizationUrl) {
      throw new Error("No authorization endpoint configured");
    }

    // Start with required OAuth parameters
    const targetUrl = new URL(authorizationUrl);
    const searchParams = new URLSearchParams({
      client_id: client.client_id,
      response_type: "code",
      redirect_uri: params.redirectUri,
      code_challenge: params.codeChallenge,
      code_challenge_method: "S256"
    });

    // Add optional standard OAuth parameters
    if (params.state) searchParams.set("state", params.state);
    if (params.scopes?.length) searchParams.set("scope", params.scopes.join(" "));

    targetUrl.search = searchParams.toString();
    res.redirect(targetUrl.toString());
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull, 
    _authorizationCode: string
  ): Promise<string> {
    // In a proxy setup, we don't store the code challenge ourselves
    // Instead, we proxy the token request and let the upstream server validate it
    return "";
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull, 
    authorizationCode: string
  ): Promise<OAuthTokens> {
    const metadata = await this.getMetadata();
    const tokenUrl = this._endpoints.tokenUrl || 
                    metadata?.token_endpoint;

    if (!tokenUrl) {
      throw new Error("No token endpoint configured");
    }

    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: client.client_id,
        client_secret: client.client_secret || "",
        code: authorizationCode,
      }),
    });

    if (!response.ok) {
      throw new ServerError(`Token exchange failed: ${response.status}`);
    }

    return response.json();
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull, 
    refreshToken: string,
    scopes?: string[]
  ): Promise<OAuthTokens> {
    const metadata = await this.getMetadata();
    const tokenUrl = this._endpoints.tokenUrl || 
                    metadata?.token_endpoint;

    if (!tokenUrl) {
      throw new Error("No token endpoint configured");
    }

    const params = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: client.client_id,
      client_secret: client.client_secret || "",
      refresh_token: refreshToken,
    });

    if (scopes?.length) {
      params.set("scope", scopes.join(" "));
    }

    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params,
    });

    if (!response.ok) {
      throw new ServerError(`Token refresh failed: ${response.status}`);
    }

    return response.json();
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    return this._verifyToken(token);
  }

  async revokeToken(
    client: OAuthClientInformationFull, 
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    const metadata = await this.getMetadata();
    const revokeUrl = this._endpoints.revokeUrl || 
                     metadata?.revocation_endpoint;

    if (!revokeUrl) {
      throw new Error("No revocation endpoint configured");
    }

    const params = new URLSearchParams();
    params.set("token", request.token);
    params.set("client_id", client.client_id);
    params.set("client_secret", client.client_secret || "");
    if (request.token_type_hint) {
      params.set("token_type_hint", request.token_type_hint);
    }

    const response = await fetch(revokeUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params,
    });

    if (!response.ok) {
      throw new ServerError(`Token revocation failed: ${response.status}`);
    }
  }

  get metadataUrl(): string | undefined {
    return this._metadataUrl;
  }

  get authorizationUrl(): string | undefined {
    return this._endpoints.authorizationUrl;
  }

  get tokenUrl(): string | undefined {
    return this._endpoints.tokenUrl;
  }

  get revokeUrl(): string | undefined {
    return this._endpoints.revokeUrl;
  }

  get registerUrl(): string | undefined {
    return this._endpoints.registerUrl;
  }
} 