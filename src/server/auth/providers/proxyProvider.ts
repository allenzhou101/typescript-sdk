import { Response } from "express";
import { OAuthRegisteredClientsStore } from "../clients.js";
import { 
  OAuthClientInformationFull, 
  OAuthTokenRevocationRequest, 
  OAuthTokens,
  OAuthTokensSchema,
} from "../../../shared/auth.js";
import { AuthInfo } from "../types.js";
import { AuthorizationParams, OAuthServerProvider } from "../provider.js";
import { ServerError } from "../errors.js";

export type ProxyEndpoints = {
  authorizationUrl?: string;
  tokenUrl?: string;
  revocationUrl?: string;
  registrationUrl?: string;
};

export type ProxyOptions = {
  /**
   * Individual endpoint URLs for proxying specific OAuth operations
   */
  endpoints: ProxyEndpoints;

   /**
   * Function to verify access tokens and return auth info
   */
   verifyToken: (token: string) => Promise<AuthInfo>;

   /**
   * Function to fetch client information from the upstream server
   */
  getClient: (clientId: string) => Promise<OAuthClientInformationFull | undefined>;

};

/**
 * Implements an OAuth server that proxies requests to another OAuth server.
 */
export class ProxyOAuthServerProvider implements OAuthServerProvider {
  private readonly _endpoints: ProxyEndpoints;
  private readonly _verifyToken: (token: string) => Promise<AuthInfo>;
  private readonly _getClient: (clientId: string) => Promise<OAuthClientInformationFull | undefined>;

  public revokeToken?: (
    client: OAuthClientInformationFull, 
    request: OAuthTokenRevocationRequest
  ) => Promise<void>;

  constructor(options: ProxyOptions) {
    this._endpoints = options.endpoints;
    this._verifyToken = options.verifyToken;
    this._getClient = options.getClient;
    if (options.endpoints?.revocationUrl) {
      this.revokeToken = async (
        client: OAuthClientInformationFull, 
        request: OAuthTokenRevocationRequest
      ) => {
        const revocationUrl = this._endpoints.revocationUrl;
    
        if (!revocationUrl) {
          throw new Error("No revocation endpoint configured");
        }
    
        const params = new URLSearchParams();
        params.set("token", request.token);
        params.set("client_id", client.client_id);
        params.set("client_secret", client.client_secret || "");
        if (request.token_type_hint) {
          params.set("token_type_hint", request.token_type_hint);
        }
    
        const response = await fetch(revocationUrl, {
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
    }
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    const registrationUrl = this._endpoints.registrationUrl;
    return {
      getClient: this._getClient,
      ...(registrationUrl && {
        registerClient: async (client: OAuthClientInformationFull) => {
          const response = await fetch(registrationUrl, {
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
      })
    }
  }

  async authorize(
    client: OAuthClientInformationFull, 
    params: AuthorizationParams, 
    res: Response
  ): Promise<void> {
    const authorizationUrl = this._endpoints.authorizationUrl;

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
    const tokenUrl = this._endpoints.tokenUrl;

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

    const data = await response.json();
    return OAuthTokensSchema.parse(data);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull, 
    refreshToken: string,
    scopes?: string[]
  ): Promise<OAuthTokens> {
    const tokenUrl = this._endpoints.tokenUrl;

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

    const data = await response.json();
    return OAuthTokensSchema.parse(data);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    return this._verifyToken(token);
  }  

  get authorizationUrl(): string | undefined {
    return this._endpoints.authorizationUrl;
  }

  get tokenUrl(): string | undefined {
    return this._endpoints.tokenUrl;
  }

  get revocationUrl(): string | undefined {
    return this._endpoints.revocationUrl;
  }

  get registrationUrl(): string | undefined {
    return this._endpoints.registrationUrl;
  }
} 