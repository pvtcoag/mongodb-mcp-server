import { randomUUID, randomBytes } from "node:crypto";
import type { Response } from "express";
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type {
    OAuthClientInformationFull,
    OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { InvalidRequestError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { renderLoginPage } from "./loginPage.js";
import { cookieName, verifySessionCookie } from "./sessionCookie.js";

const AUTHORIZATION_CODE_TTL_MS = 10 * 60 * 1000;

class InMemoryClientsStore implements OAuthRegisteredClientsStore {
    private clients = new Map<string, OAuthClientInformationFull>();

    getClient(clientId: string): OAuthClientInformationFull | undefined {
        return this.clients.get(clientId);
    }

    registerClient(
        client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">
    ): OAuthClientInformationFull {
        const full: OAuthClientInformationFull = {
            ...client,
            client_id: randomUUID(),
            client_id_issued_at: Math.floor(Date.now() / 1000),
        };
        this.clients.set(full.client_id, full);
        return full;
    }
}

type StoredCode = {
    client: OAuthClientInformationFull;
    params: AuthorizationParams;
    expiresAt: number;
};

type StoredToken = {
    token: string;
    clientId: string;
    scopes: string[];
    expiresAt: number;
    resource?: URL;
};

type StoredRefreshToken = {
    token: string;
    clientId: string;
    scopes: string[];
    expiresAt: number;
    resource?: URL;
};

export type PasswordGatedAuthProviderOptions = {
    adminPassword: string;
    sessionSecret: string;
    accessTokenTtlSec: number;
    refreshTokenTtlSec: number;
};

export class PasswordGatedAuthProvider implements OAuthServerProvider {
    public readonly clientsStore: OAuthRegisteredClientsStore = new InMemoryClientsStore();
    private readonly codes = new Map<string, StoredCode>();
    private readonly tokens = new Map<string, StoredToken>();
    private readonly refreshTokens = new Map<string, StoredRefreshToken>();

    constructor(private readonly options: PasswordGatedAuthProviderOptions) {}

    get adminPassword(): string {
        return this.options.adminPassword;
    }

    get sessionSecret(): string {
        return this.options.sessionSecret;
    }

    async authorize(
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
        res: Response
    ): Promise<void> {
        if (!client.redirect_uris.includes(params.redirectUri)) {
            throw new InvalidRequestError("Unregistered redirect_uri");
        }

        const cookieRaw = this.extractSessionCookie(res.req?.headers.cookie);
        const sessionValid = verifySessionCookie(cookieRaw, this.options.sessionSecret);

        if (!sessionValid) {
            const query = new URLSearchParams();
            query.set("client_id", client.client_id);
            query.set("redirect_uri", params.redirectUri);
            query.set("response_type", "code");
            query.set("code_challenge", params.codeChallenge);
            query.set("code_challenge_method", "S256");
            if (params.state) query.set("state", params.state);
            if (params.scopes?.length) query.set("scope", params.scopes.join(" "));
            if (params.resource) query.set("resource", params.resource.toString());

            res.status(200).set("Content-Type", "text/html; charset=utf-8").send(
                renderLoginPage({ authorizeQuery: query.toString() })
            );
            return;
        }

        const code = randomUUID();
        this.codes.set(code, {
            client,
            params,
            expiresAt: Date.now() + AUTHORIZATION_CODE_TTL_MS,
        });

        const target = new URL(params.redirectUri);
        target.searchParams.set("code", code);
        if (params.state) target.searchParams.set("state", params.state);
        res.redirect(target.toString());
    }

    async challengeForAuthorizationCode(
        _client: OAuthClientInformationFull,
        authorizationCode: string
    ): Promise<string> {
        const stored = this.codes.get(authorizationCode);
        if (!stored) {
            throw new InvalidRequestError("Invalid authorization code");
        }
        return stored.params.codeChallenge;
    }

    async exchangeAuthorizationCode(
        client: OAuthClientInformationFull,
        authorizationCode: string,
        _codeVerifier?: string,
        _redirectUri?: string,
        _resource?: URL
    ): Promise<OAuthTokens> {
        const stored = this.codes.get(authorizationCode);
        if (!stored) {
            throw new InvalidRequestError("Invalid authorization code");
        }
        this.codes.delete(authorizationCode);

        if (stored.expiresAt < Date.now()) {
            throw new InvalidRequestError("Authorization code has expired");
        }
        if (stored.client.client_id !== client.client_id) {
            throw new InvalidRequestError("Authorization code was not issued to this client");
        }

        return this.issueTokens(client.client_id, stored.params.scopes ?? [], stored.params.resource);
    }

    async exchangeRefreshToken(
        client: OAuthClientInformationFull,
        refreshToken: string,
        scopes?: string[],
        resource?: URL
    ): Promise<OAuthTokens> {
        const stored = this.refreshTokens.get(refreshToken);
        if (!stored) {
            throw new InvalidRequestError("Invalid refresh token");
        }
        if (stored.expiresAt < Date.now()) {
            this.refreshTokens.delete(refreshToken);
            throw new InvalidRequestError("Refresh token has expired");
        }
        if (stored.clientId !== client.client_id) {
            throw new InvalidRequestError("Refresh token was not issued to this client");
        }

        const grantedScopes = scopes ?? stored.scopes;
        if (scopes) {
            for (const scope of scopes) {
                if (!stored.scopes.includes(scope)) {
                    throw new InvalidRequestError("Requested scope exceeds original grant");
                }
            }
        }

        this.refreshTokens.delete(refreshToken);
        return this.issueTokens(client.client_id, grantedScopes, resource ?? stored.resource);
    }

    async verifyAccessToken(token: string): Promise<AuthInfo> {
        const stored = this.tokens.get(token);
        if (!stored) {
            throw new InvalidRequestError("Invalid access token");
        }
        if (stored.expiresAt < Date.now()) {
            this.tokens.delete(token);
            throw new InvalidRequestError("Access token has expired");
        }

        return {
            token,
            clientId: stored.clientId,
            scopes: stored.scopes,
            expiresAt: Math.floor(stored.expiresAt / 1000),
            resource: stored.resource,
        };
    }

    private issueTokens(clientId: string, scopes: string[], resource?: URL): OAuthTokens {
        const accessToken = randomBytes(32).toString("hex");
        const refreshToken = randomBytes(32).toString("hex");
        const now = Date.now();
        const accessExp = now + this.options.accessTokenTtlSec * 1000;
        const refreshExp = now + this.options.refreshTokenTtlSec * 1000;

        this.tokens.set(accessToken, {
            token: accessToken,
            clientId,
            scopes,
            expiresAt: accessExp,
            resource,
        });
        this.refreshTokens.set(refreshToken, {
            token: refreshToken,
            clientId,
            scopes,
            expiresAt: refreshExp,
            resource,
        });

        return {
            access_token: accessToken,
            token_type: "Bearer",
            expires_in: this.options.accessTokenTtlSec,
            refresh_token: refreshToken,
            scope: scopes.join(" "),
        };
    }

    private extractSessionCookie(cookieHeader: string | undefined): string | undefined {
        if (!cookieHeader) return undefined;
        const name = cookieName();
        for (const part of cookieHeader.split(";")) {
            const [k, ...rest] = part.trim().split("=");
            if (k === name) return rest.join("=");
        }
        return undefined;
    }
}

