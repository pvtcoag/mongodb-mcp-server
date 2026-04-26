import { randomUUID, randomBytes } from "node:crypto";
import type { Response } from "express";
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type {
    OAuthClientInformationFull,
    OAuthTokenRevocationRequest,
    OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { InvalidRequestError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { LoggerBase } from "../../common/logging/loggerBase.js";
import { LogId } from "../../common/logging/loggingDefinitions.js";
import { renderLoginPage } from "./loginPage.js";
import { cookieName, verifySessionCookie } from "./sessionCookie.js";
import { EncryptedFileStore, type EncryptionKey } from "./encryptedStore.js";

const AUTHORIZATION_CODE_TTL_MS = 10 * 60 * 1000;
const LOG_CTX = "oauthProvider";

type StoredCode = {
    client: OAuthClientInformationFull;
    params: AuthorizationParams;
    expiresAt: number;
};

type Family = {
    familyId: string;
    clientId: string;
    scopes: string[];
    resource?: string;
    /** Time the family was originally minted (the auth_code grant). Drives the absolute cap. */
    originalIssuedAt: number;
    revoked: boolean;
};

type StoredAccessToken = {
    token: string;
    familyId: string;
    clientId: string;
    scopes: string[];
    expiresAt: number;
    resource?: string;
};

type StoredRefreshToken = {
    token: string;
    familyId: string;
    clientId: string;
    scopes: string[];
    expiresAt: number;
    resource?: string;
};

type ConsumedRefreshToken = {
    token: string;
    familyId: string;
    consumedAt: number;
};

type PersistedState = {
    version: 1;
    clients: Record<string, OAuthClientInformationFull>;
    families: Record<string, Family>;
    accessTokens: Record<string, StoredAccessToken>;
    refreshTokens: Record<string, StoredRefreshToken>;
    consumedRefreshTokens: Record<string, ConsumedRefreshToken>;
};

const TOKEN_RE = /^[a-f0-9]{64}$/;
const ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

function validatePersistedState(value: unknown): PersistedState {
    if (typeof value !== "object" || value === null) {
        throw new Error("OAuth state must be an object");
    }
    const v = value as Partial<PersistedState>;
    if (v.version !== 1) {
        throw new Error(`Unsupported OAuth state version: ${String(v.version)}`);
    }
    const out: PersistedState = {
        version: 1,
        clients: {},
        families: {},
        accessTokens: {},
        refreshTokens: {},
        consumedRefreshTokens: {},
    };

    const objOrEmpty = (x: unknown): Record<string, unknown> =>
        typeof x === "object" && x !== null && !Array.isArray(x) ? (x as Record<string, unknown>) : {};

    for (const [k, val] of Object.entries(objOrEmpty(v.clients))) {
        if (!ID_RE.test(k)) continue;
        const c = val as OAuthClientInformationFull;
        if (typeof c?.client_id === "string" && Array.isArray(c.redirect_uris)) {
            out.clients[k] = c;
        }
    }
    for (const [k, val] of Object.entries(objOrEmpty(v.families))) {
        if (!ID_RE.test(k)) continue;
        const f = val as Family;
        if (
            typeof f?.familyId === "string" &&
            typeof f.clientId === "string" &&
            typeof f.originalIssuedAt === "number" &&
            Array.isArray(f.scopes) &&
            typeof f.revoked === "boolean"
        ) {
            out.families[k] = f;
        }
    }
    for (const [k, val] of Object.entries(objOrEmpty(v.accessTokens))) {
        if (!TOKEN_RE.test(k)) continue;
        const t = val as StoredAccessToken;
        if (
            typeof t?.token === "string" &&
            typeof t.familyId === "string" &&
            typeof t.clientId === "string" &&
            typeof t.expiresAt === "number" &&
            Array.isArray(t.scopes)
        ) {
            out.accessTokens[k] = t;
        }
    }
    for (const [k, val] of Object.entries(objOrEmpty(v.refreshTokens))) {
        if (!TOKEN_RE.test(k)) continue;
        const t = val as StoredRefreshToken;
        if (
            typeof t?.token === "string" &&
            typeof t.familyId === "string" &&
            typeof t.clientId === "string" &&
            typeof t.expiresAt === "number" &&
            Array.isArray(t.scopes)
        ) {
            out.refreshTokens[k] = t;
        }
    }
    for (const [k, val] of Object.entries(objOrEmpty(v.consumedRefreshTokens))) {
        if (!TOKEN_RE.test(k)) continue;
        const c = val as ConsumedRefreshToken;
        if (typeof c?.token === "string" && typeof c.familyId === "string" && typeof c.consumedAt === "number") {
            out.consumedRefreshTokens[k] = c;
        }
    }
    return out;
}

class InMemoryClientsStore implements OAuthRegisteredClientsStore {
    constructor(
        private readonly clients: Map<string, OAuthClientInformationFull>,
        private readonly onChange: () => void,
        private readonly onRegister: (client: OAuthClientInformationFull) => void
    ) {}

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
        this.onRegister(full);
        this.onChange();
        return full;
    }
}

export type PasswordGatedAuthProviderOptions = {
    adminPassword: string;
    sessionSecret: string;
    accessTokenTtlSec: number;
    refreshTokenTtlSec: number;
    refreshTokenAbsoluteTtlSec: number;
    logger: LoggerBase;
    storage?: {
        filePath: string;
        encryptionKey?: EncryptionKey;
    };
};

export class PasswordGatedAuthProvider implements OAuthServerProvider {
    public readonly clientsStore: OAuthRegisteredClientsStore;

    private readonly clients = new Map<string, OAuthClientInformationFull>();
    private readonly codes = new Map<string, StoredCode>();
    private readonly families = new Map<string, Family>();
    private readonly accessTokens = new Map<string, StoredAccessToken>();
    private readonly refreshTokens = new Map<string, StoredRefreshToken>();
    private readonly consumedRefreshTokens = new Map<string, ConsumedRefreshToken>();

    private readonly logger: LoggerBase;
    private readonly store?: EncryptedFileStore<PersistedState>;
    private persistChain: Promise<void> = Promise.resolve();
    private migrateOnNextWrite = false;

    constructor(private readonly options: PasswordGatedAuthProviderOptions) {
        this.logger = options.logger;
        if (options.storage) {
            this.store = new EncryptedFileStore<PersistedState>({
                filePath: options.storage.filePath,
                encryptionKey: options.storage.encryptionKey,
                validate: validatePersistedState,
            });
        }
        this.clientsStore = new InMemoryClientsStore(
            this.clients,
            () => this.scheduleSave(),
            (client) => {
                this.logger.info({
                    id: LogId.oauthClientRegistered,
                    context: LOG_CTX,
                    message: `OAuth client registered: ${client.client_id}`,
                    attributes: { client_id: client.client_id },
                });
            }
        );
    }

    /**
     * Loads persisted state from disk. Must be called once before serving requests.
     * Throws on encrypted-but-no-key (refuses silent fallback).
     */
    async initialize(): Promise<void> {
        if (!this.store) return;
        try {
            const result = await this.store.load();
            if (result.state === "missing") {
                this.logger.info({
                    id: LogId.oauthStorageLoaded,
                    context: LOG_CTX,
                    message: "OAuth state file does not exist; starting fresh.",
                });
                return;
            }

            const state = result.value;
            for (const [k, v] of Object.entries(state.clients)) this.clients.set(k, v);
            for (const [k, v] of Object.entries(state.families)) this.families.set(k, v);
            for (const [k, v] of Object.entries(state.accessTokens)) this.accessTokens.set(k, v);
            for (const [k, v] of Object.entries(state.refreshTokens)) this.refreshTokens.set(k, v);
            for (const [k, v] of Object.entries(state.consumedRefreshTokens))
                this.consumedRefreshTokens.set(k, v);

            this.logger.info({
                id: LogId.oauthStorageLoaded,
                context: LOG_CTX,
                message:
                    `Loaded OAuth state (encrypted=${result.wasEncrypted}): ` +
                    `${this.clients.size} clients, ${this.families.size} families, ` +
                    `${this.accessTokens.size} access tokens, ${this.refreshTokens.size} refresh tokens.`,
            });

            // Plaintext-on-disk + key-now-present → migrate on next write.
            if (!result.wasEncrypted && this.options.storage?.encryptionKey) {
                this.migrateOnNextWrite = true;
                this.logger.notice({
                    id: LogId.oauthStorageMigratedToEncrypted,
                    context: LOG_CTX,
                    message: "OAuth state file is plaintext but an encryption key is configured; will encrypt on next write.",
                });
            }
        } catch (err) {
            this.logger.error({
                id: LogId.oauthStorageLoadFailed,
                context: LOG_CTX,
                message: `Failed to load OAuth state: ${err instanceof Error ? err.message : String(err)}`,
            });
            throw err;
        }
    }

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

        this.logger.info({
            id: LogId.oauthAuthorizeRequested,
            context: LOG_CTX,
            message: `Authorize requested by client ${client.client_id}`,
            attributes: { client_id: client.client_id },
        });

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

        this.logger.info({
            id: LogId.oauthCodeIssued,
            context: LOG_CTX,
            message: `Authorization code issued for client ${client.client_id}`,
            attributes: { client_id: client.client_id },
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

        // Mint a new family for this grant.
        const familyId = randomUUID();
        const now = Date.now();
        const scopes = stored.params.scopes ?? [];
        const resource = stored.params.resource?.toString();
        this.families.set(familyId, {
            familyId,
            clientId: client.client_id,
            scopes,
            resource,
            originalIssuedAt: now,
            revoked: false,
        });

        const tokens = this.issueTokens(familyId, client.client_id, scopes, resource);
        this.logger.info({
            id: LogId.oauthTokenIssued,
            context: LOG_CTX,
            message: `Access+refresh token issued (new family) for client ${client.client_id}`,
            attributes: { client_id: client.client_id, family_id: familyId },
        });
        await this.scheduleSave();
        return tokens;
    }

    async exchangeRefreshToken(
        client: OAuthClientInformationFull,
        refreshToken: string,
        scopes?: string[],
        resource?: URL
    ): Promise<OAuthTokens> {
        // Replay detection: if this RT was already consumed, nuke the family.
        const consumed = this.consumedRefreshTokens.get(refreshToken);
        if (consumed) {
            this.logger.warning({
                id: LogId.oauthRefreshReplayDetected,
                context: LOG_CTX,
                message: `Refresh token replay detected for family ${consumed.familyId}; revoking family.`,
                attributes: { client_id: client.client_id, family_id: consumed.familyId },
            });
            this.revokeFamily(consumed.familyId, "refresh_replay");
            await this.scheduleSave();
            throw new InvalidRequestError("Refresh token has been revoked");
        }

        const stored = this.refreshTokens.get(refreshToken);
        if (!stored) {
            throw new InvalidRequestError("Invalid refresh token");
        }
        if (stored.expiresAt < Date.now()) {
            this.refreshTokens.delete(refreshToken);
            await this.scheduleSave();
            throw new InvalidRequestError("Refresh token has expired");
        }
        if (stored.clientId !== client.client_id) {
            // Treat cross-client use as replay → revoke family.
            this.logger.warning({
                id: LogId.oauthRefreshReplayDetected,
                context: LOG_CTX,
                message: `Refresh token presented by wrong client; revoking family ${stored.familyId}.`,
                attributes: { client_id: client.client_id, family_id: stored.familyId },
            });
            this.revokeFamily(stored.familyId, "wrong_client");
            await this.scheduleSave();
            throw new InvalidRequestError("Refresh token was not issued to this client");
        }

        const family = this.families.get(stored.familyId);
        if (!family || family.revoked) {
            throw new InvalidRequestError("Refresh token has been revoked");
        }

        // Absolute cap: family can never live past originalIssuedAt + absoluteTtl.
        const absoluteCapMs = this.options.refreshTokenAbsoluteTtlSec * 1000;
        if (Date.now() - family.originalIssuedAt > absoluteCapMs) {
            this.logger.notice({
                id: LogId.oauthAbsoluteCapExceeded,
                context: LOG_CTX,
                message: `Family ${family.familyId} exceeded absolute lifetime cap; revoking.`,
                attributes: { client_id: client.client_id, family_id: family.familyId },
            });
            this.revokeFamily(family.familyId, "absolute_cap_exceeded");
            await this.scheduleSave();
            throw new InvalidRequestError("Refresh token family has reached its absolute lifetime cap");
        }

        const grantedScopes = scopes ?? stored.scopes;
        if (scopes) {
            for (const scope of scopes) {
                if (!stored.scopes.includes(scope)) {
                    throw new InvalidRequestError("Requested scope exceeds original grant");
                }
            }
        }

        // Consume this RT (rotation): move it to consumed, issue a new pair.
        this.refreshTokens.delete(refreshToken);
        this.consumedRefreshTokens.set(refreshToken, {
            token: refreshToken,
            familyId: family.familyId,
            consumedAt: Date.now(),
        });

        const tokens = this.issueTokens(
            family.familyId,
            client.client_id,
            grantedScopes,
            resource?.toString() ?? stored.resource
        );

        this.logger.info({
            id: LogId.oauthTokenRefreshed,
            context: LOG_CTX,
            message: `Refresh token rotated for family ${family.familyId}`,
            attributes: { client_id: client.client_id, family_id: family.familyId },
        });

        await this.scheduleSave();
        return tokens;
    }

    async verifyAccessToken(token: string): Promise<AuthInfo> {
        const stored = this.accessTokens.get(token);
        if (!stored) {
            throw new InvalidRequestError("Invalid access token");
        }
        const family = this.families.get(stored.familyId);
        if (!family || family.revoked) {
            this.accessTokens.delete(token);
            throw new InvalidRequestError("Access token has been revoked");
        }
        if (stored.expiresAt < Date.now()) {
            this.accessTokens.delete(token);
            throw new InvalidRequestError("Access token has expired");
        }

        return {
            token,
            clientId: stored.clientId,
            scopes: stored.scopes,
            expiresAt: Math.floor(stored.expiresAt / 1000),
            resource: stored.resource ? new URL(stored.resource) : undefined,
        };
    }

    async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
        const token = request.token;
        if (!token) return;

        // Try as access token first.
        const at = this.accessTokens.get(token);
        if (at && at.clientId === client.client_id) {
            this.revokeFamily(at.familyId, "explicit_revoke");
            this.logger.info({
                id: LogId.oauthTokenRevoked,
                context: LOG_CTX,
                message: `Access token revoked for family ${at.familyId} (explicit)`,
                attributes: { client_id: client.client_id, family_id: at.familyId },
            });
            await this.scheduleSave();
            return;
        }

        const rt = this.refreshTokens.get(token);
        if (rt && rt.clientId === client.client_id) {
            this.revokeFamily(rt.familyId, "explicit_revoke");
            this.logger.info({
                id: LogId.oauthTokenRevoked,
                context: LOG_CTX,
                message: `Refresh token revoked for family ${rt.familyId} (explicit)`,
                attributes: { client_id: client.client_id, family_id: rt.familyId },
            });
            await this.scheduleSave();
            return;
        }

        // Per RFC 7009 §2.2: revocation of an invalid token is a no-op success.
    }

    private issueTokens(
        familyId: string,
        clientId: string,
        scopes: string[],
        resource?: string
    ): OAuthTokens {
        const accessToken = randomBytes(32).toString("hex");
        const refreshToken = randomBytes(32).toString("hex");
        const now = Date.now();
        const accessExp = now + this.options.accessTokenTtlSec * 1000;
        const refreshExp = now + this.options.refreshTokenTtlSec * 1000;

        this.accessTokens.set(accessToken, {
            token: accessToken,
            familyId,
            clientId,
            scopes,
            expiresAt: accessExp,
            resource,
        });
        this.refreshTokens.set(refreshToken, {
            token: refreshToken,
            familyId,
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

    private revokeFamily(familyId: string, reason: string): void {
        const family = this.families.get(familyId);
        if (family) {
            family.revoked = true;
        }
        // Drop all live AT/RT for this family.
        for (const [k, v] of this.accessTokens) {
            if (v.familyId === familyId) this.accessTokens.delete(k);
        }
        for (const [k, v] of this.refreshTokens) {
            if (v.familyId === familyId) this.refreshTokens.delete(k);
        }
        this.logger.notice({
            id: LogId.oauthFamilyRevoked,
            context: LOG_CTX,
            message: `Token family ${familyId} revoked (reason=${reason})`,
            attributes: { family_id: familyId, reason },
        });
    }

    /**
     * Serializes saves so concurrent mutations never race the file.
     */
    private scheduleSave(): Promise<void> {
        if (!this.store) return Promise.resolve();
        const next = this.persistChain.then(async () => {
            try {
                const state: PersistedState = {
                    version: 1,
                    clients: Object.fromEntries(this.clients),
                    families: Object.fromEntries(this.families),
                    accessTokens: Object.fromEntries(this.accessTokens),
                    refreshTokens: Object.fromEntries(this.refreshTokens),
                    consumedRefreshTokens: Object.fromEntries(this.consumedRefreshTokens),
                };
                await this.store!.save(state);
                if (this.migrateOnNextWrite) {
                    this.migrateOnNextWrite = false;
                    this.logger.notice({
                        id: LogId.oauthStorageMigratedToEncrypted,
                        context: LOG_CTX,
                        message: "OAuth state file successfully re-written in encrypted form.",
                    });
                }
            } catch (err) {
                this.logger.error({
                    id: LogId.oauthStoragePersistFailed,
                    context: LOG_CTX,
                    message: `Failed to persist OAuth state: ${err instanceof Error ? err.message : String(err)}`,
                });
            }
        });
        this.persistChain = next.catch(() => undefined);
        return next;
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
