import { createHmac, timingSafeEqual } from "node:crypto";

const COOKIE_NAME = "mdb_mcp_oauth_session";
const COOKIE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

export function cookieName(): string {
    return COOKIE_NAME;
}

function sign(value: string, secret: string): string {
    return createHmac("sha256", secret).update(value).digest("hex");
}

export function createSessionCookie(secret: string): string {
    const issuedAt = Date.now().toString();
    const sig = sign(issuedAt, secret);
    return `${issuedAt}.${sig}`;
}

export function verifySessionCookie(raw: string | undefined, secret: string): boolean {
    if (!raw) return false;
    const parts = raw.split(".");
    if (parts.length !== 2) return false;
    const issuedAt = parts[0]!;
    const sig = parts[1]!;
    const issuedAtMs = Number(issuedAt);
    if (!Number.isFinite(issuedAtMs)) return false;
    if (Date.now() - issuedAtMs > COOKIE_MAX_AGE_MS) return false;
    const expected = sign(issuedAt, secret);
    const a = Buffer.from(sig, "hex");
    const b = Buffer.from(expected, "hex");
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
}

export const SESSION_COOKIE_MAX_AGE_MS = COOKIE_MAX_AGE_MS;
