import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

const MAGIC = "MDBOAUTH1"; // file format marker
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

export type EncryptionKey = Buffer;

export function parseEncryptionKey(hex: string): EncryptionKey {
    const buf = Buffer.from(hex.trim(), "hex");
    if (buf.length !== KEY_LEN) {
        throw new Error(
            `Encryption key must be 32 bytes (64 hex chars); got ${buf.length} bytes. ` +
                `Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
        );
    }
    return buf;
}

export type EncryptedEnvelope = {
    magic: string;
    iv: string; // base64
    tag: string; // base64
    ciphertext: string; // base64
};

export function encrypt(plaintext: string, key: EncryptionKey): EncryptedEnvelope {
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    if (tag.length !== TAG_LEN) {
        throw new Error(`Unexpected GCM tag length: ${tag.length}`);
    }
    return {
        magic: MAGIC,
        iv: iv.toString("base64"),
        tag: tag.toString("base64"),
        ciphertext: ct.toString("base64"),
    };
}

export function decrypt(envelope: EncryptedEnvelope, key: EncryptionKey): string {
    if (envelope.magic !== MAGIC) {
        throw new Error(`Encrypted envelope has unexpected magic: ${envelope.magic}`);
    }
    const iv = Buffer.from(envelope.iv, "base64");
    const tag = Buffer.from(envelope.tag, "base64");
    const ct = Buffer.from(envelope.ciphertext, "base64");
    if (iv.length !== IV_LEN) throw new Error("Invalid IV length on encrypted file");
    if (tag.length !== TAG_LEN) throw new Error("Invalid GCM tag length on encrypted file");

    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

export type LoadResult<T> =
    | { state: "missing" }
    | { state: "loaded"; value: T; wasEncrypted: boolean };

export type StoreOptions<T> = {
    filePath: string;
    encryptionKey: EncryptionKey | undefined;
    /**
     * Validates parsed JSON. Should THROW if invalid. Receives untrusted input.
     */
    validate: (value: unknown) => T;
};

export class EncryptedFileStore<T> {
    constructor(private readonly opts: StoreOptions<T>) {}

    async load(): Promise<LoadResult<T>> {
        let raw: string;
        try {
            raw = await fs.readFile(this.opts.filePath, "utf8");
        } catch (err) {
            if ((err as NodeJS.ErrnoException).code === "ENOENT") {
                return { state: "missing" };
            }
            throw err;
        }

        let parsed: unknown;
        try {
            parsed = JSON.parse(raw);
        } catch (err) {
            throw new Error(`OAuth state file is not valid JSON: ${(err as Error).message}`);
        }

        // Detect encrypted envelope
        if (this.looksEncrypted(parsed)) {
            if (!this.opts.encryptionKey) {
                throw new Error(
                    "OAuth state file is encrypted but no MDB_MCP_OAUTH_ENCRYPTION_KEY is configured. Refusing to start."
                );
            }
            const plaintext = decrypt(parsed as EncryptedEnvelope, this.opts.encryptionKey);
            const inner = JSON.parse(plaintext) as unknown;
            const value = this.opts.validate(inner);
            return { state: "loaded", value, wasEncrypted: true };
        }

        // Plaintext (legacy or first-run before key was added)
        const value = this.opts.validate(parsed);
        return { state: "loaded", value, wasEncrypted: false };
    }

    /**
     * Atomically writes the value (encrypted if a key is configured).
     * Uses tmp-file + rename so a crash mid-write never produces a torn file.
     */
    async save(value: T): Promise<void> {
        const dir = path.dirname(this.opts.filePath);
        await fs.mkdir(dir, { recursive: true });

        const json = JSON.stringify(value);
        const payload = this.opts.encryptionKey
            ? JSON.stringify(encrypt(json, this.opts.encryptionKey))
            : json;

        const tmp = `${this.opts.filePath}.tmp.${process.pid}.${randomBytes(6).toString("hex")}`;
        const fh = await fs.open(tmp, "w", 0o600);
        try {
            await fh.writeFile(payload, "utf8");
            await fh.sync();
        } finally {
            await fh.close();
        }
        await fs.rename(tmp, this.opts.filePath);
    }

    private looksEncrypted(parsed: unknown): parsed is EncryptedEnvelope {
        return (
            typeof parsed === "object" &&
            parsed !== null &&
            "magic" in parsed &&
            (parsed as { magic: unknown }).magic === MAGIC
        );
    }
}
