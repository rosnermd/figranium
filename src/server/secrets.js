// Secret manager: named values (passwords, tokens) stored once, encrypted at
// rest, and referenced from any task as {$secret.NAME}.
//
// Values are encrypted with AES-256-GCM under SECRETS_KEY (32 bytes, hex or
// base64). Without that key the store refuses to write rather than falling
// back to plaintext. The API never returns a value; the only way a value
// leaves this module is decryptAll(), used by the agent at run time, and every
// value it hands out is registered with the run's redactor.

const crypto = require('crypto');
const { loadSecrets, saveSecrets } = require('./storage');

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const MAX_VALUE_LENGTH = 16 * 1024;
const MAX_DESCRIPTION_LENGTH = 200;

class SecretsError extends Error {
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}

/**
 * Parse SECRETS_KEY into a 32-byte key. Accepts 64 hex characters or base64
 * that decodes to exactly 32 bytes (`openssl rand -hex 32` / `-base64 32`).
 * @param {string|undefined} raw
 * @returns {Buffer|null} null when unset
 */
const parseKey = (raw) => {
    if (raw === undefined || raw === null || String(raw).trim() === '') return null;
    const text = String(raw).trim();
    if (/^[0-9a-fA-F]{64}$/.test(text)) return Buffer.from(text, 'hex');
    const b64 = Buffer.from(text, 'base64');
    if (b64.length === 32 && /^[A-Za-z0-9+/]+={0,2}$/.test(text)) return b64;
    throw new SecretsError('INVALID_SECRETS_KEY', 'SECRETS_KEY must be 32 bytes: 64 hex characters or base64 (generate with `openssl rand -hex 32`).');
};

// Short, non-reversible tag stored with each record so a changed SECRETS_KEY
// is reported as such instead of as a generic decryption failure.
const keyFingerprint = (key) => crypto.createHash('sha256').update(key).digest('hex').slice(0, 12);

const getKey = () => parseKey(process.env.SECRETS_KEY);

const encryptValue = (key, plaintext) => {
    const iv = crypto.randomBytes(IV_BYTES);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
    return {
        iv: iv.toString('base64'),
        tag: cipher.getAuthTag().toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        keyId: keyFingerprint(key)
    };
};

const decryptValue = (key, record) => {
    if (record.keyId && record.keyId !== keyFingerprint(key)) {
        throw new SecretsError('SECRETS_KEY_MISMATCH', `Secret "${record.name}" was encrypted with a different SECRETS_KEY.`);
    }
    const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(record.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(record.ciphertext, 'base64')), decipher.final()]).toString('utf8');
};

const toPublic = (record) => ({
    id: record.id,
    name: record.name,
    description: record.description || '',
    createdAt: record.createdAt,
    updatedAt: record.updatedAt
});

const validateName = (name) => {
    const text = String(name || '').trim();
    if (!NAME_PATTERN.test(text)) {
        throw new SecretsError('INVALID_NAME', 'Name must start with a letter or underscore and contain only letters, digits and underscores (max 64).');
    }
    return text;
};

const validateValue = (value) => {
    if (typeof value !== 'string' || value.length === 0) {
        throw new SecretsError('MISSING_VALUE', 'Value is required.');
    }
    if (value.length > MAX_VALUE_LENGTH) {
        throw new SecretsError('VALUE_TOO_LONG', `Value must be at most ${MAX_VALUE_LENGTH} characters.`);
    }
    return value;
};

const cleanDescription = (description) => String(description || '').trim().slice(0, MAX_DESCRIPTION_LENGTH);

const requireKey = () => {
    const key = getKey();
    if (!key) throw new SecretsError('SECRETS_KEY_NOT_SET', 'Set the SECRETS_KEY environment variable to store secrets.');
    return key;
};

// Decrypted values, kept so the synchronous response redactor in server.js
// can mask them without a storage round trip. Refreshed on every change.
let valueCache = null;

/**
 * Decrypt every stored secret.
 * @returns {Promise<{ values: Record<string, string>, errors: string[] }>}
 */
const decryptAll = async () => {
    const records = await loadSecrets();
    const values = {};
    const errors = [];
    if (records.length === 0) {
        valueCache = values;
        return { values, errors };
    }
    let key;
    try {
        key = getKey();
    } catch (e) {
        return { values, errors: [e.message] };
    }
    if (!key) return { values, errors: ['SECRETS_KEY is not set; stored secrets cannot be decrypted.'] };
    for (const record of records) {
        try {
            values[record.name] = decryptValue(key, record);
        } catch (e) {
            errors.push(e instanceof SecretsError ? e.message : `Secret "${record.name}" could not be decrypted.`);
        }
    }
    valueCache = values;
    return { values, errors };
};

/** Last decrypted values, or [] before the first decryptAll(). */
const getCachedSecretValues = () => (valueCache ? Object.values(valueCache) : []);

const status = async () => {
    let keyConfigured = false;
    let keyError = null;
    try {
        keyConfigured = !!getKey();
    } catch (e) {
        keyError = e.message;
    }
    const records = await loadSecrets();
    let mismatched = 0;
    if (keyConfigured) {
        const fp = keyFingerprint(getKey());
        mismatched = records.filter((r) => r.keyId && r.keyId !== fp).length;
    }
    return { keyConfigured, keyError, count: records.length, mismatched };
};

const listSecrets = async () => (await loadSecrets()).map(toPublic);

const createSecret = async ({ name, value, description }) => {
    const key = requireKey();
    const cleanName = validateName(name);
    validateValue(value);
    const records = await loadSecrets();
    if (records.some((r) => r.name === cleanName)) {
        throw new SecretsError('NAME_TAKEN', `A secret named "${cleanName}" already exists.`);
    }
    const now = new Date().toISOString();
    const record = {
        id: 'sec_' + crypto.randomBytes(8).toString('hex'),
        name: cleanName,
        description: cleanDescription(description),
        ...encryptValue(key, value),
        createdAt: now,
        updatedAt: now
    };
    await saveSecrets([...records, record]);
    await decryptAll();
    return toPublic(record);
};

const updateSecret = async (id, { name, value, description }) => {
    const records = await loadSecrets();
    const index = records.findIndex((r) => r.id === id);
    if (index === -1) throw new SecretsError('NOT_FOUND', 'Secret not found.');
    const next = { ...records[index] };
    if (name !== undefined) {
        const cleanName = validateName(name);
        if (records.some((r, i) => i !== index && r.name === cleanName)) {
            throw new SecretsError('NAME_TAKEN', `A secret named "${cleanName}" already exists.`);
        }
        next.name = cleanName;
    }
    if (description !== undefined) next.description = cleanDescription(description);
    if (value !== undefined) {
        validateValue(value);
        Object.assign(next, encryptValue(requireKey(), value));
    }
    next.updatedAt = new Date().toISOString();
    const updated = [...records];
    updated[index] = next;
    await saveSecrets(updated);
    await decryptAll();
    return toPublic(next);
};

const deleteSecret = async (id) => {
    const records = await loadSecrets();
    const remaining = records.filter((r) => r.id !== id);
    if (remaining.length === records.length) throw new SecretsError('NOT_FOUND', 'Secret not found.');
    await saveSecrets(remaining);
    await decryptAll();
};

module.exports = {
    SecretsError,
    NAME_PATTERN,
    parseKey,
    keyFingerprint,
    encryptValue,
    decryptValue,
    decryptAll,
    getCachedSecretValues,
    status,
    listSecrets,
    createSecret,
    updateSecret,
    deleteSecret
};
