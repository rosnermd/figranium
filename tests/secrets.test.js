// Tests for the secret manager and typed-text logging.
// Run: node tests/secrets.test.js   (exit 0 = pass, 1 = fail)
//
// Storage and auth are replaced in the require cache so the test never touches
// data/ or needs a session.

const assert = require('assert');
const path = require('path');
const crypto = require('crypto');
const express = require('express');

let stored = [];
const storagePath = require.resolve('../src/server/storage');
require.cache[storagePath] = {
    id: storagePath,
    filename: storagePath,
    loaded: true,
    exports: {
        loadSecrets: async () => stored,
        saveSecrets: async (records) => { stored = records; }
    }
};
const middlewarePath = require.resolve('../src/server/middleware');
let signedIn = true;
require.cache[middlewarePath] = {
    id: middlewarePath,
    filename: middlewarePath,
    loaded: true,
    exports: {
        requireAuth: (req, res, next) => (signedIn ? next() : res.status(401).json({ error: 'UNAUTHORIZED' }))
    }
};

const KEY_HEX = crypto.randomBytes(32).toString('hex');
process.env.SECRETS_KEY = KEY_HEX;

const secrets = require('../src/server/secrets');
const secretRoutes = require('../src/server/routes/secrets');
const { describeTypedText } = require('../src/agent/figranite/action-handler');
const { createRedactor, MASK } = require('../redaction');

const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const reset = () => { stored = []; signedIn = true; process.env.SECRETS_KEY = KEY_HEX; };

test('parseKey accepts hex and base64 32-byte keys', () => {
    assert.strictEqual(secrets.parseKey(KEY_HEX).length, 32);
    assert.strictEqual(secrets.parseKey(crypto.randomBytes(32).toString('base64')).length, 32);
    assert.strictEqual(secrets.parseKey(''), null);
    assert.strictEqual(secrets.parseKey(undefined), null);
});

test('parseKey rejects keys that are not 32 bytes', () => {
    assert.throws(() => secrets.parseKey('too-short'), /SECRETS_KEY must be 32 bytes/);
    assert.throws(() => secrets.parseKey(crypto.randomBytes(16).toString('hex')), /SECRETS_KEY must be 32 bytes/);
});

test('encrypt/decrypt round-trips and stores no plaintext', () => {
    const key = secrets.parseKey(KEY_HEX);
    const record = { name: 'X', ...secrets.encryptValue(key, 'hunter2-password') };
    assert.ok(!JSON.stringify(record).includes('hunter2-password'));
    assert.strictEqual(secrets.decryptValue(key, record), 'hunter2-password');
});

test('decrypting with a different key reports a key mismatch', () => {
    const record = { name: 'X', ...secrets.encryptValue(secrets.parseKey(KEY_HEX), 'value-1234') };
    const other = crypto.randomBytes(32);
    assert.throws(() => secrets.decryptValue(other, record), /different SECRETS_KEY/);
});

test('tampered ciphertext fails authentication', () => {
    const key = secrets.parseKey(KEY_HEX);
    const record = { name: 'X', ...secrets.encryptValue(key, 'value-1234') };
    const bytes = Buffer.from(record.ciphertext, 'base64');
    bytes[0] ^= 0xff;
    assert.throws(() => secrets.decryptValue(key, { ...record, ciphertext: bytes.toString('base64') }));
});

test('create, update, decryptAll and delete', async () => {
    reset();
    const created = await secrets.createSecret({ name: 'STREAMLINE_PASSWORD', value: 'first-value', description: 'owner portal' });
    assert.deepStrictEqual(Object.keys(created).sort(), ['createdAt', 'description', 'id', 'name', 'updatedAt']);
    assert.strictEqual((await secrets.decryptAll()).values.STREAMLINE_PASSWORD, 'first-value');
    await secrets.updateSecret(created.id, { value: 'second-value' });
    assert.strictEqual((await secrets.decryptAll()).values.STREAMLINE_PASSWORD, 'second-value');
    assert.deepStrictEqual(secrets.getCachedSecretValues(), ['second-value']);
    await secrets.deleteSecret(created.id);
    assert.deepStrictEqual((await secrets.decryptAll()).values, {});
});

test('rejects bad names, duplicates, and empty values', async () => {
    reset();
    await assert.rejects(secrets.createSecret({ name: '1BAD', value: 'abcd' }), /Name must start/);
    await assert.rejects(secrets.createSecret({ name: 'has-dash', value: 'abcd' }), /Name must start/);
    await assert.rejects(secrets.createSecret({ name: 'OK', value: '' }), /Value is required/);
    await secrets.createSecret({ name: 'OK', value: 'abcd' });
    await assert.rejects(secrets.createSecret({ name: 'OK', value: 'efgh' }), /already exists/);
});

test('refuses to store anything without SECRETS_KEY', async () => {
    reset();
    delete process.env.SECRETS_KEY;
    await assert.rejects(secrets.createSecret({ name: 'X', value: 'abcd' }), (e) => e.code === 'SECRETS_KEY_NOT_SET');
    assert.strictEqual(stored.length, 0);
});

test('decryptAll reports, not throws, when the key is gone', async () => {
    reset();
    await secrets.createSecret({ name: 'X', value: 'abcd' });
    delete process.env.SECRETS_KEY;
    const { values, errors } = await secrets.decryptAll();
    assert.deepStrictEqual(values, {});
    assert.match(errors[0], /SECRETS_KEY is not set/);
});

test('API never returns a secret value', async () => {
    reset();
    const app = express();
    app.use(express.json());
    app.use('/api/secrets', secretRoutes);
    const server = app.listen(0);
    const base = `http://127.0.0.1:${server.address().port}/api/secrets`;
    try {
        const json = { 'Content-Type': 'application/json' };
        const created = await (await fetch(base, { method: 'POST', headers: json, body: JSON.stringify({ name: 'PW', value: 'never-show-me' }) })).json();
        const updated = await (await fetch(`${base}/${created.id}`, { method: 'PUT', headers: json, body: JSON.stringify({ value: 'still-hidden' }) })).json();
        const list = await (await fetch(base)).text();
        const status = await (await fetch(`${base}/status`)).json();
        for (const body of [JSON.stringify(created), JSON.stringify(updated), list]) {
            assert.ok(!body.includes('never-show-me') && !body.includes('still-hidden'), 'value leaked');
            assert.ok(!body.includes('ciphertext'), 'ciphertext leaked');
        }
        assert.deepStrictEqual({ keyConfigured: status.keyConfigured, count: status.count, mismatched: status.mismatched }, { keyConfigured: true, count: 1, mismatched: 0 });
        assert.strictEqual((await fetch(`${base}/nope`, { method: 'DELETE' })).status, 404);
        assert.strictEqual((await fetch(base, { method: 'POST', headers: json, body: JSON.stringify({ name: 'PW', value: 'x234' }) })).status, 409);
        signedIn = false;
        assert.strictEqual((await fetch(base)).status, 401);
    } finally {
        server.close();
    }
});

test('typing logs the length, never the text', () => {
    assert.strictEqual(describeTypedText('hunter2pass'), '11 characters');
    assert.strictEqual(describeTypedText('x'), '1 character');
    assert.strictEqual(describeTypedText(''), '0 characters');
    assert.ok(!describeTypedText('hunter2pass').includes('hunter2'));
});

test('a secret-manager value is masked wherever it surfaces', async () => {
    reset();
    await secrets.createSecret({ name: 'PW', value: 'awa-secret-9' });
    const { values } = await secrets.decryptAll();
    const r = createRedactor(Object.values(values));
    assert.strictEqual(r.redactString('error: login failed for awa-secret-9'), `error: login failed for ${MASK}`);
    assert.deepStrictEqual(r.redact({ data: [{ typed: 'awa-secret-9' }] }), { data: [{ typed: MASK }] });
});

(async () => {
    let failed = 0;
    for (const { name, fn } of tests) {
        try {
            await fn();
            console.log(`  PASS  ${name}`);
        } catch (err) {
            failed += 1;
            console.error(`  FAIL  ${name}`);
            console.error(`        ${err.message}`);
        }
    }
    console.log(`\n${tests.length - failed}/${tests.length} passed`);
    process.exit(failed === 0 ? 0 : 1);
})();
