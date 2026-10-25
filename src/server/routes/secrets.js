const express = require('express');
const { requireAuth } = require('../middleware');
const secrets = require('../secrets');

const router = express.Router();

// Management is limited to signed-in users (not API keys): a leaked API key
// should not be able to swap a stored password. Values are write-only; no
// route returns one.

const sendError = (res, err, fallback) => {
    if (err instanceof secrets.SecretsError) {
        const status = err.code === 'NOT_FOUND' ? 404
            : err.code === 'NAME_TAKEN' ? 409
            : err.code === 'SECRETS_KEY_NOT_SET' || err.code === 'INVALID_SECRETS_KEY' ? 503
            : 400;
        return res.status(status).json({ error: err.code, details: err.message });
    }
    console.error('[SECRETS]', fallback, err && err.message);
    return res.status(500).json({ error: fallback });
};

// GET /api/secrets/status
router.get('/status', requireAuth, async (req, res) => {
    try {
        res.json(await secrets.status());
    } catch (err) {
        sendError(res, err, 'FAILED_TO_LOAD_SECRETS');
    }
});

// GET /api/secrets
router.get('/', requireAuth, async (req, res) => {
    try {
        res.json(await secrets.listSecrets());
    } catch (err) {
        sendError(res, err, 'FAILED_TO_LOAD_SECRETS');
    }
});

// POST /api/secrets
router.post('/', requireAuth, async (req, res) => {
    const { name, value, description } = req.body || {};
    try {
        res.json(await secrets.createSecret({ name, value, description }));
    } catch (err) {
        sendError(res, err, 'FAILED_TO_SAVE_SECRET');
    }
});

// PUT /api/secrets/:id — any of name, value, description
router.put('/:id', requireAuth, async (req, res) => {
    const { name, value, description } = req.body || {};
    try {
        res.json(await secrets.updateSecret(String(req.params.id), { name, value, description }));
    } catch (err) {
        sendError(res, err, 'FAILED_TO_SAVE_SECRET');
    }
});

// DELETE /api/secrets/:id
router.delete('/:id', requireAuth, async (req, res) => {
    try {
        await secrets.deleteSecret(String(req.params.id));
        res.json({ success: true });
    } catch (err) {
        sendError(res, err, 'FAILED_TO_DELETE_SECRET');
    }
});

module.exports = router;
