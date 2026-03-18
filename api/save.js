import pkg from 'pg';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const { Client } = pkg;

// คำนวณ HMAC-SHA256 สำหรับ verify ลายเซ็นจาก SSO
function computeSignature(secret, timestamp, nonce, body) {
    const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
    const base = `${timestamp}\n${nonce}\n${bodyHash}`;
    return crypto.createHmac('sha256', secret).update(base).digest('base64url');
}

let cachedModel = null;
let cachedModelPath = null;

function loadModel() {
    // allow override via env for Railway/Vercel
    const envPath = process.env.RISK_MODEL_PATH;
    const modelPath = envPath
        ? path.resolve(process.cwd(), envPath)
        : path.resolve(process.cwd(), 'model', 'behavior-model.json');

    if (cachedModel && cachedModelPath === modelPath) return cachedModel;

    const raw = fs.readFileSync(modelPath, 'utf8');
    const parsed = JSON.parse(raw);
    cachedModel = parsed;
    cachedModelPath = modelPath;
    return cachedModel;
}

function sigmoid(x) {
    // ป้องกัน overflow
    if (x > 40) return 1;
    if (x < -40) return 0;
    return 1 / (1 + Math.exp(-x));
}

// AI-based risk scoring (logistic regression inference)
function computeRiskDecision(payload) {
    const { features = {}, ip, username } = payload || {};

    let model;
    try {
        model = loadModel();
    } catch (e) {
        // ถ้าโหลด model ไม่ได้ ให้ fail-open เป็น low (ไม่ทำให้ทั้งระบบเดี้ยง)
        return { action: 'low', score: 0, model_version: 'missing', meta: { ip, username } };
    }

    const weights = model.weights || {};
    const bias = typeof model.bias === 'number' ? model.bias : 0;

    // linear combination
    let z = bias;
    const featureNames = Array.isArray(model.features) ? model.features : Object.keys(weights);
    for (const name of featureNames) {
        const w = typeof weights[name] === 'number' ? weights[name] : 0;
        const x = typeof features[name] === 'number' ? features[name] : 0;
        z += w * x;
    }

    const score = sigmoid(z);

    const mediumTh = model.thresholds?.medium ?? 0.55;
    const revokeTh = model.thresholds?.revoke ?? 0.82;

    let action = 'low';
    if (score >= revokeTh) action = 'revoke';
    else if (score >= mediumTh) action = 'medium';

    return {
        action,
        score,
        model_version: model.model_version || 'unknown',
        meta: { ip, username }
    };
}

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    // raw body สำหรับตรวจลายเซ็นจาก SSO (Vercel/Node 18+: body อาจถูก parse แล้ว)
    const rawBody = JSON.stringify(req.body || {});

    try {
        await client.connect();
        const data = req.body || {};

        // ── 1) Verify ลายเซ็นจาก SSO (ป้องกัน spoof ระหว่าง SSO ↔ Risk Engine) ──
        const sharedSecret = process.env.RISK_ENGINE_SHARED_SECRET;
        if (sharedSecret) {
            const tsHeader   = req.headers['x-risk-timestamp'];
            const nonce      = req.headers['x-risk-nonce'];
            const sigHeader  = req.headers['x-risk-signature'];

            if (!tsHeader || !nonce || !sigHeader || typeof sigHeader !== 'string') {
                return res.status(401).json({ error: 'Missing risk signature headers' });
            }

            const now    = Date.now();
            const parsed = Date.parse(String(tsHeader));
            if (!Number.isFinite(parsed) || Math.abs(now - parsed) > 5 * 60 * 1000) {
                return res.status(401).json({ error: 'Stale risk signature timestamp' });
            }

            const expected = computeSignature(sharedSecret, String(tsHeader), String(nonce), rawBody);
            const provided = sigHeader.startsWith('v1=') ? sigHeader.slice(3) : sigHeader;

            // timingSafeEqual จะ throw ถ้าความยาวต่างกัน → ต้อง guard ก่อน
            const expectedBuf = Buffer.from(expected, 'utf8');
            const providedBuf = Buffer.from(provided, 'utf8');
            const ok = (expectedBuf.length === providedBuf.length) &&
                crypto.timingSafeEqual(expectedBuf, providedBuf);
            if (!ok) {
                return res.status(401).json({ error: 'Invalid risk signature' });
            }
        }

        // ── 2) Branch ตามรูปแบบ payload ─────────────────────────────────────
        const isContinuousPayload =
            data &&
            Array.isArray(data.events) &&
            typeof data.username === 'string' &&
            typeof data.session_jti === 'string';

        if (isContinuousPayload) {
            // Risk Engine path ใหม่: รับ payload จาก SSO behavior proxy
            const { action, score, model_version } = computeRiskDecision(data);

            // บันทึกลง behavior_logs เพื่อ analytics / tuning model ภายหลัง
            const logQuery = `
                INSERT INTO behavior_logs (mouse, click, key, idle, features) 
                VALUES ($1, $2, $3, $4, $5)
            `;

            const logValue = {
                username:    data.username,
                session_jti: data.session_jti,
                ip:         data.ip,
                page:       data.page,
                ts:         data.ts,
                features:   data.features || {},
                action,
                score,
                model_version
            };

            const values = [
                {},            // mouse (legacy column)
                {},            // click
                {},            // key
                {},            // idle
                logValue       // เก็บ payload ใหม่ในคอลัมน์ features (JSONB)
            ];

            await client.query(logQuery, values);
            await client.end();

            return res.status(200).json({ action, score, model_version });
        }

        // ── 3) Legacy path: รองรับ payload เดิมจาก collector_behavior ──────
        const query = `
            INSERT INTO behavior_logs (mouse, click, key, idle, features) 
            VALUES ($1, $2, $3, $4, $5)
        `;
        
        const values = [
            data.mouse || {},  
            data.click || {},  
            data.key || {},    
            data.idle || {},   
            data.features || {}
        ];

        await client.query(query, values);
        await client.end();
        return res.status(200).json({ message: 'Success' });
    } catch (err) {
        if (client) await client.end().catch(() => {});
        return res.status(500).json({ error: 'Database Error', details: err.message });
    }
}