const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'ZENOX_ULTRA_SECURE_KEY';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin@Zenox2026';

// ============ DATA STORE ============
const DATA_FILE = path.join(__dirname, 'data', 'users.json');

function readData() {
    try {
        const data = fs.readFileSync(DATA_FILE, 'utf8');
        return JSON.parse(data);
    } catch {
        return { users: [], accessKeys: [] };
    }
}

function writeData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// ============ MIDDLEWARE ============
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"]
        }
    }
}));

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// Rate Limiting
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests' }
}));

// ============ AUTH MIDDLEWARE ============
function verifyToken(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
}

function verifyAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin required' });
    }
    next();
}

// ============ API ROUTES ============

// ---------- LOGIN ----------
app.post('/api/auth/login', async (req, res) => {
    try {
        const { deviceId, key } = req.body;
        if (!deviceId || !key) {
            return res.status(400).json({ error: 'MISSING_FIELDS' });
        }

        const data = readData();
        let user = data.users.find(u => u.deviceId === deviceId);

        if (user) {
            if (user.lockUntil && user.lockUntil > Date.now()) {
                return res.status(403).json({ error: 'TOO_MANY_ATTEMPTS' });
            }
            const isValid = await bcrypt.compare(key, user.passwordHash);
            if (!isValid) {
                user.loginAttempts = (user.loginAttempts || 0) + 1;
                if (user.loginAttempts >= 5) {
                    user.lockUntil = Date.now() + 15 * 60 * 1000;
                }
                writeData(data);
                return res.status(401).json({ error: 'INVALID_KEY' });
            }
            user.loginAttempts = 0;
            user.lockUntil = null;
            user.lastLogin = new Date().toISOString();
            writeData(data);

            const token = jwt.sign(
                { id: user.id, deviceId: user.deviceId, role: user.role },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
            return res.json({ token, deviceId: user.deviceId, role: user.role });
        }

        // New device - check access key
        const accessKey = data.accessKeys.find(k => k.key === key && k.isActive);
        if (!accessKey) return res.status(401).json({ error: 'INVALID_KEY' });
        if (accessKey.expiresAt && new Date(accessKey.expiresAt) < new Date()) {
            return res.status(401).json({ error: 'KEY_EXPIRED' });
        }
        if (accessKey.maxUsage && accessKey.usageCount >= accessKey.maxUsage) {
            return res.status(401).json({ error: 'KEY_USAGE_LIMIT_REACHED' });
        }

        const passwordHash = await bcrypt.hash(key, 12);
        const newUser = {
            id: uuidv4(),
            deviceId: deviceId,
            passwordHash: passwordHash,
            role: 'user',
            createdAt: new Date().toISOString(),
            lastLogin: new Date().toISOString(),
            loginAttempts: 0,
            lockUntil: null,
            isActive: true
        };
        data.users.push(newUser);
        accessKey.usageCount = (accessKey.usageCount || 0) + 1;
        accessKey.assignedTo = deviceId;
        writeData(data);

        const token = jwt.sign(
            { id: newUser.id, deviceId: newUser.deviceId, role: newUser.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        return res.json({ token, deviceId: newUser.deviceId, role: newUser.role });

    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ error: 'INTERNAL_ERROR' });
    }
});

// ---------- VERIFY ----------
app.get('/api/auth/verify', verifyToken, (req, res) => {
    res.json({ valid: true, deviceId: req.user.deviceId, role: req.user.role });
});

// ---------- ADMIN LOGIN ----------
app.post('/api/admin/login', async (req, res) => {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });
    if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: 'Invalid admin password' });
    }
    const token = jwt.sign(
        { id: 'admin', role: 'admin', deviceId: 'ADMIN' },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
    res.json({ token, role: 'admin' });
});

// ---------- ADMIN: GET USERS ----------
app.get('/api/admin/users', verifyToken, verifyAdmin, (req, res) => {
    const data = readData();
    const users = data.users.map(u => ({
        id: u.id,
        deviceId: u.deviceId,
        role: u.role,
        createdAt: u.createdAt,
        lastLogin: u.lastLogin,
        isActive: u.isActive,
        loginAttempts: u.loginAttempts,
        lockUntil: u.lockUntil
    }));
    res.json({ users });
});

// ---------- ADMIN: GET KEYS ----------
app.get('/api/admin/keys', verifyToken, verifyAdmin, (req, res) => {
    const data = readData();
    res.json({ keys: data.accessKeys });
});

// ---------- ADMIN: GENERATE KEY ----------
app.post('/api/admin/keys', verifyToken, verifyAdmin, (req, res) => {
    const { maxUsage, expiresInDays } = req.body;
    const key = `ZENOX-V1-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
    const data = readData();
    const newKey = {
        key: key,
        deviceId: key,
        createdAt: new Date().toISOString(),
        expiresAt: expiresInDays ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000).toISOString() : null,
        isActive: true,
        usageCount: 0,
        maxUsage: maxUsage || 1,
        assignedTo: null
    };
    data.accessKeys.push(newKey);
    writeData(data);
    res.json({ key: newKey });
});

// ---------- ADMIN: REVOKE KEY ----------
app.delete('/api/admin/keys/:key', verifyToken, verifyAdmin, (req, res) => {
    const { key } = req.params;
    const data = readData();
    const index = data.accessKeys.findIndex(k => k.key === key);
    if (index === -1) return res.status(404).json({ error: 'Key not found' });
    data.accessKeys[index].isActive = false;
    writeData(data);
    res.json({ success: true });
});

// ---------- ADMIN: TOGGLE USER ----------
app.post('/api/admin/users/:id/toggle', verifyToken, verifyAdmin, (req, res) => {
    const { id } = req.params;
    const data = readData();
    const user = data.users.find(u => u.id === id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.isActive = !user.isActive;
    writeData(data);
    res.json({ success: true, isActive: user.isActive });
});

// ---------- ADMIN: DELETE USER ----------
app.delete('/api/admin/users/:id', verifyToken, verifyAdmin, (req, res) => {
    const { id } = req.params;
    const data = readData();
    data.users = data.users.filter(u => u.id !== id);
    writeData(data);
    res.json({ success: true });
});

// ---------- HEALTH ----------
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🔐 BOSS ZENOX Server running on port ${PORT}`);
});