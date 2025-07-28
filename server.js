const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const axios = require('axios');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt'); // For password hashing
const rateLimit = require('express-rate-limit'); // For rate limiting
const crypto = require('crypto'); // For secure session ID generation

const app = express();
const PORT = 3000;

// Environment variable for bcrypt salt rounds (important for security)
// In production, set this via your hosting environment.
// For local development, you can set it directly or use a .env file.
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10');

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize DB with async/await for sequential table creation
const db = new sqlite3.Database('spammer.db', async (err) => {
    if (err) {
        console.error('DB open error:', err);
        process.exit(1);
    }

    try {
        await createTables();
        await setupDefaultUsers(); // Renamed and modified to be more robust
        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Error initializing database:', error);
        process.exit(1);
    }
});

// Helper function for database queries
const runDbQuery = (query, params = []) => new Promise((resolve, reject) => {
    db.run(query, params, function(err) { // Use function() for 'this' context
        if (err) reject(err);
        else resolve(this); // Resolve with 'this' to get lastID/changes
    });
});

const getDbQuery = (query, params = []) => new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
    });
});

const allDbQuery = (query, params = []) => new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
    });
});


// Function to create tables sequentially
async function createTables() {
    // Table for application users (login, permissions)
    await runDbQuery(`
        CREATE TABLE IF NOT EXISTS app_users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            can_add_persistent INTEGER NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0 -- New column for admin status
        )
    `);

    // Table for looked-up Xbox users (gamertag to XUID)
    await runDbQuery(`
        CREATE TABLE IF NOT EXISTS xbox_users (
            gamertag TEXT PRIMARY KEY,
            xuid TEXT NOT NULL
        )
    `);

    await runDbQuery(`
        CREATE TABLE IF NOT EXISTS api_keys (
            key TEXT PRIMARY KEY,
            persistent INTEGER NOT NULL DEFAULT 0
        )
    `);

    await runDbQuery(`
        CREATE TABLE IF NOT EXISTS sessions (
            sessionId TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            createdAt INTEGER DEFAULT (strftime('%s','now'))
        )
    `);

    // Audit Log Table
    await runDbQuery(`
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER DEFAULT (strftime('%s','now')),
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT
        )
    `);

    // NEW: Table for Known XUIDs (persistent list managed by admin)
    await runDbQuery(`
        CREATE TABLE IF NOT EXISTS known_xuids (
            xuid TEXT PRIMARY KEY,
            username TEXT NOT NULL
        )
    `);
}

// Function to set up/correct default users' permissions
async function setupDefaultUsers() {
    try {
        const hashedPasswordAdmin = await bcrypt.hash('admin', BCRYPT_SALT_ROUNDS);
        const hashedPasswordBrock = await bcrypt.hash('xbox', BCRYPT_SALT_ROUNDS);
        const hashedPasswordTest = await bcrypt.hash('test', BCRYPT_SALT_ROUNDS);

        // --- Admin User ---
        // Ensure admin user exists and has correct permissions
        await runDbQuery(
            'INSERT OR IGNORE INTO app_users (username, password_hash, can_add_persistent, is_admin) VALUES (?, ?, ?, ?)',
            ['admin', hashedPasswordAdmin, 1, 1] // Admin has persistent key add and is admin
        );
        await runDbQuery( // Ensure permissions are updated if user already existed
            'UPDATE app_users SET can_add_persistent = 1, is_admin = 1 WHERE username = ?',
            ['admin']
        );
        console.log('Admin user "admin" ensured with persistent key add permission and admin status.');


        // --- Brock User ---
        await runDbQuery(
            'INSERT OR IGNORE INTO app_users (username, password_hash, can_add_persistent, is_admin) VALUES (?, ?, ?, ?)',
            ['brock', hashedPasswordBrock, 0, 0] // Brock has no persistent key permission, not admin
        );
        await runDbQuery(
            'UPDATE app_users SET can_add_persistent = 0, is_admin = 0 WHERE username = ?',
            ['brock']
        );
        console.log('User "brock" ensured without persistent key add permission and not admin.');

        // --- Test User ---
        await runDbQuery(
            'INSERT OR IGNORE INTO app_users (username, password_hash, can_add_persistent, is_admin) VALUES (?, ?, ?, ?)',
            ['test', hashedPasswordTest, 0, 0] // Test has no persistent key permission, not admin
        );
        await runDbQuery(
            'UPDATE app_users SET can_add_persistent = 0, is_admin = 0 WHERE username = ?',
            ['test']
        );
        console.log('User "test" ensured without persistent key add permission and not admin.');

    } catch (error) {
        console.error('Error setting up default users:', error);
        throw error; // Re-throw to halt server startup if critical setup fails
    }
}

// Audit Log Function
async function logAuditAction(username, action, details) {
    try {
        await runDbQuery(
            'INSERT INTO audit_logs (username, action, details) VALUES (?, ?, ?)',
            [username, action, JSON.stringify(details)]
        );
    } catch (error) {
        console.error('Failed to write to audit log:', error);
    }
}


// --- Authentication Middleware ---
const authenticateSession = async (req, res, next) => {
    const sessionId = req.cookies.sessionId;
    if (!sessionId) {
        return res.status(401).json({ message: 'Unauthorized: No session provided' });
    }

    try {
        const session = await getDbQuery(
            'SELECT username FROM sessions WHERE sessionId = ? AND createdAt > ?',
            [sessionId, Math.floor(Date.now() / 1000) - 24 * 60 * 60] // Check for 24-hour expiry
        );

        if (!session) {
            return res.status(401).json({ message: 'Unauthorized: Invalid or expired session' });
        }

        // Fetch user permissions from the app_users table, including new is_admin
        const user = await getDbQuery('SELECT can_add_persistent, is_admin FROM app_users WHERE username = ?', [session.username]);
        if (!user) {
            console.error(`User ${session.username} found in session but not in app_users table.`);
            return res.status(500).json({ message: 'Server error: User data missing' });
        }

        req.username = session.username;
        req.canAddPersistent = user.can_add_persistent === 1; // Convert INTEGER to boolean
        req.isAdmin = user.is_admin === 1; // Admin status
        next();
    } catch (error) {
        console.error('Session authentication error:', error);
        res.status(500).json({ message: 'Server error during authentication' });
    }
};

// Admin-only middleware
const adminOnly = (req, res, next) => {
    if (!req.isAdmin) {
        return res.status(403).json({ message: 'Forbidden: Admin access required.' });
    }
    next();
};

// --- Rate Limiter for sending messages ---
const messageSendLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many message requests from this IP, please try again after a minute',
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// --- Routes ---

// Serve frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    try {
        // Query app_users table for login
        const user = await getDbQuery('SELECT password_hash, can_add_persistent, is_admin FROM app_users WHERE username = ?', [username]);

        if (user && await bcrypt.compare(password, user.password_hash)) {
            const sessionId = crypto.randomBytes(16).toString('hex'); // Secure session ID

            await runDbQuery(
                'INSERT INTO sessions (sessionId, username) VALUES (?, ?)',
                [sessionId, username]
            );

            res.cookie('sessionId', sessionId, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 24 * 60 * 60 * 1000 // 1 day
            });
            res.json({ success: true, username, canAddPersistent: user.can_add_persistent === 1, isAdmin: user.is_admin === 1 });
            await logAuditAction(username, 'Login', { status: 'Success' });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
            await logAuditAction(username, 'Login', { status: 'Failed', reason: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error during login' });
        await logAuditAction(username, 'Login', { status: 'Error', details: error.message });
    }
});

// Check session
app.get('/check-session', async (req, res) => {
    const sessionId = req.cookies.sessionId;
    if (!sessionId) return res.json({ loggedIn: false });

    try {
        const session = await getDbQuery(
            'SELECT username FROM sessions WHERE sessionId = ? AND createdAt > ?',
            [sessionId, Math.floor(Date.now() / 1000) - 24 * 60 * 60]
        );

        if (!session) return res.json({ loggedIn: false });

        // Query app_users table for user permissions, including new is_admin
        const user = await getDbQuery('SELECT can_add_persistent, is_admin FROM app_users WHERE username = ?', [session.username]);
        if (!user) {
            console.error(`User ${session.username} found in session but not in app_users table during check-session.`);
            return res.json({ loggedIn: false });
        }

        res.json({ loggedIn: true, username: session.username, canAddPersistent: user.can_add_persistent === 1, isAdmin: user.is_admin === 1 });
    } catch (error) {
        console.error('Check session error:', error);
        res.status(500).json({ message: 'Server error during session check' });
    }
});

// Logout
app.post('/logout', authenticateSession, async (req, res) => { // Added authenticateSession to get req.username
    const sessionId = req.cookies.sessionId;
    if (!sessionId) return res.json({ success: true });

    try {
        await runDbQuery('DELETE FROM sessions WHERE sessionId = ?', [sessionId]);
        res.clearCookie('sessionId');
        res.json({ success: true });
        await logAuditAction(req.username, 'Logout', { status: 'Success' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ success: false, message: 'Server error during logout' });
        await logAuditAction(req.username, 'Logout', { status: 'Error', details: error.message });
    }
});

// Get API keys
app.get('/api-keys', authenticateSession, async (req, res) => {
    try {
        const rows = await allDbQuery('SELECT key, persistent FROM api_keys');
        const persistentKeys = rows.filter(k => k.persistent === 1).map(k => k.key);
        const tempKeys = rows.filter(k => k.persistent === 0).map(k => k.key);
        res.json({ persistentKeys, tempKeys });
    } catch (error) {
        console.error('Failed to fetch API keys:', error);
        res.status(500).json({ message: 'Failed to fetch API keys' });
    }
});

// Add API key
app.post('/api-keys', authenticateSession, async (req, res) => {
    const { key, persistent } = req.body;

    if (!key) {
        await logAuditAction(req.username, 'Add API Key', { status: 'Failed', reason: 'Missing key' });
        return res.status(400).json({ message: 'API key required' });
    }
    // Basic API key format validation (assuming UUID-like)
    if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(key)) {
        console.warn(`Attempt to add invalid API key format: ${key}`);
        await logAuditAction(req.username, 'Add API Key', { status: 'Failed', reason: 'Invalid format', key: key.substring(0, 8) + '...' });
        return res.status(400).json({ message: 'Invalid API key format' });
    }

    if (persistent && !req.canAddPersistent) {
        await logAuditAction(req.username, 'Add API Key', { status: 'Failed', reason: 'Forbidden: Not allowed to add persistent keys', key: key.substring(0, 8) + '...' });
        return res.status(403).json({ message: 'Not allowed to add persistent keys' });
    }

    try {
        const result = await runDbQuery(
            'INSERT OR IGNORE INTO api_keys (key, persistent) VALUES (?, ?)',
            [key, persistent ? 1 : 0]
        );
        if (result.changes === 0) {
            await logAuditAction(req.username, 'Add API Key', { status: 'Failed', reason: 'Already exists', key: key.substring(0, 8) + '...' });
            return res.status(409).json({ success: false, message: 'API key already exists' });
        }
        res.json({ success: true });
        await logAuditAction(req.username, 'Add API Key', { status: 'Success', key: key.substring(0, 8) + '...', persistent });
    } catch (error) {
        console.error('Failed to add API key:', error);
        res.status(500).json({ message: 'Failed to add API key' });
        await logAuditAction(req.username, 'Add API Key', { status: 'Error', details: error.message, key: key.substring(0, 8) + '...' });
    }
});

// Delete API key
app.delete('/api-keys/:key', authenticateSession, async (req, res) => {
    const { key } = req.params;
    const persistent = req.query.persistent === 'true'; // Query param indicates if it's a persistent key

    if (persistent && !req.canAddPersistent) {
        await logAuditAction(req.username, 'Delete API Key', { status: 'Failed', reason: 'Forbidden: Not allowed to delete persistent keys', key: key.substring(0, 8) + '...' });
        return res.status(403).json({ message: 'Not allowed to delete persistent keys' });
    }

    try {
        const result = await runDbQuery('DELETE FROM api_keys WHERE key = ? AND persistent = ?', [key, persistent ? 1 : 0]);
        if (result.changes === 0) {
            await logAuditAction(req.username, 'Delete API Key', { status: 'Failed', reason: 'Not found or type mismatch', key: key.substring(0, 8) + '...' });
            return res.status(404).json({ success: false, message: 'API key not found or not matching type' });
        }
        res.json({ success: true });
        await logAuditAction(req.username, 'Delete API Key', { status: 'Success', key: key.substring(0, 8) + '...', persistent });
    } catch (error) {
        console.error('Failed to delete API key:', error);
        res.status(500).json({ message: 'Failed to delete API key' });
        await logAuditAction(req.username, 'Delete API Key', { status: 'Error', details: error.message, key: key.substring(0, 8) + '...' });
    }
});

// Lookup XUID by gamertag
app.post('/lookup-xuid', authenticateSession, async (req, res) => {
    const { username: gamertag, apiKey } = req.body; // 'username' here is actually the gamertag

    if (!gamertag || !apiKey) {
        await logAuditAction(req.username, 'XUID Lookup', { status: 'Failed', reason: 'Missing gamertag or API key', gamertag });
        return res.status(400).json({ message: 'Missing gamertag or API key' });
    }

    try {
        const apiKeyRow = await getDbQuery('SELECT key FROM api_keys WHERE key = ?', [apiKey]);
        if (!apiKeyRow) {
            await logAuditAction(req.username, 'XUID Lookup', { status: 'Failed', reason: 'Invalid API key provided', gamertag, apiKey: apiKey.substring(0, 8) + '...' });
            return res.status(400).json({ message: 'Invalid API key provided for lookup' });
        }

        console.log(`Looking up XUID for gamertag: ${gamertag} with API key: ${apiKey.substring(0, 8)}...`); // Log partial key
        const response = await axios.get(`https://xbl.io/api/v2/friends/search?gt=${encodeURIComponent(gamertag)}`, {
            headers: { 'X-Authorization': apiKey }
        });

        const profileUser = response.data.profileUsers?.[0];
        if (!profileUser) {
            await logAuditAction(req.username, 'XUID Lookup', { status: 'Failed', reason: 'User not found on Xbox Live', gamertag, apiKey: apiKey.substring(0, 8) + '...' });
            return res.status(404).json({ message: 'User not found on Xbox Live' });
        }

        const xuid = profileUser.id;
        console.log(`Found XUID: ${xuid} for gamertag: ${gamertag}`);

        // Insert or replace into the NEW xbox_users table
        // Ensure XUID is stored as TEXT for consistency and to match API's likely handling
        await runDbQuery('INSERT OR REPLACE INTO xbox_users (gamertag, xuid) VALUES (?, ?)', [gamertag, String(xuid)]);
        res.json({ xuid });
        await logAuditAction(req.username, 'XUID Lookup', { status: 'Success', gamertag, xuid, apiKey: apiKey.substring(0, 8) + '...' });
    } catch (error) {
        console.error('Lookup XUID error:', error.response?.data || error.message);
        const errorMessage = error.response?.data?.errorMessage || 'An unknown error occurred during XUID lookup.';
        res.status(500).json({ message: 'Error looking up XUID', details: errorMessage });
        await logAuditAction(req.username, 'XUID Lookup', { status: 'Error', details: errorMessage, gamertag, apiKey: apiKey.substring(0, 8) + '...' });
    }
});

// Send messages
app.post('/send-message', authenticateSession, messageSendLimiter, async (req, res) => {
    const { xuid, message, timeSpacing = 5, sendCount = 1, apiKeys } = req.body;

    if (!xuid || !message || !apiKeys || !Array.isArray(apiKeys) || apiKeys.length === 0) {
        await logAuditAction(req.username, 'Send Message', { status: 'Failed', reason: 'Missing required fields', xuid, messagePreview: message.substring(0, 30), sendCount });
        return res.status(400).json({ message: 'Missing required fields: XUID, message, and API keys' });
    }
    // Validate XUID: must be a numeric string (already done in frontend, but good to have backend validation)
    if (!/^\d+$/.test(xuid)) {
        await logAuditAction(req.username, 'Send Message', { status: 'Failed', reason: 'Invalid XUID format', xuid, messagePreview: message.substring(0, 30), sendCount });
        return res.status(400).json({ message: 'Invalid XUID format: must be a numeric string' });
    }
    // Validate sendCount and timeSpacing
    if (sendCount <= 0 || sendCount > 100) { // Limit max send count to prevent abuse
        await logAuditAction(req.username, 'Send Message', { status: 'Failed', reason: 'Invalid sendCount', xuid, messagePreview: message.substring(0, 30), sendCount });
        return res.status(400).json({ message: 'Invalid sendCount: must be between 1 and 100' });
    }
    if (timeSpacing < 0 || timeSpacing > 60) { // Limit max time spacing
        await logAuditAction(req.username, 'Send Message', { status: 'Failed', reason: 'Invalid timeSpacing', xuid, messagePreview: message.substring(0, 30), sendCount });
        return res.status(400).json({ message: 'Invalid timeSpacing: must be between 0 and 60 seconds' });
    }

    try {
        // Validate provided API keys against keys stored in DB
        const validApiKeysRows = await allDbQuery('SELECT key FROM api_keys WHERE key IN (' + apiKeys.map(() => '?').join(',') + ')', apiKeys);
        const validApiKeys = validApiKeysRows.map(row => row.key);

        if (validApiKeys.length !== apiKeys.length) {
            const invalidKeys = apiKeys.filter(key => !validApiKeys.includes(key));
            await logAuditAction(req.username, 'Send Message', { status: 'Failed', reason: 'Invalid API keys provided', xuid, messagePreview: message.substring(0, 30), invalidKeys: invalidKeys.map(k => k.substring(0, 8) + '...') });
            return res.status(400).json({ message: 'One or more provided API keys are invalid or not registered.', invalidKeys });
        }

        console.log(`Sending ${sendCount} message(s) to XUID: ${xuid} with message: "${message.substring(0, 30)}..." using ${validApiKeys.length} API key(s)`);
        
        const successMessages = [];
        const failedMessages = [];

        for (let i = 0; i < sendCount; i++) {
            for (const key of validApiKeys) {
                try {
                    await axios.post('https://xbl.io/api/v2/conversations', {
                        xuid: String(xuid), // Ensure XUID is a string
                        message
                    }, {
                        headers: { 'X-Authorization': key }
                    });
                    successMessages.push(`Message ${i+1} sent with key ${key.substring(0,8)}...`);
                } catch (error) {
                    console.error(`Message send attempt ${i+1} with key ${key.substring(0,8)}... failed:`, error.response?.data || error.message);
                    failedMessages.push({
                        attempt: i + 1,
                        apiKey: key.substring(0,8) + '...',
                        error: error.response?.data?.errorMessage || error.message
                    });
                }
                if (timeSpacing > 0) {
                    await new Promise(resolve => setTimeout(resolve, timeSpacing * 1000));
                }
            }
        }
        
        if (failedMessages.length === sendCount * validApiKeys.length && failedMessages.length > 0) { // All failed
            await logAuditAction(req.username, 'Send Message', { status: 'All Failed', xuid, messagePreview: message.substring(0, 30), sendCount, failures: failedMessages });
            return res.status(500).json({
                success: false,
                message: 'All message send attempts failed.',
                details: failedMessages
            });
        } else if (failedMessages.length > 0) { // Some failed
            await logAuditAction(req.username, 'Send Message', { status: 'Partial Success', xuid, messagePreview: message.substring(0, 30), sendCount, successful: successMessages.length, failures: failedMessages.length });
            return res.status(200).json({
                success: true,
                message: `Successfully sent ${successMessages.length} messages. Some attempts failed.`,
                successful: successMessages,
                failures: failedMessages
            });
        } else { // All successful
            console.log(`Successfully sent ${sendCount} message(s) to XUID: ${xuid}`);
            res.json({ success: true, message: `Successfully sent ${sendCount} message(s).` });
            await logAuditAction(req.username, 'Send Message', { status: 'Success', xuid, messagePreview: message.substring(0, 30), sendCount });
        }

    } catch (error) {
        console.error('Send message general error:', error.message);
        res.status(500).json({
            message: 'An unexpected error occurred during message sending.',
            details: error.message
        });
        await logAuditAction(req.username, 'Send Message', { status: 'Error', details: error.message, xuid, messagePreview: message.substring(0, 30), sendCount });
    }
});

// Add new user (ADMIN ONLY)
app.post('/add-user', authenticateSession, adminOnly, async (req, res) => { // Enforce adminOnly
    const { username, password, canAddPersistent = false } = req.body;

    if (!username || !password) {
        await logAuditAction(req.username, 'Add User', { status: 'Failed', reason: 'Missing username or password', targetUser: username });
        return res.status(400).json({ message: 'Username and password are required for new user.' });
    }

    try {
        // Check if user already exists
        const existingUser = await getDbQuery('SELECT username FROM app_users WHERE username = ?', [username]);
        if (existingUser) {
            await logAuditAction(req.username, 'Add User', { status: 'Failed', reason: 'User already exists', targetUser: username });
            return res.status(409).json({ message: 'User with that username already exists.' });
        }

        // Hash the new user's password
        const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

        // Insert new user into app_users table
        await runDbQuery(
            'INSERT INTO app_users (username, password_hash, can_add_persistent, is_admin) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, canAddPersistent ? 1 : 0, 0] // New users are not admins by default
        );

        res.json({ success: true, message: `User '${username}' added successfully.` });
        await logAuditAction(req.username, 'Add User', { status: 'Success', targetUser: username, canAddPersistent });

    } catch (error) {
        console.error('Error adding new user:', error);
        res.status(500).json({ message: 'Server error: Failed to add user.' });
        await logAuditAction(req.username, 'Add User', { status: 'Error', details: error.message, targetUser: username });
    }
});

// Get all app users (ADMIN ONLY)
app.get('/admin/users', authenticateSession, adminOnly, async (req, res) => {
    try {
        // Exclude password_hash for security
        const users = await allDbQuery('SELECT username, can_add_persistent, is_admin FROM app_users');
        res.json({ success: true, users });
    } catch (error) {
        console.error('Error fetching users for admin:', error);
        res.status(500).json({ success: false, message: 'Server error: Failed to fetch users.' });
    }
});

// NEW: Update User Permissions (ADMIN ONLY)
app.put('/admin/users/:username', authenticateSession, adminOnly, async (req, res) => {
    const targetUsername = req.params.username;
    const { canAddPersistent, isAdmin } = req.body; // These will be boolean values from frontend

    // Input validation
    if (typeof canAddPersistent === 'undefined' || typeof isAdmin === 'undefined') {
        await logAuditAction(req.username, 'Update User Permissions', { status: 'Failed', reason: 'Missing permission flags', targetUser: targetUsername });
        return res.status(400).json({ message: 'Both canAddPersistent and isAdmin flags are required.' });
    }

    try {
        const targetUser = await getDbQuery('SELECT can_add_persistent, is_admin FROM app_users WHERE username = ?', [targetUsername]);
        if (!targetUser) {
            await logAuditAction(req.username, 'Update User Permissions', { status: 'Failed', reason: 'User not found', targetUser: targetUsername });
            return res.status(404).json({ message: 'User not found.' });
        }

        // IMPORTANT SECURITY CHECKS:
        // 1. Prevent an admin from demoting another admin
        if (targetUser.is_admin === 1 && isAdmin === false && req.username !== targetUsername) {
            await logAuditAction(req.username, 'Update User Permissions', { status: 'Failed', reason: 'Cannot demote another admin', targetUser: targetUsername });
            return res.status(403).json({ message: 'Cannot demote another administrator.' });
        }
        
        // 2. Prevent an admin from revoking their own admin status or persistent key rights
        if (req.username === targetUsername) {
            const currentAdminUser = await getDbQuery('SELECT can_add_persistent, is_admin FROM app_users WHERE username = ?', [req.username]);
            if (currentAdminUser.is_admin === 1 && isAdmin === false) {
                await logAuditAction(req.username, 'Update User Permissions', { status: 'Failed', reason: 'Cannot revoke own admin status', targetUser: targetUsername });
                return res.status(403).json({ message: 'You cannot revoke your own administrator status.' });
            }
            if (currentAdminUser.can_add_persistent === 1 && canAddPersistent === false) {
                await logAuditAction(req.username, 'Update User Permissions', { status: 'Failed', reason: 'Cannot revoke own persistent key rights', targetUser: targetUsername });
                return res.status(403).json({ message: 'You cannot revoke your own persistent key adding rights.' });
            }
        }

        const result = await runDbQuery(
            'UPDATE app_users SET can_add_persistent = ?, is_admin = ? WHERE username = ?',
            [canAddPersistent ? 1 : 0, isAdmin ? 1 : 0, targetUsername]
        );

        if (result.changes === 0) {
            await logAuditAction(req.username, 'Update User Permissions', { status: 'Failed', reason: 'No changes or user not found', targetUser: targetUsername, canAddPersistent, isAdmin });
            return res.status(400).json({ success: false, message: 'No changes applied or user not found.' });
        }

        res.json({ success: true, message: `Permissions for user '${targetUsername}' updated successfully.` });
        await logAuditAction(req.username, 'Update User Permissions', { status: 'Success', targetUser: targetUsername, canAddPersistent, isAdmin });

    } catch (error) {
        console.error(`Error updating user permissions for ${targetUsername}:`, error);
        res.status(500).json({ success: false, message: `Server error: Failed to update permissions for user ${targetUsername}.` });
        await logAuditAction(req.username, 'Update User Permissions', { status: 'Error', details: error.message, targetUser: targetUsername, canAddPersistent, isAdmin });
    }
});


// Delete User (ADMIN ONLY)
app.delete('/admin/users/:username', authenticateSession, adminOnly, async (req, res) => {
    const targetUsername = req.params.username;

    // Prevent admin from deleting themselves
    if (targetUsername === req.username) {
        await logAuditAction(req.username, 'Delete User', { status: 'Failed', reason: 'Cannot delete self', targetUser: targetUsername });
        return res.status(403).json({ message: 'You cannot delete your own admin account.' });
    }

    try {
        // Check if the target user exists and is not an admin
        const targetUser = await getDbQuery('SELECT is_admin FROM app_users WHERE username = ?', [targetUsername]);
        if (!targetUser) {
            await logAuditAction(req.username, 'Delete User', { status: 'Failed', reason: 'User not found', targetUser: targetUsername });
            return res.status(404).json({ message: 'User not found.' });
        }
        if (targetUser.is_admin === 1) {
            await logAuditAction(req.username, 'Delete User', { status: 'Failed', reason: 'Cannot delete another admin', targetUser: targetUsername });
            return res.status(403).json({ message: 'Cannot delete another administrator account.' });
        }

        // Delete user and their sessions
        await runDbQuery('DELETE FROM app_users WHERE username = ?', [targetUsername]);
        await runDbQuery('DELETE FROM sessions WHERE username = ?', [targetUsername]); // Clear their sessions

        res.json({ success: true, message: `User '${targetUsername}' and their sessions deleted successfully.` });
        await logAuditAction(req.username, 'Delete User', { status: 'Success', targetUser: targetUsername });

    } catch (error) {
        console.error(`Error deleting user ${targetUsername}:`, error);
        res.status(500).json({ success: false, message: `Server error: Failed to delete user ${targetUsername}.` });
        await logAuditAction(req.username, 'Delete User', { status: 'Error', details: error.message, targetUser: targetUsername });
    }
});

// Get Audit Logs (ADMIN ONLY)
app.get('/admin/audit-logs', authenticateSession, adminOnly, async (req, res) => {
    const { limit = 50, offset = 0, username, action } = req.query; // Add query params for filtering/pagination

    let query = 'SELECT id, timestamp, username, action, details FROM audit_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?';
    let params = [parseInt(limit), parseInt(offset)];

    if (username) {
        query = 'SELECT id, timestamp, username, action, details FROM audit_logs WHERE username = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?';
        params = [username, parseInt(limit), parseInt(offset)];
    }
    if (action) {
        // This is a simplified example; for complex filtering, you might need dynamic query building
        // For 'action', it's usually an exact match.
        if (username) { // If both username and action are provided
            query = 'SELECT id, timestamp, username, action, details FROM audit_logs WHERE username = ? AND action = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?';
            params = [username, action, parseInt(limit), parseInt(offset)];
        } else {
            query = 'SELECT id, timestamp, username, action, details FROM audit_logs WHERE action = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?';
            params = [action, parseInt(limit), parseInt(offset)];
        }
    }

    try {
        const logs = await allDbQuery(query, params);
        // Parse the 'details' JSON string back into an object
        const parsedLogs = logs.map(log => ({
            ...log,
            details: log.details ? JSON.parse(log.details) : {}
        }));
        res.json({ success: true, logs: parsedLogs });
    } catch (error) {
        console.error('Error fetching audit logs:', error);
        res.status(500).json({ success: false, message: 'Server error: Failed to fetch audit logs.' });
    }
});


// Get Xbox Profile Data by XUID
app.post('/profile-data', authenticateSession, async (req, res) => {
    const { xuid, apiKey } = req.body;

    if (!xuid || !apiKey) {
        await logAuditAction(req.username, 'Xbox Profile Lookup', { status: 'Failed', reason: 'Missing XUID or API key', xuid });
        return res.status(400).json({ message: 'Missing XUID or API key' });
    }

    // Validate XUID format
    if (!/^\d{16}$/.test(xuid)) {
        await logAuditAction(req.username, 'Xbox Profile Lookup', { status: 'Failed', reason: 'Invalid XUID format', xuid });
        return res.status(400).json({ message: 'Invalid XUID format: must be a 16-digit number.' });
    }

    try {
        const apiKeyRow = await getDbQuery('SELECT key FROM api_keys WHERE key = ?', [apiKey]);
        if (!apiKeyRow) {
            await logAuditAction(req.username, 'Xbox Profile Lookup', { status: 'Failed', reason: 'Invalid API key provided', xuid, apiKey: apiKey.substring(0, 8) + '...' });
            return res.status(400).json({ message: 'Invalid API key provided for profile data lookup' });
        }

        console.log(`Fetching profile data for XUID: ${xuid} with API key: ${apiKey.substring(0, 8)}...`);
        const response = await axios.get(`https://xbl.io/api/v2/account/${encodeURIComponent(xuid)}`, {
            headers: { 'X-Authorization': apiKey }
        });

        // The xbl.io /account/{xuid} endpoint returns an object where
        const profileData = response.data; // Assuming response.data is the profile object
        if (!profileData || !profileData.profileUsers || profileData.profileUsers.length === 0) {
            await logAuditAction(req.username, 'Xbox Profile Lookup', { status: 'Failed', reason: 'Profile data not found on Xbox Live', xuid, apiKey: apiKey.substring(0, 8) + '...' });
            return res.status(404).json({ message: 'Xbox Live profile data not found for this XUID.' });
        }
        
        // Extract relevant profile information if needed, or send the whole thing
        res.json({ success: true, profile: profileData.profileUsers[0] });
        await logAuditAction(req.username, 'Xbox Profile Lookup', { status: 'Success', xuid, apiKey: apiKey.substring(0, 8) + '...' });

    } catch (error) {
        console.error('Xbox Profile Lookup error:', error.response?.data || error.message);
        const errorMessage = error.response?.data?.errorMessage || 'An unknown error occurred during Xbox profile lookup.';
        res.status(500).json({ message: 'Error fetching Xbox profile data', details: errorMessage });
        await logAuditAction(req.username, 'Xbox Profile Lookup', { status: 'Error', details: errorMessage, xuid, apiKey: apiKey.substring(0, 8) + '...' });
    }
});

// Get all known XUIDs (visible to all authenticated users)
app.get('/known-xuids', authenticateSession, async (req, res) => {
    try {
        const knownXuids = await allDbQuery('SELECT xuid, username FROM known_xuids ORDER BY username ASC');
        res.json({ success: true, knownXuids });
    } catch (error) {
        console.error('Error fetching known XUIDs:', error);
        res.status(500).json({ success: false, message: 'Server error: Failed to fetch known XUIDs.' });
    }
});

// Add a known XUID (ADMIN ONLY)
app.post('/known-xuids', authenticateSession, adminOnly, async (req, res) => {
    const { xuid, username } = req.body;

    if (!xuid || !username) {
        await logAuditAction(req.username, 'Add Known XUID', { status: 'Failed', reason: 'Missing XUID or username', xuid, username });
        return res.status(400).json({ message: 'XUID and username are required.' });
    }

    // Basic XUID validation (16-digit number)
    if (!/^\d{16}$/.test(xuid)) {
        await logAuditAction(req.username, 'Add Known XUID', { status: 'Failed', reason: 'Invalid XUID format', xuid, username });
        return res.status(400).json({ message: 'Invalid XUID format: must be a 16-digit number.' });
    }

    try {
        const result = await runDbQuery(
            'INSERT OR IGNORE INTO known_xuids (xuid, username) VALUES (?, ?)',
            [xuid, username]
        );
        if (result.changes === 0) {
            await logAuditAction(req.username, 'Add Known XUID', { status: 'Failed', reason: 'XUID already exists', xuid, username });
            return res.status(409).json({ success: false, message: 'XUID already exists in the known list.' });
        }
        res.json({ success: true, message: `Known XUID ${xuid} added successfully.` });
        await logAuditAction(req.username, 'Add Known XUID', { status: 'Success', xuid, username });
    } catch (error) {
        console.error('Error adding known XUID:', error);
        res.status(500).json({ success: false, message: 'Server error: Failed to add known XUID.' });
        await logAuditAction(req.username, 'Add Known XUID', { status: 'Error', details: error.message, xuid, username });
    }
});

// Delete a known XUID (ADMIN ONLY)
app.delete('/known-xuids/:xuid', authenticateSession, adminOnly, async (req, res) => {
    const { xuid } = req.params;

    try {
        const result = await runDbQuery('DELETE FROM known_xuids WHERE xuid = ?', [xuid]);
        if (result.changes === 0) {
            await logAuditAction(req.username, 'Delete Known XUID', { status: 'Failed', reason: 'XUID not found', xuid });
            return res.status(404).json({ success: false, message: 'Known XUID not found.' });
        }
        res.json({ success: true, message: `Known XUID ${xuid} deleted successfully.` });
        await logAuditAction(req.username, 'Delete Known XUID', { status: 'Success', xuid });
    } catch (error) {
        console.error('Error deleting known XUID:', error);
        res.status(500).json({ success: false, message: 'Server error: Failed to delete known XUID.' });
        await logAuditAction(req.username, 'Delete Known XUID', { status: 'Error', details: error.message, xuid });
    }
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});