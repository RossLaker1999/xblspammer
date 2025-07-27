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
            can_add_persistent INTEGER NOT NULL DEFAULT 0
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
}

// Function to set up/correct default users' permissions
async function setupDefaultUsers() {
    try {
        const hashedPasswordAdmin = await bcrypt.hash('admin', BCRYPT_SALT_ROUNDS);
        const hashedPasswordBrock = await bcrypt.hash('xbox', BCRYPT_SALT_ROUNDS);
        const hashedPasswordTest = await bcrypt.hash('test', BCRYPT_SALT_ROUNDS);

        // --- Admin User ---
        // Insert admin if not exists (or replace if password changes but we want to keep current password)
        // For simplicity and self-correction, we'll INSERT OR IGNORE and then UPDATE permissions.
        await runDbQuery(
            'INSERT OR IGNORE INTO app_users (username, password_hash, can_add_persistent) VALUES (?, ?, ?)',
            ['admin', hashedPasswordAdmin, 1] // Attempt to insert with correct permission
        );
        // Always ensure admin has persistent key add permission
        await runDbQuery(
            'UPDATE app_users SET can_add_persistent = 1 WHERE username = ?',
            ['admin']
        );
        console.log('Admin user "admin" ensured with persistent key add permission.');


        // --- Brock User ---
        await runDbQuery(
            'INSERT OR IGNORE INTO app_users (username, password_hash, can_add_persistent) VALUES (?, ?, ?)',
            ['brock', hashedPasswordBrock, 0] // Attempt to insert with no persistent key permission
        );
        // Always ensure brock does NOT have persistent key add permission
        await runDbQuery(
            'UPDATE app_users SET can_add_persistent = 0 WHERE username = ?',
            ['brock']
        );
        console.log('User "brock" ensured without persistent key add permission.');

        // --- Test User ---
        await runDbQuery(
            'INSERT OR IGNORE INTO app_users (username, password_hash, can_add_persistent) VALUES (?, ?, ?)',
            ['test', hashedPasswordTest, 0] // Attempt to insert with no persistent key permission
        );
        // Always ensure test does NOT have persistent key add permission
        await runDbQuery(
            'UPDATE app_users SET can_add_persistent = 0 WHERE username = ?',
            ['test']
        );
        console.log('User "test" ensured without persistent key add permission.');

    } catch (error) {
        console.error('Error setting up default users:', error);
        throw error; // Re-throw to halt server startup if critical setup fails
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

        // Fetch user permissions from the app_users table
        const user = await getDbQuery('SELECT can_add_persistent FROM app_users WHERE username = ?', [session.username]);
        if (!user) {
             console.error(`User ${session.username} found in session but not in app_users table.`);
             return res.status(500).json({ message: 'Server error: User data missing' });
        }

        req.username = session.username;
        req.canAddPersistent = user.can_add_persistent === 1; // Convert INTEGER to boolean
        next();
    } catch (error) {
        console.error('Session authentication error:', error);
        res.status(500).json({ message: 'Server error during authentication' });
    }
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
        const user = await getDbQuery('SELECT password_hash, can_add_persistent FROM app_users WHERE username = ?', [username]);

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
            res.json({ success: true, username, canAddPersistent: user.can_add_persistent === 1 });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error during login' });
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

        // Query app_users table for user permissions
        const user = await getDbQuery('SELECT can_add_persistent FROM app_users WHERE username = ?', [session.username]);
        if (!user) {
            console.error(`User ${session.username} found in session but not in app_users table during check-session.`);
            return res.json({ loggedIn: false });
        }

        res.json({ loggedIn: true, username: session.username, canAddPersistent: user.can_add_persistent === 1 });
    } catch (error) {
        console.error('Check session error:', error);
        res.status(500).json({ message: 'Server error during session check' });
    }
});

// Logout
app.post('/logout', async (req, res) => {
    const sessionId = req.cookies.sessionId;
    if (!sessionId) return res.json({ success: true });

    try {
        await runDbQuery('DELETE FROM sessions WHERE sessionId = ?', [sessionId]);
        res.clearCookie('sessionId');
        res.json({ success: true });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ success: false, message: 'Server error during logout' });
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
        return res.status(400).json({ message: 'API key required' });
    }
    // Basic API key format validation (assuming UUID-like)
    if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(key)) {
        console.warn(`Attempt to add invalid API key format: ${key}`);
        return res.status(400).json({ message: 'Invalid API key format' });
    }

    if (persistent && !req.canAddPersistent) {
        return res.status(403).json({ message: 'Not allowed to add persistent keys' });
    }

    try {
        const result = await runDbQuery(
            'INSERT OR IGNORE INTO api_keys (key, persistent) VALUES (?, ?)',
            [key, persistent ? 1 : 0]
        );
        if (result.changes === 0) {
            return res.status(409).json({ success: false, message: 'API key already exists' });
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Failed to add API key:', error);
        res.status(500).json({ message: 'Failed to add API key' });
    }
});

// Delete API key
app.delete('/api-keys/:key', authenticateSession, async (req, res) => {
    const { key } = req.params;
    const persistent = req.query.persistent === 'true'; // Query param indicates if it's a persistent key

    if (persistent && !req.canAddPersistent) {
        return res.status(403).json({ message: 'Not allowed to delete persistent keys' });
    }

    try {
        const result = await runDbQuery('DELETE FROM api_keys WHERE key = ? AND persistent = ?', [key, persistent ? 1 : 0]);
        if (result.changes === 0) {
            return res.status(404).json({ success: false, message: 'API key not found or not matching type' });
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Failed to delete API key:', error);
        res.status(500).json({ message: 'Failed to delete API key' });
    }
});

// Lookup XUID by gamertag
app.post('/lookup-xuid', authenticateSession, async (req, res) => {
    const { username: gamertag, apiKey } = req.body; // 'username' here is actually the gamertag

    if (!gamertag || !apiKey) {
        return res.status(400).json({ message: 'Missing gamertag or API key' });
    }

    try {
        const apiKeyRow = await getDbQuery('SELECT key FROM api_keys WHERE key = ?', [apiKey]);
        if (!apiKeyRow) {
            return res.status(400).json({ message: 'Invalid API key provided for lookup' });
        }

        console.log(`Looking up XUID for gamertag: ${gamertag} with API key: ${apiKey.substring(0, 8)}...`); // Log partial key
        const response = await axios.get(`https://xbl.io/api/v2/friends/search?gt=${encodeURIComponent(gamertag)}`, {
            headers: { 'X-Authorization': apiKey }
        });

        const profileUser = response.data.profileUsers?.[0];
        if (!profileUser) {
            return res.status(404).json({ message: 'User not found on Xbox Live' });
        }

        const xuid = profileUser.id;
        console.log(`Found XUID: ${xuid} for gamertag: ${gamertag}`);

        // Insert or replace into the NEW xbox_users table
        // Ensure XUID is stored as TEXT for consistency and to match API's likely handling
        await runDbQuery('INSERT OR REPLACE INTO xbox_users (gamertag, xuid) VALUES (?, ?)', [gamertag, String(xuid)]);
        res.json({ xuid });
    } catch (error) {
        console.error('Lookup XUID error:', error.response?.data || error.message);
        const errorMessage = error.response?.data?.errorMessage || 'An unknown error occurred during XUID lookup.';
        res.status(500).json({ message: 'Error looking up XUID', details: errorMessage });
    }
});

// Send messages
app.post('/send-message', authenticateSession, messageSendLimiter, async (req, res) => {
    const { xuid, message, timeSpacing = 5, sendCount = 1, apiKeys } = req.body;

    if (!xuid || !message || !apiKeys || !Array.isArray(apiKeys) || apiKeys.length === 0) {
        return res.status(400).json({ message: 'Missing required fields: XUID, message, and API keys' });
    }
    // Validate XUID: must be a numeric string (already done in frontend, but good to have backend validation)
    if (!/^\d+$/.test(xuid)) {
        return res.status(400).json({ message: 'Invalid XUID format: must be a numeric string' });
    }
    // Validate sendCount and timeSpacing
    if (sendCount <= 0 || sendCount > 100) { // Limit max send count to prevent abuse
        return res.status(400).json({ message: 'Invalid sendCount: must be between 1 and 100' });
    }
    if (timeSpacing < 0 || timeSpacing > 60) { // Limit max time spacing
        return res.status(400).json({ message: 'Invalid timeSpacing: must be between 0 and 60 seconds' });
    }

    try {
        // Validate provided API keys against keys stored in DB
        const validApiKeysRows = await allDbQuery('SELECT key FROM api_keys WHERE key IN (' + apiKeys.map(() => '?').join(',') + ')', apiKeys);
        const validApiKeys = validApiKeysRows.map(row => row.key);

        if (validApiKeys.length !== apiKeys.length) {
            const invalidKeys = apiKeys.filter(key => !validApiKeys.includes(key));
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
            return res.status(500).json({
                success: false,
                message: 'All message send attempts failed.',
                details: failedMessages
            });
        } else if (failedMessages.length > 0) { // Some failed
            return res.status(200).json({
                success: true,
                message: `Successfully sent ${successMessages.length} messages. Some attempts failed.`,
                successful: successMessages,
                failures: failedMessages
            });
        } else { // All successful
            console.log(`Successfully sent ${sendCount} message(s) to XUID: ${xuid}`);
            res.json({ success: true, message: `Successfully sent ${sendCount} message(s).` });
        }

    } catch (error) {
        console.error('Send message general error:', error.message);
        res.status(500).json({
            message: 'An unexpected error occurred during message sending.',
            details: error.message
        });
    }
});

// Add new user (ADMIN ONLY)
app.post('/add-user', authenticateSession, async (req, res) => {
    // Check if the authenticated user is an admin
    if (!req.canAddPersistent) { // This flag indicates admin status in our current setup
        return res.status(403).json({ message: 'Forbidden: Only admin users can add new users.' });
    }

    const { username, password, canAddPersistent = false } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required for new user.' });
    }

    try {
        // Check if user already exists
        const existingUser = await getDbQuery('SELECT username FROM app_users WHERE username = ?', [username]);
        if (existingUser) {
            return res.status(409).json({ message: 'User with that username already exists.' });
        }

        // Hash the new user's password
        const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

        // Insert new user into app_users table
        await runDbQuery(
            'INSERT INTO app_users (username, password_hash, can_add_persistent) VALUES (?, ?, ?)',
            [username, hashedPassword, canAddPersistent ? 1 : 0]
        );

        res.json({ success: true, message: `User '${username}' added successfully.` });

    } catch (error) {
        console.error('Error adding new user:', error);
        res.status(500).json({ message: 'Server error: Failed to add user.' });
    }
});

// NEW: Get Xbox Profile Data by XUID
app.post('/profile-data', authenticateSession, async (req, res) => {
    const { xuid, apiKey } = req.body;

    if (!xuid || !apiKey) {
        return res.status(400).json({ message: 'Missing XUID or API key' });
    }

    // Validate XUID format
    if (!/^\d{16}$/.test(xuid)) {
        return res.status(400).json({ message: 'Invalid XUID format: must be a 16-digit number.' });
    }

    try {
        const apiKeyRow = await getDbQuery('SELECT key FROM api_keys WHERE key = ?', [apiKey]);
        if (!apiKeyRow) {
            return res.status(400).json({ message: 'Invalid API key provided for profile data lookup' });
        }

        console.log(`Fetching profile data for XUID: ${xuid} with API key: ${apiKey.substring(0, 8)}...`);
        const response = await axios.get(`https://xbl.io/api/v2/account/${encodeURIComponent(xuid)}`, {
            headers: { 'X-Authorization': apiKey }
        });

        // The xbl.io /account/{xuid} endpoint returns an object where keys are XUIDs
        // and values are the profile data. We need to extract the correct XUID's data.
        const profileData = response.data[xuid];

        if (!profileData) {
            return res.status(404).json({ message: 'Profile data not found for this XUID.' });
        }

        console.log(`Profile data fetched for XUID: ${xuid}`);
        res.json({ success: true, profile: profileData });

    } catch (error) {
        console.error('Error fetching profile data:', error.response?.data || error.message);
        const errorMessage = error.response?.data?.errorMessage || 'An unknown error occurred during profile data lookup.';
        res.status(500).json({ message: 'Error fetching profile data', details: errorMessage });
    }
});


// Start server
app.listen(PORT, () => {
    console.log(`Server listening at http://localhost:${PORT}`);
});