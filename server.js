// Load config
const config = require('./config.json');
const express = require('express');
const fetch = require('node-fetch');
const path = require('path');
const app = express();
const session = require('express-session');
const FileStore = require('session-file-store')(session);

// Public config for client
const publicConfig = {
    discord: {
        clientId: config.discord.clientId,
        redirectUri: config.discord.redirectUri,
        apiEndpoint: config.discord.apiEndpoint
    },
    website: config.website,
    roles: config.roles,
    resources: config.resources
};

// Private config for server-side only
const privateConfig = {
    discord: {
        clientSecret: config.discord.clientSecret,
        botToken: config.discord.botToken,
        guildId: config.discord.guildId
    }
};

// Database setup for news/press releases
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.sqlite');

// Create tables if they don't exist
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT,
        avatar TEXT,
        roles TEXT
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS news (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        content TEXT,
        image_url TEXT,
        author_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(author_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS team_structure (
        id INTEGER PRIMARY KEY,
        structure TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    store: new FileStore(),
    secret: config.session.secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 86400000 // 24 hours
    }
}));

// Middleware to check if user is authenticated
const isAuthenticated = async (req, res, next) => {
    // First check session authentication
    if (req.session.user) {
        next();
        return;
    }

    // If no session, check token authentication
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.split(' ')[1];
    
    try {
        const userResponse = await fetch(`https://discord.com/api/v10/users/@me`, {
            headers: {
                Authorization: `Bearer ${token}`,
            },
        });

        if (!userResponse.ok) {
            throw new Error('Failed to verify user');
        }

        const user = await userResponse.json();
        req.user = user;
        next();
    } catch (error) {
        console.error('Auth error:', error);
        res.status(401).json({ error: 'Authentication failed' });
    }
};

// Middleware to check if user has required role
const hasRole = (roleKey) => {
    return async (req, res, next) => {
        console.log('Checking role:', roleKey);
        console.log('User session:', req.session.user);
        
        // Get user ID either from session or token authentication
        const userId = req.session.user?.id || req.user?.id;
        if (!userId) {
            console.log('No user ID found');
            return res.status(403).json({ error: 'No user found' });
        }

        try {
            // Get user's roles from Discord server
            const memberResponse = await fetch(
                `https://discord.com/api/v10/guilds/${privateConfig.discord.guildId}/members/${userId}`,
                {
                    headers: {
                        Authorization: `Bot ${privateConfig.discord.botToken}`,
                    },
                }
            );

            if (!memberResponse.ok) {
                throw new Error('Failed to verify member roles');
            }

            const member = await memberResponse.json();
            const userRoles = member.roles || [];
            console.log('User roles:', userRoles);
            console.log('Config roles:', publicConfig.roles[roleKey]);

            // Check if user has any of the allowed roles
            const hasRequiredRole = userRoles.some(userRole => 
                publicConfig.roles[roleKey].includes(userRole)
            );

            console.log('Has required role:', hasRequiredRole);

            if (hasRequiredRole) {
                next();
            } else {
                res.status(403).json({ error: 'Forbidden - Missing required role' });
            }
        } catch (error) {
            console.error('Role check error:', error);
            res.status(500).json({ error: 'Failed to verify roles' });
        }
    };
};

// Serve config file (only public config)
app.get('/config.json', (req, res) => {
    console.log('Sending public config:', publicConfig);
    res.json(publicConfig);
});

// Auth status endpoint
app.get('/api/auth/status', (req, res) => {
    console.log('Auth status check - Session:', req.session);
    console.log('Auth status check - User:', req.session?.user);
    if (req.session && req.session.user) {
        res.json({
            authenticated: true,
            user: req.session.user
        });
    } else {
        res.json({
            authenticated: false
        });
    }
});

// Discord OAuth callback endpoint
app.post('/api/auth/discord', async (req, res) => {
    const { code } = req.body;
    console.log('Received auth code:', code);

    if (!code) {
        return res.status(400).json({ error: 'No code provided' });
    }

    try {
        // Exchange code for token
        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            body: new URLSearchParams({
                client_id: publicConfig.discord.clientId,
                client_secret: privateConfig.discord.clientSecret,
                code,
                grant_type: 'authorization_code',
                redirect_uri: publicConfig.discord.redirectUri,
                scope: 'identify guilds.members.read',
            }),
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });

        const tokens = await tokenResponse.json();
        console.log('Token response:', tokens);

        if (tokens.error) {
            throw new Error(tokens.error);
        }

        // Get user info
        const userResponse = await fetch(`https://discord.com/api/v10/users/@me`, {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`,
            },
        });

        const user = await userResponse.json();
        console.log('User info:', user);

        // Get user's roles from your Discord server
        const memberResponse = await fetch(
            `https://discord.com/api/v10/guilds/${privateConfig.discord.guildId}/members/${user.id}`,
            {
                headers: {
                    Authorization: `Bot ${privateConfig.discord.botToken}`,
                },
            }
        );

        const member = await memberResponse.json();
        console.log('Member info:', member);
        
        if (member.error) {
            console.error('Error fetching member:', member.error);
            throw new Error(`Failed to fetch member info: ${member.error}`);
        }

        if (!member.roles) {
            console.log('No roles found in member object');
            throw new Error('No roles found in member response');
        }

        const roles = member.roles;
        console.log('User roles:', roles);

        // Store user in database
        db.run(
            'INSERT OR REPLACE INTO users (id, username, avatar, roles) VALUES (?, ?, ?, ?)',
            [user.id, user.username, user.avatar, JSON.stringify(roles)]
        );

        // Store user in session
        req.session.user = {
            id: user.id,
            username: user.username,
            avatar: user.avatar,
            roles: roles
        };

        console.log('Stored session user:', req.session.user);

        res.json({
            token: tokens.access_token,
            user: req.session.user
        });
    } catch (error) {
        console.error('Discord auth error:', error);
        res.status(500).json({ error: `Authentication failed: ${error.message}` });
    }
});

// News endpoints
app.get('/api/news', async (req, res) => {
    db.all(`
        SELECT news.*, users.username as author_username, users.avatar as author_avatar, users.id as author_id
        FROM news 
        LEFT JOIN users ON news.author_id = users.id 
        ORDER BY news.created_at DESC
    `, [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: 'Failed to fetch news' });
            return;
        }
        res.json(rows);
    });
});

app.post('/api/news', isAuthenticated, hasRole('NEWS_MANAGER'), async (req, res) => {
    const { title, content, image_url } = req.body;
    
    if (!title || !content) {
        return res.status(400).json({ error: 'Title and content are required' });
    }

    db.run(
        'INSERT INTO news (title, content, image_url, author_id) VALUES (?, ?, ?, ?)',
        [title, content, image_url, req.session.user.id],
        function(err) {
            if (err) {
                res.status(500).json({ error: 'Failed to create news post' });
                return;
            }
            res.json({ id: this.lastID });
        }
    );
});

app.put('/api/news/:id', isAuthenticated, hasRole('NEWS_MANAGER'), async (req, res) => {
    const { title, content, image_url } = req.body;
    const id = req.params.id;
    
    if (!title || !content) {
        return res.status(400).json({ error: 'Title and content are required' });
    }

    db.run(
        'UPDATE news SET title = ?, content = ?, image_url = ? WHERE id = ?',
        [title, content, image_url, id],
        function(err) {
            if (err) {
                res.status(500).json({ error: 'Failed to update news post' });
                return;
            }
            res.json({ success: true });
        }
    );
});

app.delete('/api/news/:id', isAuthenticated, hasRole('NEWS_MANAGER'), async (req, res) => {
    db.run('DELETE FROM news WHERE id = ?', [req.params.id], (err) => {
        if (err) {
            res.status(500).json({ error: 'Failed to delete news post' });
            return;
        }
        res.json({ success: true });
    });
});

// Get team structure
app.get('/api/team/structure', async (req, res) => {
    db.get('SELECT structure FROM team_structure WHERE id = 1', [], (err, row) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to fetch team structure' });
        }
        res.json(row ? JSON.parse(row.structure) : { categories: [] });
    });
});

// Team structure endpoint
app.post('/api/team/structure', isAuthenticated, hasRole('ADMIN'), async (req, res) => {
    try {
        // Save team structure to database
        const structure = req.body;
        
        // Validate structure format
        if (!structure || !structure.categories || !Array.isArray(structure.categories)) {
            return res.status(400).json({ error: 'Invalid team structure format' });
        }

        // Save to database
        db.run(
            'INSERT OR REPLACE INTO team_structure (id, structure) VALUES (?, ?)',
            [1, JSON.stringify(structure)],
            (err) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ error: 'Failed to save team structure' });
                }
                res.json({ message: 'Team structure saved successfully' });
            }
        );
    } catch (error) {
        console.error('Error saving team structure:', error);
        res.status(500).json({ error: error.message });
    }
});

// Serve logo file
app.get('/CSPLogo.png', (req, res) => {
    res.sendFile(path.join(__dirname, 'CSPLogo.png'));
});

// Serve background image
app.get('/CSPPicture.png', (req, res) => {
    res.sendFile(path.join(__dirname, 'CSPPicture.png'));
});

// Serve index.html for all routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
const PORT = config.server.port || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 