const express = require('express');
const cors = require('cors');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-umessage-key';
const DB_FILE = path.join(__dirname, 'database.json');

// Initialize database if it doesn't exist
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], posts: [], messages: [] }));
}

// Helper to read/write DB
const readDB = () => JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
const writeDB = (data) => fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));

// Generate unique Friend Code
const generateFriendCode = () => {
    return '#UM-' + Math.random().toString(36).substring(2, 8).toUpperCase();
};

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- ROUTES ---

// 1. Register
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    const db = readDB();
    
    if (db.users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: Date.now().toString(),
        username,
        password: hashedPassword,
        friendCode: generateFriendCode(),
        friends: [] // Stores friend codes
    };

    db.users.push(newUser);
    writeDB(db);

    const token = jwt.sign({ id: newUser.id, username: newUser.username, friendCode: newUser.friendCode }, JWT_SECRET);
    res.json({ token, user: { id: newUser.id, username: newUser.username, friendCode: newUser.friendCode } });
});

// 2. Login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const db = readDB();
    
    const user = db.users.find(u => u.username === username);
    if (!user) return res.status(400).json({ error: 'User not found' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user.id, username: user.username, friendCode: user.friendCode }, JWT_SECRET);
    res.json({ token, user: { id: user.id, username: user.username, friendCode: user.friendCode } });
});

// 3. Add Friend
app.post('/api/friends/add', authenticateToken, (req, res) => {
    const { friendCode } = req.body;
    const db = readDB();
    
    const userIndex = db.users.findIndex(u => u.id === req.user.id);
    const friend = db.users.find(u => u.friendCode === friendCode);

    if (!friend) return res.status(404).json({ error: 'Friend code not found' });
    if (db.users[userIndex].friends.includes(friendCode)) return res.status(400).json({ error: 'Already friends' });

    db.users[userIndex].friends.push(friendCode);
    writeDB(db);
    res.json({ message: 'Friend added!', friend: { username: friend.username, friendCode } });
});

// 4. Create Post
app.post('/api/posts', authenticateToken, (req, res) => {
    const { content } = req.body;
    const db = readDB();
    
    const newPost = {
        id: Date.now().toString(),
        authorId: req.user.id,
        authorName: req.user.username,
        content,
        timestamp: new Date().toISOString(),
        likes: 0
    };

    db.posts.unshift(newPost);
    writeDB(db);
    res.json(newPost);
});

// 5. Get Feed
app.get('/api/posts', authenticateToken, (req, res) => {
    const db = readDB();
    res.json(db.posts);
});

// 6. Send Direct Message
app.post('/api/messages', authenticateToken, (req, res) => {
    const { toFriendCode, content } = req.body;
    const db = readDB();
    
    const newMessage = {
        id: Date.now().toString(),
        from: req.user.friendCode,
        to: toFriendCode,
        content,
        timestamp: new Date().toISOString()
    };

    db.messages.push(newMessage);
    writeDB(db);
    res.json(newMessage);
});

// 7. Get Messages
app.get('/api/messages/:friendCode', authenticateToken, (req, res) => {
    const db = readDB();
    const chatHistory = db.messages.filter(m => 
        (m.from === req.user.friendCode && m.to === req.params.friendCode) ||
        (m.from === req.params.friendCode && m.to === req.user.friendCode)
    );
    res.json(chatHistory);
});

app.listen(PORT, () => {
    console.log(`uMessage backend running on port ${PORT}`);
});