const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-umessage-key';
const MONGO_URI = process.env.MONGO_URI;

// Connect to MongoDB
mongoose.connect(MONGO_URI)
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB connection error:', err));

// --- SCHEMAS ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    friendCode: { type: String, required: true, unique: true },
    friends: [String]
});
const User = mongoose.model('User', userSchema);

const postSchema = new mongoose.Schema({
    authorId: String,
    authorName: String,
    content: String,
    timestamp: { type: Date, default: Date.now },
    likes: { type: Number, default: 0 }
});
const Post = mongoose.model('Post', postSchema);

const messageSchema = new mongoose.Schema({
    from: String,
    to: String,
    content: String,
    timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// Generate unique Friend Code
const generateFriendCode = () => '#UM-' + Math.random().toString(36).substring(2, 8).toUpperCase();

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- ROUTES ---

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (await User.findOne({ username })) return res.status(400).json({ error: 'Username exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username,
            password: hashedPassword,
            friendCode: generateFriendCode(),
            friends: []
        });
        await newUser.save();

        const token = jwt.sign({ id: newUser._id, username: newUser.username, friendCode: newUser.friendCode }, JWT_SECRET);
        res.json({ token, user: { id: newUser._id, username: newUser.username, friendCode: newUser.friendCode } });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id, username: user.username, friendCode: user.friendCode }, JWT_SECRET);
        res.json({ token, user: { id: user._id, username: user.username, friendCode: user.friendCode } });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Add Friend
app.post('/api/friends/add', authenticateToken, async (req, res) => {
    try {
        const { friendCode } = req.body;
        const friend = await User.findOne({ friendCode });
        if (!friend) return res.status(404).json({ error: 'Friend code not found' });

        const user = await User.findById(req.user.id);
        if (user.friends.includes(friendCode)) return res.status(400).json({ error: 'Already friends' });

        user.friends.push(friendCode);
        await user.save();
        res.json({ message: 'Friend added!', friend: { username: friend.username, friendCode } });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add friend' });
    }
});

// Create Post
app.post('/api/posts', authenticateToken, async (req, res) => {
    const post = new Post({ authorId: req.user.id, authorName: req.user.username, content: req.body.content });
    await post.save();
    res.json(post);
});

// Get Feed
app.get('/api/posts', authenticateToken, async (req, res) => {
    const posts = await Post.find().sort({ timestamp: -1 }).limit(50);
    res.json(posts);
});

// Send Message
app.post('/api/messages', authenticateToken, async (req, res) => {
    const msg = new Message({ from: req.user.friendCode, to: req.body.toFriendCode, content: req.body.content });
    await msg.save();
    res.json(msg);
});

// Get Messages
app.get('/api/messages/:friendCode', authenticateToken, async (req, res) => {
    const messages = await Message.find({
        $or: [
            { from: req.user.friendCode, to: req.params.friendCode },
            { from: req.params.friendCode, to: req.user.friendCode }
        ]
    }).sort({ timestamp: 1 });
    res.json(messages);
});

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));