// server.js (Backend - Node.js with Express)
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = "your_secret_key"; // Change this to a strong secret key

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, )));
app.use(session({ secret: SECRET_KEY, resave: false, saveUninitialized: true }));

const USERS_FILE = "users.json";
const DATA_FILE = "data.json";

// Load data
const loadData = (file) => fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : { users: [], posts: [] };

// Save data
const saveData = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

// Register a new user
app.post("/register", async (req, res) => {
    const { email, password } = req.body;
    const data = loadData(USERS_FILE);

    if (data.users.find(user => user.email === email)) {
        return res.status(400).json({ error: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: Date.now(), email, password: hashedPassword };
    data.users.push(newUser);
    saveData(USERS_FILE, data);

    res.json({ message: "User registered successfully" });
});

// User login
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const data = loadData(USERS_FILE);
    const user = data.users.find(u => u.email === email);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token, userId: user.id, email: user.email });
});

// Middleware to check authentication
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Invalid token" });
        req.user = decoded;
        next();
    });
};

// Get all posts
app.get("/posts", (req, res) => {
    const data = loadData(DATA_FILE);
    res.json(data.posts);
});

// Create a new post (Only Authenticated Users)
app.post("/post", authenticate, (req, res) => {
    const data = loadData(DATA_FILE);
    const newPost = { id: Date.now(), text: req.body.text, user: req.user.email, comments: [], reposts: 0 };
    data.posts.push(newPost);
    saveData(DATA_FILE, data);
    res.json(newPost);
});

// Add a comment (Only Authenticated Users)
app.post("/comment", authenticate, (req, res) => {
    const data = loadData(DATA_FILE);
    const post = data.posts.find((p) => p.id === req.body.postId);
    if (post) {
        post.comments.push({ id: Date.now(), text: req.body.text, user: req.user.email });
        saveData(DATA_FILE, data);
        res.json(post);
    } else {
        res.status(404).json({ error: "Post not found" });
    }
});

// Repost a post (Only Authenticated Users)
app.post("/repost", authenticate, (req, res) => {
    const data = loadData(DATA_FILE);
    const post = data.posts.find((p) => p.id === req.body.postId);
    if (post) {
        post.reposts++;
        saveData(DATA_FILE, data);
        res.json(post);
    } else {
        res.status(404).json({ error: "Post not found" });
    }
});

// Serve index.html at root
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "COMMUN/channel/index.html"));
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
