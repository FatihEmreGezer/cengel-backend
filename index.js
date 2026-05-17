const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/cengel_db';
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_cengel_key';

// Connect to MongoDB
mongoose.connect(MONGO_URI, {
  serverSelectionTimeoutMS: 5000 // Keep trying to send operations for 5 seconds
})
  .then(() => console.log('MongoDB connected successfully.'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1); // Exit process on failure so Render automatically restarts it
  });

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

app.get('/', (req, res) => {
  const state = mongoose.connection.readyState;
  const states = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  };
  res.json({
    status: 'ok',
    dbState: states[state] || state
  });
});

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Kullanıcı adı ve şifre zorunludur.' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Bu kullanıcı adı zaten alınmış.' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = new User({
      username,
      password: hashedPassword
    });

    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, JWT_SECRET);

    res.status(201).json({ user: { id: newUser._id, username: newUser.username }, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Sunucu hatası.', details: err.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Kullanıcı adı ve şifre zorunludur.' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Kullanıcı bulunamadı.' });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Hatalı şifre.' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET);

    res.json({ user: { id: user._id, username: user.username }, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Sunucu hatası.', details: err.message });
  }
});

app.listen(port, () => {
  console.log(`Backend server is running on port ${port}`);
});
