// server.js

const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const User = require('./models/user');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// User registration
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;

  const userExists = await User.findOne({ username });
  if (userExists) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const user = new User({ username, password, role });
  await user.save();
  res.status(201).json({ message: 'User registered successfully' });
});

// User login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user || !(await user.matchPassword(password))) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Middleware to protect routes based on roles
const protect = (roles) => {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(403).json({ message: 'No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) return res.status(403).json({ message: 'Failed to authenticate token' });
      if (!roles.includes(decoded.role)) {
        return res.status(403).json({ message: 'Access denied' });
      }
      req.user = decoded; // Attach the decoded user info to the request
      next();
    });
  };
};

// Protected route example
app.get('/api/admin', protect(['admin']), (req, res) => {
  res.json({ message: 'Welcome Admin!' });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
