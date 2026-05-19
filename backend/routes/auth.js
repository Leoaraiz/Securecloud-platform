const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'securecloud-dev-secret-change-in-production';
const JWT_EXPIRES = '8h';

// In-memory users (production would use a database)
const USERS = [
  {
    id: 'u1',
    username: 'admin',
    displayName: 'Admin User',
    // AdminSecure123!
    passwordHash: bcrypt.hashSync('AdminSecure123!', 10),
    role: 'admin',
    avatar: 'A',
  },
  {
    id: 'u2',
    username: 'viewer',
    displayName: 'Security Viewer',
    // Viewer123!
    passwordHash: bcrypt.hashSync('Viewer123!', 10),
    role: 'viewer',
    avatar: 'V',
  },
];

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
});

// POST /api/auth/login
router.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const user = USERS.find(u => u.username === username.toLowerCase().trim());
  if (!user) {
    // Constant-time to prevent enumeration
    await bcrypt.compare(password, '$2a$10$invalid_hash_for_timing_safety');
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, displayName: user.displayName },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );

  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role, displayName: user.displayName, avatar: user.avatar },
  });
});

// POST /api/auth/verify
router.post('/verify', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = USERS.find(u => u.id === decoded.id);
    if (!user) return res.status(401).json({ error: 'User not found' });
    res.json({ valid: true, user: { id: user.id, username: user.username, role: user.role, displayName: user.displayName, avatar: user.avatar } });
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});

// Middleware to protect API routes
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { router, requireAuth };
