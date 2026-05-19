require('dotenv').config();
const http    = require('http');
const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const rateLimit = require('express-rate-limit');

const apiRoutes = require('./routes/api');
const { router: authRoutes, requireAuth } = require('./routes/auth');
const { setupWebSocket } = require('./websocket/wsServer');

const app  = express();
const PORT = process.env.PORT || 4000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5173', 'http://localhost:3000'],
  credentials: true,
}));
app.use(express.json({ limit: '1mb' }));
app.set('trust proxy', 1);

// Public routes
app.get('/health', (req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));
app.use('/api/auth', authRoutes);

// Protected routes (require JWT)
app.use('/api', rateLimit({ windowMs: 60000, max: 300 }), requireAuth, apiRoutes);

app.use((req, res) => res.status(404).json({ error: `${req.method} ${req.path} not found` }));
app.use((err, req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

const server = http.createServer(app);
setupWebSocket(server);

server.listen(PORT, () => {
  console.log('\n\x1b[36m🔐 SecureCloud Enterprise Backend v3.0\x1b[0m');
  console.log(`   HTTP API  → http://localhost:${PORT}/api`);
  console.log(`   WebSocket → ws://localhost:${PORT}/ws`);
  console.log(`\n   \x1b[33mDemo accounts:\x1b[0m`);
  console.log(`   admin  / AdminSecure123! (full access)`);
  console.log(`   viewer / Viewer123!      (read only)\n`);
});
