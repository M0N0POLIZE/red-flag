require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Anthropic = require('@anthropic-ai/sdk');
const Stripe = require('stripe');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const JWT_SECRET = process.env.JWT_SECRET || 'redflag-secret-change-this';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      credits INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      user_id TEXT REFERENCES users(id),
      mode TEXT,
      score INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('Database ready');
}
initDB();

// Auth middleware
function authMiddleware(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired, please log in again' });
  }
}

app.use(cors({ origin: true, credentials: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

// Stripe webhook - raw body
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email = session.customer_email;
    const credits = parseInt(session.metadata.credits);
    await pool.query(
      'UPDATE users SET credits = credits + $1 WHERE email = $2',
      [credits, email]
    );
    console.log(`Added ${credits} credits to ${email}`);
  }
  res.json({ received: true });
});

app.use(express.json());

// REGISTER
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Account already exists with this email' });
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (id, email, password, credits) VALUES ($1, $2, $3, 0) RETURNING id, email, credits',
      [uuidv4(), email, hashed]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ user: { email: user.email, credits: user.credits } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'No account found with this email' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Incorrect password' });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ user: { email: user.email, credits: user.credits } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// GET current user
app.get('/api/me', authMiddleware, async (req, res) => {
  const result = await pool.query('SELECT email, credits FROM users WHERE id = $1', [req.user.id]);
  res.json({ user: result.rows[0] });
});

// BUY CREDITS
app.post('/api/buy-credits', authMiddleware, async (req, res) => {
  const { email } = req.user;
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      customer_email: email,
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: '10 Red Flag Scans',
            description: 'Detect red flags in texts, dating profiles, and situations',
          },
          unit_amount: parseInt(process.env.PRICE_AMOUNT),
        },
        quantity: 1,
      }],
      mode: 'payment',
      metadata: { credits: process.env.PRICE_CREDITS },
      success_url: `${req.headers.origin}/success.html`,
      cancel_url: `${req.headers.origin}`,
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ANALYZE
app.post('/api/analyze', authMiddleware, async (req, res) => {
  const { mode, input } = req.body;
  if (!mode || !input) return res.status(400).json({ error: 'Missing fields' });

  const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  const user = userResult.rows[0];
  if (!user || user.credits <= 0) {
    return res.status(402).json({ error: 'No credits remaining. Please buy more!' });
  }

  try {
    const message = await anthropic.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1000,
      messages: [{
        role: 'user',
        content: `You are a dramatic but insightful Red Flag Detector AI. Analyze the following ${mode} for red flags.\n\nInput: "${input}"\n\nRespond ONLY with valid JSON, no markdown, no backticks, no extra text. Use this exact format:\n{"score":<integer 0-100>,"flags":["flag one","flag two","flag three"],"summary":"2-3 sentence witty but honest verdict specific to the input"}\n\nScore: 0=zero flags, 100=run immediately. Be specific. If no real flags, give a low score honestly.`
      }]
    });

    const text = message.content.map(b => b.text || '').join('');
    const result = JSON.parse(text.replace(/```json|```/g, '').trim());

    await pool.query('UPDATE users SET credits = credits - 1 WHERE id = $1', [user.id]);
    await pool.query('INSERT INTO scans (id, user_id, mode, score) VALUES ($1, $2, $3, $4)', [uuidv4(), user.id, mode, result.score]);

    const updated = await pool.query('SELECT credits FROM users WHERE id = $1', [user.id]);
    res.json({ ...result, creditsRemaining: updated.rows[0].credits });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚩 Red Flag Detector running on port ${PORT}`));
