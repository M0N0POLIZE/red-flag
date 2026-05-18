require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Anthropic = require('@anthropic-ai/sdk');
const Stripe = require('stripe');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// Database setup
const db = new Database('redflag.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    credits INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    mode TEXT,
    score INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Middleware
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Stripe webhooks need raw body - must be before express.json()
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

    // Add credits to user, create if doesn't exist
    const existing = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (existing) {
      db.prepare('UPDATE users SET credits = credits + ? WHERE email = ?').run(credits, email);
    } else {
      db.prepare('INSERT INTO users (id, email, credits) VALUES (?, ?, ?)').run(uuidv4(), email, credits);
    }
    console.log(`Added ${credits} credits to ${email}`);
  }

  res.json({ received: true });
});

app.use(express.json());

// Create Stripe checkout session
app.post('/api/buy-credits', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

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
      success_url: `${req.headers.origin}/success.html?email=${encodeURIComponent(email)}`,
      cancel_url: `${req.headers.origin}`,
    });

    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Check credits
app.post('/api/credits', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const user = db.prepare('SELECT credits FROM users WHERE email = ?').get(email);
  res.json({ credits: user ? user.credits : 0 });
});

// Analyze endpoint - the actual AI call
app.post('/api/analyze', async (req, res) => {
  const { email, mode, input } = req.body;
  if (!email || !mode || !input) return res.status(400).json({ error: 'Missing fields' });

  // Check credits
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || user.credits <= 0) {
    return res.status(402).json({ error: 'No credits remaining. Please buy more!' });
  }

  try {
    const message = await anthropic.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1000,
      messages: [{
        role: 'user',
        content: `You are a dramatic but insightful Red Flag Detector AI. Analyze the following ${mode} for red flags.

Input: "${input}"

Respond ONLY with valid JSON, no markdown, no backticks, no extra text. Use this exact format:
{"score":<integer 0-100>,"flags":["flag one","flag two","flag three"],"summary":"2-3 sentence witty but honest verdict specific to the input"}

Score: 0=zero flags, 100=run immediately. Be specific. If no real flags, give a low score honestly.`
      }]
    });

    const text = message.content.map(b => b.text || '').join('');
    const result = JSON.parse(text.replace(/```json|```/g, '').trim());

    // Deduct credit
    db.prepare('UPDATE users SET credits = credits - 1 WHERE email = ?').run(email);
    db.prepare('INSERT INTO scans (id, user_id, mode, score) VALUES (?, ?, ?, ?)').run(uuidv4(), user.id, mode, result.score);

    const remaining = db.prepare('SELECT credits FROM users WHERE email = ?').get(email);
    res.json({ ...result, creditsRemaining: remaining.credits });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚩 Red Flag Detector running on port ${PORT}`));
