require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Anthropic = require('@anthropic-ai/sdk');
const Stripe = require('stripe');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const adapter = new FileSync('db.json');
const db = low(adapter);
db.defaults({ users: [], scans: [] }).write();

app.use(cors());
app.use(express.static(path.join(__dirname)));

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
    const existing = db.get('users').find({ email }).value();
    if (existing) {
      db.get('users').find({ email }).assign({ credits: existing.credits + credits }).write();
    } else {
      db.get('users').push({ id: uuidv4(), email, credits, created_at: new Date().toISOString() }).write();
    }
    console.log(`Added ${credits} credits to ${email}`);
  }
  res.json({ received: true });
});

app.use(express.json());

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

app.post('/api/credits', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const user = db.get('users').find({ email }).value();
  res.json({ credits: user ? user.credits : 0 });
});

app.post('/api/analyze', async (req, res) => {
  const { email, mode, input } = req.body;
  if (!email || !mode || !input) return res.status(400).json({ error: 'Missing fields' });
  const user = db.get('users').find({ email }).value();
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
    db.get('users').find({ email }).assign({ credits: user.credits - 1 }).write();
    db.get('scans').push({ id: uuidv4(), user_id: user.id, mode, score: result.score, created_at: new Date().toISOString() }).write();
    const updatedUser = db.get('users').find({ email }).value();
    res.json({ ...result, creditsRemaining: updatedUser.credits });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚩 Red Flag Detector running on port ${PORT}`));
