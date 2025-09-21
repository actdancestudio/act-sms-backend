import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import twilio from 'twilio';

// ======== ENV VARS ========
const PORT = process.env.PORT || 3001;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
const DEV_ORIGINS =
  process.env.DEV_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173';
const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER } =
  process.env;

// ======== EXPRESS APP ========
const app = express();

// Twilio webhooks send x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));
// JSON for your own API calls
app.use(bodyParser.json());

// ======== CORS CONFIG ========
const allowList = new Set(
  [FRONTEND_ORIGIN, ...DEV_ORIGINS.split(',')].map((s) => s.trim()).filter(Boolean)
);
app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true); // allow curl/postman/Twilio
      if (allowList.has(origin)) return cb(null, true);
      console.warn('🚫 CORS blocked Origin:', origin);
      return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);

// ======== TWILIO CLIENT ========
const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
const { MessagingResponse } = twilio.twiml;

// ======== ROUTES ========

// Root + health
app.get('/', (_req, res) => res.send('ACT SMS backend is running'));
app.get('/api/health', (_req, res) =>
  res.json({ ok: true, message: 'Server running ✅' })
);

// Incoming SMS webhook (Twilio -> your server)
app.post('/sms', (req, res) => {
  const twiml = new MessagingResponse();
  twiml.message("Thanks for texting ACT Dance! We’ll get back to you shortly.");
  res.type('text/xml').send(twiml.toString());
});

// Outgoing SMS (your app -> Twilio -> user)
app.post('/api/sms/send', async (req, res) => {
  try {
    const { to, body } = req.body;
    if (!to || !body)
      return res.status(400).json({ ok: false, error: 'Missing to/body' });

    const message = await client.messages.create({
      from: TWILIO_PHONE_NUMBER,
      to,
      body,
    });

    res.json({ ok: true, sid: message.sid, status: message.status });
  } catch (err) {
    console.error('❌ SMS send error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ======== START SERVER ========
app.listen(PORT, () => {
  console.log(`✅ ACT SMS server running at http://localhost:${PORT}`);
});
