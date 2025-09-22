// server.mjs
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import twilio from 'twilio';
import { google } from 'googleapis';

/* ========== ENV ========== */
const PORT = process.env.PORT || 10000;

// Twilio
const {
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_PHONE_NUMBER,
} = process.env;

// CORS (optional allow-list)
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '';
const DEV_ORIGINS = (process.env.DEV_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// Google OAuth (Calendar)
const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI, // e.g. https://lighthouse.actdance.ca/oauth2/callback
} = process.env;

/* ========== APP ========== */
const app = express();

// Parsers: Twilio webhooks need urlencoded; your APIs use JSON
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Simple request logger
app.use((req, _res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// CORS allow-list (optional—safe defaults)
const allowList = new Set([FRONTEND_ORIGIN, ...DEV_ORIGINS].filter(Boolean));
app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);          // allow curl/postman/Twilio
      if (allowList.size === 0) return cb(null, true); // if no allow-list provided, allow all
      if (allowList.has(origin)) return cb(null, true);
      console.warn('🚫 CORS blocked Origin:', origin);
      return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);
app.options('*', cors());

/* ========== TWILIO ========== */
const twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
const { MessagingResponse } = twilio.twiml;

/* ========== GOOGLE OAUTH ========== */
const oauth2Client = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI
);

/* ========== ROUTES ========== */

// Health
app.get('/', (_req, res) => res.send('ACT SMS backend is running'));
app.get('/api/health', (_req, res) => res.json({ ok: true, message: 'Server running ✅' }));

// Debug OAuth env presence
app.get('/oauth2/ping', (_req, res) => {
  res.json({
    hasClientId: !!GOOGLE_CLIENT_ID,
    hasClientSecret: !!GOOGLE_CLIENT_SECRET,
    redirectUri: GOOGLE_REDIRECT_URI || null,
  });
});

// Start Google OAuth
app.get('/oauth2/auth', (_req, res) => {
  try {
    const url = oauth2Client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      scope: [
        'https://www.googleapis.com/auth/calendar.events',
        'https://www.googleapis.com/auth/calendar.readonly',
      ],
    });
    res.redirect(url);
  } catch (e) {
    console.error('Auth URL error:', e);
    res.status(500).send('Auth URL error');
  }
});

// Handle Google callback
app.get('/oauth2/callback', async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send('No code provided');
    const { tokens } = await oauth2Client.getToken(code);

    // TODO: Persist tokens (DB/file). Keep refresh_token for long-term access.
    oauth2Client.setCredentials(tokens);

    res.send('Google Calendar connected ✔️ You can close this tab.');
  } catch (err) {
    console.error('OAuth callback error:', err?.response?.data || err);
    res.status(500).send('OAuth error');
  }
});

// Incoming SMS (Twilio → your server)
app.post('/sms', (req, res) => {
  try {
    const twiml = new MessagingResponse();
    twiml.message("Thanks for texting ACT Dance! We’ll get back to you shortly.");
    res.type('text/xml').send(twiml.toString());
  } catch (e) {
    console.error('Twilio webhook error:', e);
    res.status(500).type('text/plain').send('Webhook error');
  }
});

// Outgoing SMS (your app → Twilio → user)
app.post('/api/sms/send', async (req, res) => {
  try {
    const { to, body } = req.body || {};
    if (!to || !body) return res.status(400).json({ ok: false, error: 'Missing to/body' });

    const message = await twilioClient.messages.create({
      from: TWILIO_PHONE_NUMBER,
      to,
      body,
    });

    res.json({ ok: true, sid: message.sid, status: message.status });
  } catch (err) {
    console.error('❌ SMS send error:', err?.message || err);
    res.status(500).json({ ok: false, error: err.message || 'SMS send failed' });
  }
});

/* ========== START ========== */
app.listen(PORT, () => {
  console.log(`✅ ACT SMS server running at http://localhost:${PORT}`);
});
