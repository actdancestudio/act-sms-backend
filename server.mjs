import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import twilio from 'twilio';

// ======== ENV VARS ========
const PORT = process.env.PORT || 3001;
const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER } = process.env;

// ======== APP ========
const app = express();
app.use(bodyParser.urlencoded({ extended: false })); // Twilio webhooks
app.use(bodyParser.json());                          // Your API JSON

// Log every request (method + path) to Render logs
app.use((req, _res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// Permissive CORS (works for Lighthouse + Twilio)
app.use(cors({ origin: true, credentials: true }));
app.options('*', cors({ origin: true, credentials: true }));

// ======== TWILIO ========
const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
const { MessagingResponse } = twilio.twiml;

// ======== ROUTES ========
app.get('/', (_req, res) => res.send('ACT SMS backend is running'));
app.get('/api/health', (_req, res) => res.json({ ok: true, message: 'Server running ✅' }));

// Start OAuth: hit this in the browser
app.get('/oauth2/auth', (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: [
      'https://www.googleapis.com/auth/calendar.events',
      'https://www.googleapis.com/auth/calendar.readonly'
    ],
  });
  res.redirect(url);
});


    const start = new Date(Date.now() + 60 * 60 * 1000);
    const end = new Date(start.getTime() + 30 * 60 * 1000);

    const event = {
      summary: 'ACT Lighthouse Test',
      start: { dateTime: start.toISOString(), timeZone: 'America/Vancouver' },
      end:   { dateTime: end.toISOString(),   timeZone: 'America/Vancouver' },
    };

    const r = await calendar.events.insert({ calendarId: 'primary', requestBody: event });
    res.json({ ok: true, id: r.data.id });
  
    console.error('Create event error:', e);
    res.status(500).json({ ok: false, error: e.message });
  

// ---- TWILIO SMS ----
app.post('/sms', (req, res) => {
  const twiml = new MessagingResponse();
  twiml.message("Thanks for texting ACT Dance! We’ll get back to you shortly.");
  res.type('text/xml').send(twiml.toString());
});

app.post('/api/sms/send', async (req, res) => {
  try {
    const { to, body } = req.body;
    if (!to || !body) return res.status(400).json({ ok: false, error: 'Missing to/body' });

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

// ======== START ========
app.listen(PORT, () => {
  console.log(`✅ ACT SMS server running at http://localhost:${PORT}`);
});
