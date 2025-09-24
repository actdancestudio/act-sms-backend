// server.mjs
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import twilio from 'twilio';
import { google } from 'googleapis';

/* ============================================================================
 * CONFIG
 * ==========================================================================*/
const CONFIG = {
  PORT: Number(process.env.PORT || 10000),

  // CORS
  FRONTEND_ORIGIN: process.env.FRONTEND_ORIGIN || 'https://www.lighthouse.actdance.ca',
  DEV_ORIGINS: (process.env.DEV_ORIGINS || 'https://lighthouse.actdance.ca')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean),

  // Twilio
  TWILIO_ACCOUNT_SID: process.env.TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN: process.env.TWILIO_AUTH_TOKEN,
  TWILIO_PHONE_NUMBER: process.env.TWILIO_PHONE_NUMBER,

  // Alert destination (your personal phone)
  ALERT_PHONE: process.env.ALERT_PHONE,

  // Optional shared secret for incoming automations/webhooks (Wix → this server)
  // Set the same string in your Wix Automation "Send Webhook" custom header:
  //   Header Name: X-Automation-Secret, Value: <the same secret>
  AUTOMATION_SHARED_SECRET: process.env.AUTOMATION_SHARED_SECRET || '',

  // Google OAuth / Calendar
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI: process.env.GOOGLE_REDIRECT_URI,      // e.g. https://lighthouse.actdance.ca/oauth2/callback
  GCAL_CALENDAR_ID: process.env.GCAL_CALENDAR_ID || 'primary',
};

function warnMissingEnv(name) {
  if (!CONFIG[name]) console.warn(`⚠️  Missing env: ${name}`);
}
// Required for SMS features
['TWILIO_ACCOUNT_SID','TWILIO_AUTH_TOKEN','TWILIO_PHONE_NUMBER','ALERT_PHONE'].forEach(warnMissingEnv);
// Nice-to-have for securing webhooks
['AUTOMATION_SHARED_SECRET'].forEach(warnMissingEnv);
// Required only if you use Google Calendar sync
['GOOGLE_CLIENT_ID','GOOGLE_CLIENT_SECRET','GOOGLE_REDIRECT_URI'].forEach(warnMissingEnv);

/* ============================================================================
 * APP & MIDDLEWARE
 * ==========================================================================*/
const app = express();

// Minimal request logger
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// CORS first
const corsAllowList = new Set([CONFIG.FRONTEND_ORIGIN, ...CONFIG.DEV_ORIGINS]);
const corsAllowRegexes = [
  /^https:\/\/([a-z0-9-]+\.)*base44\.com$/i,
  /^https:\/\/([a-z0-9-]+\.)*base44\.app$/i,           // optional if you use .app previews
  /^https:\/\/(www\.)?lighthouse\.actdance\.ca$/i,     // your domain
];
app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true); // allow curl/postman/Twilio
      if (corsAllowList.has(origin)) return cb(null, true);
      if (corsAllowRegexes.some(re => re.test(origin))) return cb(null, true);
      console.warn('🚫 CORS blocked Origin:', origin);
      return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);
app.options('*', cors());

// Body parsers
app.use(express.json()); // JSON APIs
app.use(express.urlencoded({ extended: false })); // for Twilio webhooks & form posts

/* ============================================================================
 * TWILIO SETUP
 * ==========================================================================*/
const twilioClient = twilio(CONFIG.TWILIO_ACCOUNT_SID, CONFIG.TWILIO_AUTH_TOKEN);
const { MessagingResponse } = twilio.twiml;

/* ============================================================================
 * GOOGLE OAUTH / CALENDAR
 *  - In-memory token store for simplicity (swap for DB when ready)
 * ==========================================================================*/
const oauth2Client = new google.auth.OAuth2(
  CONFIG.GOOGLE_CLIENT_ID,
  CONFIG.GOOGLE_CLIENT_SECRET,
  CONFIG.GOOGLE_REDIRECT_URI
);

let gTokens = null;
oauth2Client.on('tokens', t => {
  gTokens = { ...(gTokens || {}), ...t };
});

function requireGoogle() {
  if (!gTokens?.access_token && !gTokens?.refresh_token) {
    const err = new Error('Google not connected. Visit /oauth2/auth to connect.');
    err.status = 401;
    throw err;
  }
  oauth2Client.setCredentials(gTokens);
  return google.calendar({ version: 'v3', auth: oauth2Client });
}

/* ============================================================================
 * HELPERS
 * ==========================================================================*/
function assert(condition, message, status = 400) {
  if (!condition) {
    const err = new Error(message);
    err.status = status;
    throw err;
  }
}

function verifyAutomationSecret(req) {
  if (!CONFIG.AUTOMATION_SHARED_SECRET) return true; // not enforced
  const incoming = req.header('X-Automation-Secret') || req.header('x-automation-secret');
  return incoming && incoming === CONFIG.AUTOMATION_SHARED_SECRET;
}

/* ============================================================================
 * BASIC HEALTH
 * ==========================================================================*/
app.get('/', (_req, res) => res.send('✅ ACT backend is running'));
app.get('/api/health', (_req, res) => res.json({ ok: true, ts: Date.now() }));

/* ============================================================================
 * WIX → WEBHOOK → SMS ALERT (from your Twilio business number)
 * ==========================================================================*/
app.post('/hooks/wix/new-lead', async (req, res, next) => {
  try {
    assert(verifyAutomationSecret(req), 'Unauthorized webhook', 401);

    const { name, email, phone, formName } = req.body || {};
    assert(CONFIG.ALERT_PHONE, 'ALERT_PHONE not configured');

    const lines = [
      'New Wix Lead!',
      `Name: ${name || '—'}`,
      `Email: ${email || '—'}`,
      `Phone: ${phone || '—'}`,
      formName ? `Form: ${formName}` : null,
    ].filter(Boolean);

    const message = await twilioClient.messages.create({
      from: CONFIG.TWILIO_PHONE_NUMBER,
      to: CONFIG.ALERT_PHONE,
      body: lines.join('\n'),
    });

    res.json({ ok: true, sid: message.sid, status: message.status });
  } catch (err) {
    next(err);
  }
});

/* ============================================================================
 * TWILIO SMS
 * ==========================================================================*/
// Incoming SMS (Twilio → your server)
app.post('/sms', (req, res, next) => {
  try {
    const twiml = new MessagingResponse();
    twiml.message("Thanks for texting ACT Dance! We’ll get back to you shortly.");
    res.type('text/xml').send(twiml.toString());
  } catch (err) {
    next(err);
  }
});

// Outgoing SMS (your app → Twilio → recipient)
app.post('/api/sms/send', async (req, res, next) => {
  try {
    const { to, body } = req.body || {};
    assert(to && body, 'Missing to/body');

    const msg = await twilioClient.messages.create({
      from: CONFIG.TWILIO_PHONE_NUMBER,
      to,
      body,
    });
    res.json({ ok: true, sid: msg.sid, status: msg.status });
  } catch (err) {
    next(err);
  }
});

/* ============================================================================
 * GOOGLE OAUTH FLOW
 * ==========================================================================*/
app.get('/oauth2/ping', (_req, res) => {
  res.json({
    hasClientId: !!CONFIG.GOOGLE_CLIENT_ID,
    hasClientSecret: !!CONFIG.GOOGLE_CLIENT_SECRET,
    redirectUri: CONFIG.GOOGLE_REDIRECT_URI || null,
  });
});

app.get('/oauth2/auth', (_req, res, next) => {
  try {
    const url = oauth2Client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      scope: ['https://www.googleapis.com/auth/calendar'], // full R/W
    });
    res.redirect(url);
  } catch (err) {
    next(err);
  }
});

app.get('/oauth2/callback', async (req, res, next) => {
  try {
    const code = req.query.code;
    assert(code, 'No code provided');

    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    gTokens = tokens;

    res.send('Google Calendar connected ✔️ You can close this tab.');
  } catch (err) {
    next(err);
  }
});

app.get('/api/gcal/status', (_req, res) => {
  const connected = !!(gTokens?.access_token || gTokens?.refresh_token);
  res.json({ connected });
});

/* ============================================================================
 * GOOGLE CALENDAR: LIST / CREATE / UPDATE / DELETE
 * ==========================================================================*/
app.get('/api/gcal/calendars', async (_req, res, next) => {
  try {
    const calendar = requireGoogle();
    const { data } = await calendar.calendarList.list();
    res.json(data.items || []);
  } catch (err) {
    next(err);
  }
});

app.get('/api/gcal/events', async (req, res, next) => {
  try {
    const calendar = requireGoogle();
    const {
      calendarId = CONFIG.GCAL_CALENDAR_ID,
      timeMin,
      timeMax,
      maxResults = 100,
      pageToken,
      syncToken,
      showDeleted = false,
    } = req.query;

    const params = {
      calendarId,
      maxResults: Number(maxResults),
    };

    if (syncToken) {
      params.syncToken = syncToken;     // incremental sync
    } else {
      params.singleEvents = true;
      params.orderBy = 'startTime';
      params.timeMin = timeMin || new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
      params.timeMax = timeMax || new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
      params.showDeleted = String(showDeleted) === 'true';
      if (pageToken) params.pageToken = pageToken;
    }

    const { data } = await calendar.events.list(params);
    res.json({
      items: data.items || [],
      nextPageToken: data.nextPageToken || null,
      nextSyncToken: data.nextSyncToken || null,
    });
  } catch (err) {
    // If syncToken expired → 410 Gone
    next(err);
  }
});

app.post('/api/gcal/events', async (req, res, next) => {
  try {
    const calendar = requireGoogle();
    const {
      calendarId = CONFIG.GCAL_CALENDAR_ID,
      summary,
      description,
      location,
      start,
      end,
      attendees,
      reminders,
      colorId,
      extendedProperties,
      conferenceData,
      transparency = 'opaque',
      visibility = 'default',
    } = req.body || {};

    assert(start && end, 'start/end required');

    const { data } = await calendar.events.insert({
      calendarId,
      requestBody: {
        summary,
        description,
        location,
        start,
        end,
        attendees,
        reminders,
        colorId,
        extendedProperties,
        conferenceData,
        transparency,
        visibility,
      },
      sendUpdates: 'all',
      conferenceDataVersion: conferenceData ? 1 : 0,
    });

    res.status(201).json(data);
  } catch (err) {
    next(err);
  }
});

app.patch('/api/gcal/events/:eventId', async (req, res, next) => {
  try {
    const calendar = requireGoogle();
    const { eventId } = req.params;
    const { calendarId = CONFIG.GCAL_CALENDAR_ID, ...patchFields } = req.body || {};
    assert(eventId, 'eventId required');

    const { data } = await calendar.events.patch({
      calendarId,
      eventId,
      requestBody: patchFields,
      sendUpdates: 'all',
      conferenceDataVersion: patchFields.conferenceData ? 1 : 0,
    });

    res.json(data);
  } catch (err) {
    next(err);
  }
});

app.delete('/api/gcal/events/:eventId', async (req, res, next) => {
  try {
    const calendar = requireGoogle();
    const { eventId } = req.params;
    const { calendarId = CONFIG.GCAL_CALENDAR_ID } = req.query;
    assert(eventId, 'eventId required');

    await calendar.events.delete({
      calendarId,
      eventId,
      sendUpdates: 'all',
    });

    res.json({ ok: true, deleted: eventId });
  } catch (err) {
    next(err);
  }
});

/* ============================================================================
 * 404 + ERROR HANDLERS
 * ==========================================================================*/
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', path: req.path });
});

app.use((err, _req, res, _next) => {
  const status = err.status || err.code || 500;
  const message = err.message || 'Internal Server Error';
  // Log a concise error with any nested Google/Twilio payload if present
  const detail = err?.response?.data || err?.more || null;
  if (detail) console.error('❌ Error detail:', detail);
  console.error('❌', status, message);
  res.status(status).json({ error: message });
});

/* ============================================================================
 * START
 * ==========================================================================*/
app.listen(CONFIG.PORT, () => {
  console.log(`✅ ACT backend running on port ${CONFIG.PORT}`);
});
