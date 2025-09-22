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

// ==== CORS (self-contained) ====
// Safe defaults if envs aren't set yet:
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'https://www.lighthouse.actdance.ca';
const DEV_ORIGINS_RAW = process.env.DEV_ORIGINS || 'https://lighthouse.actdance.ca';
const DEV_ORIGINS = DEV_ORIGINS_RAW.split(',').map(s => s.trim()).filter(Boolean);

const corsAllowList = new Set([FRONTEND_ORIGIN, ...DEV_ORIGINS].filter(Boolean));
const corsAllowRegexes = [
  /^https:\/\/([a-z0-9-]+\.)*base44\.app$/i,        // any *.base44.app (previews)
  /^https:\/\/(www\.)?lighthouse\.actdance\.ca$/i,  // your app domains
];

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);                   // curl/postman/Twilio
    if (corsAllowList.has(origin)) return cb(null, true); // exact allow-list
    if (corsAllowRegexes.some(re => re.test(origin))) return cb(null, true); // regex allow
    console.warn('🚫 CORS blocked Origin:', origin);
    cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));
app.options('*', cors());



// Google OAuth (Calendar)
const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI, // e.g. https://lighthouse.actdance.ca/oauth2/callback
  GCAL_CALENDAR_ID = 'primary',
} = process.env;

/* ========== APP ========== */
const app = express();
app.use(express.urlencoded({ extended: false })); // Twilio webhooks
app.use(express.json());                           // JSON APIs

// Simple logger
app.use((req, _res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// CORS allow-list (safe defaults)
const allowList = new Set([FRONTEND_ORIGIN, ...DEV_ORIGINS].filter(Boolean));
app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);                // allow curl/postman/Twilio
      if (allowList.size === 0) return cb(null, true);   // no list => allow all
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

// In-memory token store (swap for DB in production)
let gTokens = null;

// Keep refreshed tokens in memory as Google rotates them
oauth2Client.on('tokens', (t) => {
  gTokens = { ...(gTokens || {}), ...t };
});
globalThis.gTokens = gTokens; // after you declare gTokens

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
      scope: ['https://www.googleapis.com/auth/calendar'], // full R/W
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
    oauth2Client.setCredentials(tokens);
    gTokens = tokens; // keep for subsequent calls (persist in DB for production)

    res.send('Google Calendar connected ✔️ You can close this tab.');
  } catch (err) {
    console.error('OAuth callback error:', err?.response?.data || err);
    res.status(500).send('OAuth error');
  }
});

/* ========== GOOGLE CALENDAR HELPERS & ENDPOINTS ========== */

// Build authed Calendar client
function authedCalendar() {
  if (!gTokens?.access_token && !gTokens?.refresh_token) {
    const err = new Error('Google not connected. Visit /oauth2/auth first.');
    err.status = 401;
    throw err;
  }
  oauth2Client.setCredentials(gTokens);
  return google.calendar({ version: 'v3', auth: oauth2Client });
}

// List calendars (choose non-primary, etc.)
app.get('/api/gcal/calendars', async (_req, res) => {
  try {
    const calendar = authedCalendar();
    const { data } = await calendar.calendarList.list();
    res.json(data.items || []);
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Failed to list calendars' });
  }
});

// List events (windowed or incremental via syncToken)
app.get('/api/gcal/events', async (req, res) => {
  try {
    const calendar = authedCalendar();
    const {
      calendarId = GCAL_CALENDAR_ID,
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
      singleEvents: true,
      showDeleted: showDeleted === 'true',
      pageToken,
      orderBy: 'startTime',
    };

    if (syncToken) {
      // Incremental sync: do NOT include timeMin/timeMax/orderBy
      params.syncToken = syncToken;
      delete params.singleEvents;
      delete params.orderBy;
    } else {
      params.timeMin = timeMin || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      params.timeMax = timeMax || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    }

    const { data } = await calendar.events.list(params);
    res.json({
      items: data.items || [],
      nextPageToken: data.nextPageToken || null,
      nextSyncToken: data.nextSyncToken || null,
    });
  } catch (e) {
    // If syncToken expired, Google returns 410 GONE
    const status = e.code || e.status || 500;
    res.status(status).json({ error: e.message || 'Failed to list events' });
  }
});

// Create event
app.post('/api/gcal/events', async (req, res) => {
  try {
    const calendar = authedCalendar();
    const {
      calendarId = GCAL_CALENDAR_ID,
      summary,
      description,
      location,
      start, // {dateTime, timeZone} OR {date}
      end,   // same shape as start
      attendees,
      reminders,
      colorId,
      extendedProperties, // { private: { lighthouseId, studentId, type } }
      conferenceData,     // { createRequest: { requestId } } to create Google Meet
      transparency = 'opaque',
      visibility = 'default',
    } = req.body || {};

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
  } catch (e) {
    res.status(500).json({ error: e.message || 'Failed to create event' });
  }
});

// Update event
app.patch('/api/gcal/events/:eventId', async (req, res) => {
  try {
    const calendar = authedCalendar();
    const { eventId } = req.params;
    const { calendarId = GCAL_CALENDAR_ID, ...patchFields } = req.body || {};

    const { data } = await calendar.events.patch({
      calendarId,
      eventId,
      requestBody: patchFields,
      sendUpdates: 'all',
      conferenceDataVersion: patchFields.conferenceData ? 1 : 0,
    });

    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message || 'Failed to update event' });
  }
});

// Delete event
app.delete('/api/gcal/events/:eventId', async (req, res) => {
  try {
    const calendar = authedCalendar();
    const { eventId } = req.params;
    const { calendarId = GCAL_CALENDAR_ID } = req.query;

    await calendar.events.delete({
      calendarId,
      eventId,
      sendUpdates: 'all',
    });

    res.json({ ok: true, deleted: eventId });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Failed to delete event' });
  }
});

/* ========== TWILIO SMS ENDPOINTS ========== */

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
// Are we connected to Google?
app.get('/api/gcal/status', (_req, res) => {
  const connected = !!(globalThis.gTokens?.access_token || globalThis.gTokens?.refresh_token);
  res.json({ connected });
});

/* ========== START ========== */
app.listen(PORT, () => {
  console.log(`✅ ACT SMS server running at http://localhost:${PORT}`);
});
