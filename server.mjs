// server.mjs 
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import twilio from 'twilio';
import { google } from 'googleapis';
import sgMail from '@sendgrid/mail';

/* ============================================================================
 * CONFIG
 * ==========================================================================*/
const CONFIG = {
  PORT: Number(process.env.PORT || 10000),

  // CORS
  FRONTEND_ORIGIN: process.env.FRONTPEND_ORIGIN || process.env.FRONTEND_ORIGIN || 'https://www.lighthouse.actdance.ca',
  DEV_ORIGINS: (process.env.DEV_ORIGINS || 'https://lighthouse.actdance.ca,https://app.base44.com')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),

  // Twilio
  TWILIO_ACCOUNT_SID: process.env.TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN: process.env.TWILIO_AUTH_TOKEN,
  TWILIO_PHONE_NUMBER: process.env.TWILIO_PHONE_NUMBER,

  // Your personal phone to receive alerts
  ALERT_PHONE: process.env.ALERT_PHONE,

  // Optional: shared secret for incoming automations/webhooks (Wix → this server)
  // If set, Wix must send it as a header (X-Automation-Secret) OR in the body/query "secret"
  AUTOMATION_SHARED_SECRET: process.env.AUTOMATION_SHARED_SECRET || '',

  // Google OAuth / Calendar
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI: process.env.GOOGLE_REDIRECT_URI, // e.g. http://localhost:10000/oauth2callback

  // NEW: Sheets-specific redirect so Calendar & Sheets can use different callbacks
  GOOGLE_REDIRECT_URI_SHEETS: process.env.GOOGLE_REDIRECT_URI_SHEETS, // e.g. http://localhost:10000/oauth2callback/sheets

  GCAL_CALENDAR_ID: process.env.GCAL_CALENDAR_ID || 'primary',

  // Sheets
  SHEETS_SPREADSHEET_ID: process.env.SHEETS_SPREADSHEET_ID,
};

function warnMissingEnv(name) {
  if (!CONFIG[name]) console.warn(`⚠️  Missing env: ${name}`);
}
// Required for SMS features
['TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_PHONE_NUMBER', 'ALERT_PHONE'].forEach(warnMissingEnv);
// Nice-to-have for securing webhooks
['AUTOMATION_SHARED_SECRET'].forEach(warnMissingEnv);
// Required only if you use Google OAuth
['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_REDIRECT_URI'].forEach(warnMissingEnv);
// Helpful warnings for email
['SENDGRID_API_KEY', 'SENDGRID_FROM_EMAIL', 'SENDGRID_MARKETING_GROUP_ID'].forEach((k) =>
  !process.env[k] && console.warn(`⚠️  Missing env: ${k}`)
);

/* ============================================================================
 * APP & MIDDLEWARE
 * ==========================================================================*/
const app = express();

// Minimal request logger
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});
// DEBUG: show which redirect_uri + client your server will use for Sheets auth
app.get('/debug/oauth/sheets', (req, res) => {
  const redirectUri = (process.env.GOOGLE_REDIRECT_URI_SHEETS || process.env.GOOGLE_REDIRECT_URI || '').trim();
  res.json({
    clientId: process.env.GOOGLE_CLIENT_ID || null,
    usingRedirectUri: redirectUri || null,
  });
});

// CORS first
const corsAllowList = new Set([CONFIG.FRONTEND_ORIGIN, ...CONFIG.DEV_ORIGINS]);
const corsAllowRegexes = [
  /^https:\/\/([a-z0-9-]+\.)*base44\.com$/i,
  /^https:\/\/([a-z0-9-]+\.)*base44\.app$/i, // optional, if you use .app previews
  /^https:\/\/(www\.)?lighthouse\.actdance\.ca$/i,
];
app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true); // allow curl/postman/Twilio
      if (corsAllowList.has(origin)) return cb(null, true);
      if (corsAllowRegexes.some((re) => re.test(origin))) return cb(null, true);
      console.warn('🚫 CORS blocked Origin:', origin);
      return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);
app.options('*', cors());

// Body parsers
app.use(express.json()); // JSON APIs
app.use(express.urlencoded({ extended: false })); // Twilio webhooks & form posts

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
oauth2Client.on('tokens', (t) => {
  gTokens = { ...(gTokens || {}), ...t };
});
function loadTokensFromEnv() {
  try {
    if (process.env.GOOGLE_TOKENS_JSON) {
      gTokens = JSON.parse(process.env.GOOGLE_TOKENS_JSON);
      oauth2Client.setCredentials(gTokens);
      console.log('Loaded Google tokens from env (Sheets/Calendar).');
    }
  } catch (e) {
    console.error('Failed to parse GOOGLE_TOKENS_JSON:', e);
  }
}
loadTokensFromEnv();

function requireGoogle() {
  if (!gTokens?.access_token && !gTokens?.refresh_token) {
    const err = new Error('Google not connected. Visit /oauth2/auth to connect.');
    err.status = 401;
    throw err;
  }
  oauth2Client.setCredentials(gTokens);
  return google.calendar({ version: 'v3', auth: oauth2Client });
}


// NEW: Sheets helper (parallel to requireGoogle)
function requireSheets() {
  if (!gTokens?.access_token && !gTokens?.refresh_token) {
    const err = new Error('Google not connected. Visit /auth/google/sheets to connect Sheets.');
    err.status = 401;
    throw err;
  }
  oauth2Client.setCredentials(gTokens);
  return google.sheets({ version: 'v4', auth: oauth2Client });
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

// Accept payload from JSON body OR query string (?key=value)
function getPayload(req) {
  return (req.body && Object.keys(req.body).length) ? req.body : req.query;
}

// Accept secret in header or body/query; if no secret configured, do not enforce
function verifyAutomationSecret(req) {
  if (!CONFIG.AUTOMATION_SHARED_SECRET) return true;
  const header = req.header('X-Automation-Secret') || req.header('x-automation-secret');
  const src = getPayload(req);
  const bodySecret = src?.secret || src?.automationSecret || src?.X_Automation_Secret;
  return (header && header === CONFIG.AUTOMATION_SHARED_SECRET) ||
         (bodySecret && bodySecret === CONFIG.AUTOMATION_SHARED_SECRET);
}

/* ============================================================================
 * BASIC HEALTH
 * ==========================================================================*/
// (removed stray res.send(...) that was outside any route)
app.get('/api/health', (_req, res) => res.json({ ok: true, ts: Date.now() }));

/* ============================================================================
 * WIX → WEBHOOK → SMS ALERT (from your Twilio business number)
 * - Accepts POST or GET
 * - Accepts: name OR firstName+lastName, email, phone, formName
 * - Verifies secret (header or body/query) if configured
 * ==========================================================================*/
app.all('/hooks/wix/new-lead', async (req, res, next) => {
  try {
    assert(verifyAutomationSecret(req), 'Unauthorized webhook', 401);
    assert(CONFIG.ALERT_PHONE, 'ALERT_PHONE not configured', 500);

    const src = getPayload(req) || {};
    const fullName = (src.name || [src.firstName, src.lastName].filter(Boolean).join(' ')).trim();
    const email = src.email || '';
    const phone = src.phone || '';
    const formName = src.formName || 'Lead Inquiry';

    const lines = [
      'New Wix Lead!',
      `Name: ${fullName || '—'}`,
      `Email: ${email || '—'}`,
      `Phone: ${phone || '—'}`,
      formName ? `Form: ${formName}` : null,
    ].filter(Boolean);

    const msg = await twilioClient.messages.create({
      from: CONFIG.TWILIO_PHONE_NUMBER,
      to: CONFIG.ALERT_PHONE,
      body: lines.join('\n'),
    });

    res.json({ ok: true, sid: msg.sid, status: msg.status });
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
 * GOOGLE OAUTH FLOW (Calendar)
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
    gTokens = { ...(gTokens || {}), ...tokens };

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

    const params = { calendarId, maxResults: Number(maxResults) };

    if (syncToken) {
      params.syncToken = syncToken; // incremental sync
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
 * GOOGLE SHEETS AUTH (separate, safe)
 *  - Uses Sheets-specific redirect if set; otherwise falls back to main redirect
 * ==========================================================================*/
app.get('/auth/google/sheets', (req, res, next) => {
  try {
    const url = oauth2Client.generateAuthUrl({
      access_type: 'offline',
      include_granted_scopes: true, // incremental auth; keeps your Calendar access
      scope: [
        'https://www.googleapis.com/auth/spreadsheets',
        'https://www.googleapis.com/auth/drive.file',
      ],
      prompt: 'consent', // ensures refresh_token if needed
      redirect_uri: CONFIG.GOOGLE_REDIRECT_URI_SHEETS || CONFIG.GOOGLE_REDIRECT_URI,
    });

    // ✅ Log AFTER the URL is created
    console.log('SHEETS AUTH URL →', url);

    res.redirect(url);
  } catch (err) {
    next(err);
  }
});


app.get('/oauth2callback/sheets', async (req, res, next) => {
  try {
    const { code } = req.query;
    const redirectUri = CONFIG.GOOGLE_REDIRECT_URI_SHEETS || CONFIG.GOOGLE_REDIRECT_URI;

    const { tokens } = await oauth2Client.getToken({ code, redirect_uri: redirectUri });
    oauth2Client.setCredentials(tokens);

    // merge with any existing tokens (so Calendar keeps working)
    gTokens = { ...(gTokens || {}), ...tokens };

    // print tokens so you can persist them in Render
    const blob = JSON.stringify(gTokens);
    console.log('GOOGLE_TOKENS_JSON →', blob);

    res.send('✅ Google Sheets connected. Copy GOOGLE_TOKENS_JSON from logs and save it to Render env.');
  } catch (err) {
    console.error('Sheets OAuth error:', err);
    next(err);
  }
});


/* ============================================================================
 * GOOGLE SHEETS: tiny status/read/append endpoints (for testing)
 * ==========================================================================*/
app.get('/api/sheets/status', (_req, res) => {
  const connected = !!(gTokens?.access_token || gTokens?.refresh_token);
  res.json({ connected, spreadsheetId: CONFIG.SHEETS_SPREADSHEET_ID || null });
});

app.get('/api/sheets/read', async (req, res, next) => {
  try {
    const sheets = requireSheets();
    const spreadsheetId = CONFIG.SHEETS_SPREADSHEET_ID;
    const range = String(req.query.range || 'Sheet1!A1:B10');
    const { data } = await sheets.spreadsheets.values.get({ spreadsheetId, range });
    res.json({ ok: true, range, values: data.values || [] });
  } catch (err) {
    next(err);
  }
});

app.post('/api/sheets/append', async (req, res, next) => {
  try {
    const sheets = requireSheets();
    const spreadsheetId = CONFIG.SHEETS_SPREADSHEET_ID;
    const range = String(req.body?.range || 'Sheet1!A1');
    const values = Array.isArray(req.body?.values) ? req.body.values : null;
    assert(values && Array.isArray(values[0]), 'values must be a 2D array, e.g. [["A","B"]]');
    const { data } = await sheets.spreadsheets.values.append({
      spreadsheetId,
      range,
      valueInputOption: 'USER_ENTERED',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values },
    });
    res.json({ ok: true, updates: data.updates || null });
  } catch (err) {
    next(err);
  }
});

/* ============================================================================
 * SENDGRID SETUP
 * ==========================================================================*/
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

/* ============================================================================
 * EMAIL ENDPOINT (enhanced)
 * ==========================================================================*/
app.post('/api/email/send', async (req, res) => {
  try {
    let { to, subject, html, text, categories = [], customArgs = {} } = req.body || {};

    if (!to || !subject || (!html && !text)) {
      return res.status(400).json({ ok: false, error: 'to, subject, and html or text are required' });
    }

    // Allow single string, comma-separated, or array
    const recipients = Array.isArray(to)
      ? to
      : String(to).split(',').map((s) => s.trim()).filter(Boolean);

    // Auto-append compliant footer with Unsubscribe (if not already present)
    if (html && !html.includes('<%asm_group_unsubscribe_raw_url%>')) {
      html += `
        <hr>
        <p style="font-size:12px;opacity:0.8;line-height:1.4">
          You’re receiving this because you engaged with ACT Dance.<br>
          <a href="<%asm_group_unsubscribe_raw_url%>">Unsubscribe</a> anytime.
          <br>ACT Dance • Kelowna, BC
        </p>`;
    }

    const msg = {
      to: recipients,
      from: { email: process.env.SENDGRID_FROM_EMAIL, name: process.env.SENDGRID_FROM_NAME },
      subject,
      html: html || undefined,
      text: text || undefined,
      categories: Array.isArray(categories) ? categories.slice(0, 4) : undefined,
      customArgs: customArgs && typeof customArgs === 'object' ? customArgs : undefined,
      asm: process.env.SENDGRID_MARKETING_GROUP_ID
        ? { groupId: Number(process.env.SENDGRID_MARKETING_GROUP_ID) }
        : undefined, // unsubscribe group
      trackingSettings: {
        clickTracking: { enable: true },
        openTracking: { enable: true },
      },
    };

    const [response] = await sgMail.send(msg);
    return res.json({ ok: true, status: response.statusCode });
  } catch (err) {
    console.error('SendGrid error:', err?.response?.body || err.message);
    return res.status(500).json({ ok: false, error: err?.response?.body || err.message });
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
  const detail = err?.response?.data || err?.more || null;
  if (detail) console.error('❌ Error detail:', detail);
  console.error('❌', status, message);
  res.status(status).json({ error: message });
});

/* ============================================================================
 * BOOKING WEBHOOK → WRITE ONE ROW TO Events-M02!A:S
 *  - Puts Tracking Number in P (your link key)
 *  - B (Name) and T (Auto Title) are filled by your sheet formulas
 * ==========================================================================*/
// --- replaces the old TEST echo route ---
const pad2 = (n) => String(n).padStart(2, '0');
const ymd = (d) => `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
const hm = (d) => `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;

app.post('/api/hooks/booking', async (req, res, next) => {
  try {
    // (optional) enforce secret if set
    assert(verifyAutomationSecret(req), 'Unauthorized webhook', 401);

    const {
      trackingNumber,        // REQUIRED → goes to P
      student = {},
      teacher = '',
      startIso,
      endIso,
      location = '',
      frontBack = '',        // 'Front' or 'Back' → goes to I
      title = '',            // optional manual title → goes to F
      notes = '',            // goes to H
      programPlusCount = ''  // e.g., 'ACT 20, 5/20' → goes to S
    } = req.body || {};

    assert(CONFIG.SHEETS_SPREADSHEET_ID, 'SHEETS_SPREADSHEET_ID not set', 500);
    assert(trackingNumber, 'trackingNumber missing');
    assert(startIso && endIso, 'startIso/endIso required');

    const start = new Date(startIso);
    const end = new Date(endIso);

    const row = [
      ymd(start),            // A Date
      '',                    // B Name (auto via P using your formula)
      teacher,               // C Teacher
      hm(start),             // D Start Time
      hm(end),               // E End Time
      title,                 // F Manual Title (optional)
      location,              // G Location
      notes,                 // H Notes
      frontBack,             // I Front/Back
      '',                    // J Hours (sheet formula)
      '',                    // K Back Dept (your formula from I)
      '',                    // L Ren/Ext Lessons
      '',                    // M Front Dept Lesson
      '',                    // N (skip)
      '',                    // O (Original/Extension/Renewal/No Sale) — leave blank
      trackingNumber,        // P Tracking Number
      '',                    // Q Program (parsed from S)
      '',                    // R Lesson Count (parsed from S)
      programPlusCount       // S Program + Count (source)
      // T Auto Title is a formula on the sheet
    ];

    const sheets = requireSheets();
    await sheets.spreadsheets.values.append({
      spreadsheetId: CONFIG.SHEETS_SPREADSHEET_ID,
      range: 'Events-M02!A2:S2',
      valueInputOption: 'USER_ENTERED',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values: [row] },
    });

    res.json({ ok: true, wrote: 'Events-M02!A:S', trackingNumber, startIso, endIso });
  } catch (err) {
    console.error('[booking webhook ERROR]', err);
    next(err);
  }
});

/* ============================================================================
 * START
 * ==========================================================================*/
app.listen(CONFIG.PORT, () => {
  console.log(`✅ ACT backend running on port ${CONFIG.PORT}`);
});
// DEBUG: show which redirect_uri + client your server will use for Sheets auth
app.get('/debug/oauth/sheets', (req, res) => {
  const redirectUri = (process.env.GOOGLE_REDIRECT_URI_SHEETS || process.env.GOOGLE_REDIRECT_URI || '').trim();
  res.json({
    clientId: process.env.GOOGLE_CLIENT_ID || null,
    usingRedirectUri: redirectUri || null,
  });
});
