import 'dotenv/config';
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import twilio from "twilio";

// ======== ENV VARS ========
const {
  PORT = 3001,
  FRONTEND_ORIGIN = "http://localhost:5173", // your ACT Lighthouse dev origin
  DEV_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173",
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_PHONE_NUMBER, // your Twilio number (must be SMS capable)
} = process.env;

// ======== EXPRESS APP ========
const app = express();
app.use(bodyParser.json());

// ======== CORS CONFIG ========
const allowList = new Set(
  [FRONTEND_ORIGIN, ...DEV_ORIGINS.split(",")]
    .map((s) => s.trim())
    .filter(Boolean)
);

const corsOptions = {
  origin(origin, cb) {
    if (!origin) return cb(null, true); // allow curl/postman
    if (allowList.has(origin)) return cb(null, true);
    console.warn("🚫 CORS blocked Origin:", origin);
    return cb(new Error("Not allowed by CORS"));
  },
  credentials: true,
};

app.use(cors(corsOptions));

// ======== TWILIO CLIENT ========
const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

// ======== ROUTES ========

// Health check
app.get("/api/health", (req, res) => {
  res.json({ ok: true, message: "Server running ✅" });
});

// Send SMS
app.post("/api/sms/send", async (req, res) => {
  try {
    const { to, body } = req.body;
    if (!to || !body) return res.status(400).json({ ok: false, error: "Missing to/body" });

    const message = await client.messages.create({
      from: TWILIO_PHONE_NUMBER,
      to,
      body,
    });

    res.json({ ok: true, sid: message.sid, status: message.status });
  } catch (err) {
    console.error("❌ SMS send error:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ======== START SERVER ========
app.listen(PORT, () => {
  console.log(`✅ ACT SMS server running at http://localhost:${PORT}`);
});
