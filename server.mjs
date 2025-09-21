import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import twilio from 'twilio';

// ======== ENV VARS ========
const {
  PORT = process.env.PORT || 3001,
  FRONTEND_ORIGIN = 'http://localhost:5173',
  DEV_ORIGINS = 'http://localhost:5173,http://127.0.0.1:5173',
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_PHONE_NUMBER,
} = process.env;

// ======== EXPRESS APP ========

// ======== EXPRESS APP ========
const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
// Incoming SMS webhook (Twilio -> your server)
app.post('/sms', (req, res) => {
  const { MessagingResponse } = twilio.twiml;
  const twiml = new MessagingResponse();
  twiml.message("Thanks for texting ACT Dance! We’ll get back to you shortly.");
  res.type('text/xml').send(twiml.toString());
});
