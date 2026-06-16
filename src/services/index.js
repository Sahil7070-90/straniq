// src/services/index.js — All External Services

const nodemailer = require("nodemailer");
const axios      = require("axios");

// ══════════════════════════════════════════════
// OTP GENERATOR
// ══════════════════════════════════════════════
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ══════════════════════════════════════════════
// EMAIL SERVICE (Gmail SMTP)
// ══════════════════════════════════════════════
let transporter = null;

function getTransporter() {
  if (!transporter && process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST || "smtp.gmail.com",
      port: parseInt(process.env.EMAIL_PORT) || 587,
      secure: false,
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
      tls: { rejectUnauthorized: false },
    });
  }
  return transporter;
}

async function sendEmailOTP(email, otp, username) {
  const t = getTransporter();

  // If no email config → return demo OTP in dev
  if (!t) {
    console.log(`[DEV] Email OTP for ${email}: ${otp}`);
    return { ok: true, demo: true };
  }

  const html = `
  <!DOCTYPE html>
  <html>
  <body style="margin:0;padding:0;background:#06060f;font-family:'Segoe UI',sans-serif;">
    <div style="max-width:480px;margin:40px auto;background:#0d0d1e;border:1px solid #1e1e3a;border-radius:20px;overflow:hidden;">
      <div style="background:linear-gradient(135deg,#7c3aed,#a855f7);padding:32px;text-align:center;">
        <div style="font-size:2.5rem;margin-bottom:8px;">⚡</div>
        <h1 style="color:#fff;font-size:1.8rem;font-weight:900;margin:0;letter-spacing:-1px;">Straniq</h1>
        <p style="color:rgba(255,255,255,.7);margin:6px 0 0;font-size:.9rem;">Meet the World — Instantly</p>
      </div>
      <div style="padding:32px;">
        <p style="color:#f0f0ff;font-size:1rem;margin-bottom:8px;">Hi <strong>${username}</strong>,</p>
        <p style="color:#8888aa;font-size:.9rem;margin-bottom:28px;line-height:1.6;">
          Your email verification code for Straniq is:
        </p>
        <div style="background:#1a1a38;border:2px solid #7c3aed;border-radius:16px;padding:24px;text-align:center;margin-bottom:28px;">
          <div style="font-size:2.5rem;font-weight:900;letter-spacing:12px;color:#a855f7;">${otp}</div>
          <p style="color:#4a4a6a;font-size:.78rem;margin:10px 0 0;">Valid for 10 minutes</p>
        </div>
        <p style="color:#4a4a6a;font-size:.78rem;line-height:1.6;">
          If you didn't request this, please ignore this email.
          Never share this OTP with anyone.
        </p>
      </div>
      <div style="background:#060610;padding:16px;text-align:center;border-top:1px solid #1e1e3a;">
        <p style="color:#4a4a6a;font-size:.72rem;margin:0;">
          © 2024 Straniq · Safe · Anonymous · Instant
        </p>
      </div>
    </div>
  </body>
  </html>`;

  try {
    await t.sendMail({
      from: process.env.EMAIL_FROM || `Straniq <${process.env.EMAIL_USER}>`,
      to: email,
      subject: `${otp} — Your Straniq Verification Code`,
      html,
    });
    return { ok: true };
  } catch (err) {
    console.error("Email send error:", err.message);
    return { ok: false, error: err.message };
  }
}

// ══════════════════════════════════════════════
// PHONE OTP SERVICE (Fast2SMS — India)
// ══════════════════════════════════════════════
async function sendPhoneOTP(phone, otp) {
  const apiKey = process.env.FAST2SMS_API_KEY;

  if (!apiKey) {
    console.log(`[DEV] Phone OTP for ${phone}: ${otp}`);
    return { ok: true, demo: true };
  }

  // Remove country code if present
  const cleanPhone = phone.replace(/^\+91/, "").replace(/\D/g, "");

  try {
    const res = await axios.post(
      "https://www.fast2sms.com/dev/bulkV2",
      {
        variables_values: otp,
        route: "otp",
        numbers: cleanPhone,
      },
      {
        headers: {
          authorization: apiKey,
          "Content-Type": "application/json",
        },
        timeout: 10000,
      }
    );
    if (res.data?.return === true) return { ok: true };
    return { ok: false, error: res.data?.message || "SMS failed" };
  } catch (err) {
    console.error("SMS send error:", err.message);
    return { ok: false, error: err.message };
  }
}

// ══════════════════════════════════════════════
// CONTENT MODERATION (Sightengine AI)
// ══════════════════════════════════════════════
const SIGHTENGINE_USER   = process.env.SIGHTENGINE_USER;
const SIGHTENGINE_SECRET = process.env.SIGHTENGINE_SECRET;
const MODERATION_ENABLED = !!(SIGHTENGINE_USER && SIGHTENGINE_SECRET);

// Models to check: nudity, violence, offensive
const MODELS = "nudity,violence,offensive,gore";

async function moderateImageBase64(base64Data) {
  if (!MODERATION_ENABLED) return { safe: true, demo: true };
  try {
    const formData = new URLSearchParams();
    formData.append("media", base64Data);
    formData.append("models", MODELS);
    formData.append("api_user", SIGHTENGINE_USER);
    formData.append("api_secret", SIGHTENGINE_SECRET);

    const res = await axios.post(
      "https://api.sightengine.com/1.0/check.json",
      formData.toString(),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 8000 }
    );
    return parseModerationResult(res.data);
  } catch (err) {
    console.error("Moderation error:", err.message);
    return { safe: true, error: err.message }; // Fail open to avoid blocking legitimate users
  }
}

async function moderateImageUrl(imageUrl) {
  if (!MODERATION_ENABLED) return { safe: true, demo: true };
  try {
    const res = await axios.get("https://api.sightengine.com/1.0/check.json", {
      params: { url: imageUrl, models: MODELS, api_user: SIGHTENGINE_USER, api_secret: SIGHTENGINE_SECRET },
      timeout: 8000,
    });
    return parseModerationResult(res.data);
  } catch (err) {
    console.error("Moderation URL error:", err.message);
    return { safe: true, error: err.message };
  }
}

function parseModerationResult(data) {
  if (!data) return { safe: true };

  const issues = [];
  let isSafe = true;

  // Nudity check
  if (data.nudity) {
    const nude = data.nudity;
    const nudityScore = Math.max(
      nude.raw || 0,
      nude.partial || 0,
      nude.safe ? 0 : 0
    );
    if (nudityScore > 0.5 || (nude.raw && nude.raw > 0.3)) {
      isSafe = false;
      issues.push({ type: "nudity", score: nudityScore });
    }
  }

  // Violence / gore check
  if (data.violence && data.violence.prob > 0.5) {
    isSafe = false;
    issues.push({ type: "violence", score: data.violence.prob });
  }

  if (data.gore && data.gore.prob > 0.5) {
    isSafe = false;
    issues.push({ type: "gore", score: data.gore.prob });
  }

  // Offensive check
  if (data.offensive) {
    const off = data.offensive;
    if (off.prob > 0.7) {
      isSafe = false;
      issues.push({ type: "offensive", score: off.prob });
    }
  }

  return {
    safe: isSafe,
    issues,
    confidence: issues.length ? Math.max(...issues.map(i => i.score)) : 0,
    raw: data,
  };
}

// Text moderation (basic keyword filter)
const BAD_WORDS_REGEX = /\b(sex|nude|naked|porn|xxx|fuck|dick|pussy|ass|boobs|penis|vagina|rape|molest|pedophile|child porn|cp)\b/gi;

function moderateText(text) {
  if (!text) return { safe: true };
  const found = text.match(BAD_WORDS_REGEX);
  if (found) {
    return {
      safe: false,
      issues: [{ type: "profanity", words: [...new Set(found.map(w => w.toLowerCase()))] }],
    };
  }
  return { safe: true };
}

module.exports = {
  generateOTP,
  sendEmailOTP,
  sendPhoneOTP,
  moderateImageBase64,
  moderateImageUrl,
  moderateText,
  MODERATION_ENABLED,
};
