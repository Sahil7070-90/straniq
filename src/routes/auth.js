// src/routes/auth.js — Complete Auth with OTP Verification

const router  = require("express").Router();
const bcrypt  = require("bcryptjs");
const { body, validationResult } = require("express-validator");
const db      = require("../models/db");
const { authenticate, authLimiter, otpLimiter, makeToken } = require("../middleware/auth");
const { generateOTP, sendEmailOTP, sendPhoneOTP } = require("../services");

// ── Validation ────────────────────────────────────────────
const regRules = [
  body("username").trim().isLength({min:3,max:20}).withMessage("Username must be 3-20 characters.")
    .matches(/^[a-zA-Z0-9_]+$/).withMessage("Only letters, numbers and underscores allowed."),
  body("email").optional({checkFalsy:true}).isEmail().normalizeEmail().withMessage("Invalid email."),
  body("phone").optional({checkFalsy:true}).matches(/^(\+91|91)?[6-9]\d{9}$/).withMessage("Invalid Indian phone number."),
  body("password").isLength({min:6,max:72}).withMessage("Password must be 6-72 characters."),
];

// ══════════════════════════════════════════════════════════
// POST /api/register — Step 1: Create account (unverified)
// ══════════════════════════════════════════════════════════
router.post("/register", authLimiter, regRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { username, email, phone, password } = req.body;
  if (!email && !phone) return res.status(400).json({ error: "Email or phone number is required." });

  try {
    if (email && db.emailExists(email))    return res.status(400).json({ error: "This email is already registered." });
    if (phone && db.phoneExists(phone))    return res.status(400).json({ error: "This phone number is already registered." });
    if (db.usernameExists(username))       return res.status(400).json({ error: "This username is already taken." });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = db.createUser({ username, email, phone, passwordHash });
    const token = makeToken(user);

    res.status(201).json({
      success: true,
      message: "Account created! Please verify your email or phone.",
      token,
      user: db.safeUser(user),
      needsVerification: true,
      verifyVia: email ? "email" : "phone",
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

// ══════════════════════════════════════════════════════════
// POST /api/send-email-otp
// ══════════════════════════════════════════════════════════
router.post("/send-email-otp", otpLimiter, authenticate, async (req, res) => {
  const user = req.user;
  if (!user.email) return res.status(400).json({ error: "No email linked to this account." });
  if (user.isEmailVerified) return res.status(400).json({ error: "Email already verified." });

  const otp = generateOTP();
  db.saveOTP(`email:${user.email}`, otp, 10);

  const result = await sendEmailOTP(user.email, otp, user.username);
  if (!result.ok) return res.status(500).json({ error: "Failed to send email. Check email config." });

  res.json({
    success: true,
    message: result.demo
      ? `[DEV MODE] OTP: ${otp} (Check server console)`
      : `Verification code sent to ${user.email.replace(/(.{2}).*(@.*)/, "$1***$2")}`,
    demo: result.demo || false,
    // Only return OTP in dev mode
    ...(result.demo && { otp }),
  });
});

// ══════════════════════════════════════════════════════════
// POST /api/verify-email-otp
// ══════════════════════════════════════════════════════════
router.post("/verify-email-otp", authenticate, [
  body("otp").isLength({min:6,max:6}).withMessage("OTP must be 6 digits.").isNumeric(),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { otp } = req.body;
  const user = req.user;
  if (!user.email) return res.status(400).json({ error: "No email to verify." });

  const result = db.verifyOTP(`email:${user.email}`, otp);
  if (!result.ok) return res.status(400).json({ error: result.reason });

  db.updateUser(user.id, { isEmailVerified: true });
  const newToken = makeToken(db.getUserById(user.id));
  res.json({ success: true, message: "Email verified successfully! ✅", token: newToken, user: db.safeUser(db.getUserById(user.id)) });
});

// ══════════════════════════════════════════════════════════
// POST /api/send-phone-otp
// ══════════════════════════════════════════════════════════
router.post("/send-phone-otp", otpLimiter, authenticate, async (req, res) => {
  const user = req.user;
  if (!user.phone) return res.status(400).json({ error: "No phone linked to this account." });
  if (user.isPhoneVerified) return res.status(400).json({ error: "Phone already verified." });

  const otp = generateOTP();
  db.saveOTP(`phone:${user.phone}`, otp, 10);

  const result = await sendPhoneOTP(user.phone, otp);
  if (!result.ok) return res.status(500).json({ error: "Failed to send SMS. Check Fast2SMS config." });

  res.json({
    success: true,
    message: result.demo
      ? `[DEV MODE] OTP: ${otp} (Check server console)`
      : `OTP sent to ${user.phone.replace(/(\d{2})\d{6}(\d{2})/, "$1xxxxxx$2")}`,
    demo: result.demo || false,
    ...(result.demo && { otp }),
  });
});

// ══════════════════════════════════════════════════════════
// POST /api/verify-phone-otp
// ══════════════════════════════════════════════════════════
router.post("/verify-phone-otp", authenticate, [
  body("otp").isLength({min:6,max:6}).isNumeric(),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { otp } = req.body;
  const user = req.user;
  if (!user.phone) return res.status(400).json({ error: "No phone to verify." });

  const result = db.verifyOTP(`phone:${user.phone}`, otp);
  if (!result.ok) return res.status(400).json({ error: result.reason });

  db.updateUser(user.id, { isPhoneVerified: true });
  const newToken = makeToken(db.getUserById(user.id));
  res.json({ success: true, message: "Phone verified successfully! ✅", token: newToken, user: db.safeUser(db.getUserById(user.id)) });
});

// ══════════════════════════════════════════════════════════
// POST /api/login
// ══════════════════════════════════════════════════════════
router.post("/login", authLimiter, [
  body("identifier").notEmpty().withMessage("Email or phone required."),
  body("password").notEmpty().withMessage("Password required."),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { identifier, password } = req.body;
  // Find by email or phone
  const user = db.getUserByEmail(identifier) || db.getUserByPhone(identifier) || db.getUserByUsername(identifier);

  if (!user) return res.status(400).json({ error: "No account found. Please check your email/phone." });
  if (user.isBanned) return res.status(403).json({ error: `Account suspended: ${user.banReason}` });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(400).json({ error: "Incorrect password. Please try again." });

  db.checkPremiumExpiry(user.id);
  db.updateUser(user.id, { lastSeen: new Date().toISOString() });
  const token = makeToken(user);

  res.json({
    success: true,
    message: `Welcome back, ${user.username}!`,
    token,
    user: db.safeUser(user),
    isVerified: user.isEmailVerified || user.isPhoneVerified,
  });
});

// ══════════════════════════════════════════════════════════
// POST /api/forgot-password — Send reset OTP
// ══════════════════════════════════════════════════════════
router.post("/forgot-password", otpLimiter, [
  body("identifier").notEmpty(),
], async (req, res) => {
  const { identifier } = req.body;
  const user = db.getUserByEmail(identifier) || db.getUserByPhone(identifier);
  // Always return success (don't reveal if email exists)
  if (!user) return res.json({ success: true, message: "If account exists, OTP has been sent." });

  const otp = generateOTP();
  db.saveOTP(`reset:${user.id}`, otp, 15);

  if (user.email) await sendEmailOTP(user.email, otp, user.username);
  else if (user.phone) await sendPhoneOTP(user.phone, otp);

  res.json({ success: true, message: "If account exists, a reset OTP has been sent.", userId: user.id });
});

// ══════════════════════════════════════════════════════════
// POST /api/reset-password
// ══════════════════════════════════════════════════════════
router.post("/reset-password", [
  body("userId").notEmpty(),
  body("otp").isLength({min:6,max:6}).isNumeric(),
  body("newPassword").isLength({min:6}).withMessage("Password min 6 characters."),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { userId, otp, newPassword } = req.body;
  const result = db.verifyOTP(`reset:${userId}`, otp);
  if (!result.ok) return res.status(400).json({ error: result.reason });

  const hash = await bcrypt.hash(newPassword, 12);
  db.updateUser(userId, { passwordHash: hash });
  res.json({ success: true, message: "Password reset successfully. Please login." });
});

// ══════════════════════════════════════════════════════════
// POST /api/logout
// ══════════════════════════════════════════════════════════
router.post("/logout", authenticate, (req, res) => {
  db.blacklistToken(req.token);
  res.json({ success: true, message: "Logged out successfully." });
});

// ══════════════════════════════════════════════════════════
// GET /api/me
// ══════════════════════════════════════════════════════════
router.get("/me", authenticate, (req, res) => {
  db.checkPremiumExpiry(req.user.id);
  res.json({ user: db.safeUser(req.user) });
});

// ══════════════════════════════════════════════════════════
// PUT /api/profile
// ══════════════════════════════════════════════════════════
router.put("/profile", authenticate, [
  body("bio").optional().isLength({max:200}),
  body("gender").optional().isIn(["male","female","other",""]),
  body("interests").optional().isArray({max:10}),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
  const { bio, gender, country, interests } = req.body;
  const updates = {};
  if (bio !== undefined)       updates.bio = bio.trim().slice(0, 200);
  if (gender !== undefined)    updates.gender = gender;
  if (country !== undefined)   updates.country = country;
  if (interests !== undefined) updates.interests = interests.slice(0, 10);
  const user = db.updateUser(req.user.id, updates);
  res.json({ success: true, user: db.safeUser(user) });
});

// ══════════════════════════════════════════════════════════
// PUT /api/change-password
// ══════════════════════════════════════════════════════════
router.put("/change-password", authenticate, [
  body("currentPassword").notEmpty(),
  body("newPassword").isLength({min:6}).withMessage("Password min 6 characters."),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
  const { currentPassword, newPassword } = req.body;
  const valid = await bcrypt.compare(currentPassword, req.user.passwordHash);
  if (!valid) return res.status(400).json({ error: "Current password is incorrect." });
  const hash = await bcrypt.hash(newPassword, 12);
  db.updateUser(req.user.id, { passwordHash: hash });
  db.blacklistToken(req.token);
  res.json({ success: true, message: "Password changed. Please login again." });
});

module.exports = router;
