// src/middleware/auth.js

const jwt        = require("jsonwebtoken");
const rateLimit  = require("express-rate-limit");
const db         = require("../models/db");

const JWT_SECRET = process.env.JWT_SECRET || "straniq_dev_secret_change_in_prod";

const authenticate = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer "))
    return res.status(401).json({ error: "Authentication required." });
  const token = auth.split(" ")[1];
  if (db.isBlacklisted(token))
    return res.status(401).json({ error: "Session expired. Please login again." });
  try {
    const dec = jwt.verify(token, JWT_SECRET);
    const user = db.getUserById(dec.id);
    if (!user)  return res.status(401).json({ error: "Account not found." });
    if (user.isBanned) return res.status(403).json({ error: `Account suspended: ${user.banReason}` });
    db.checkPremiumExpiry(user.id);
    req.user = user; req.token = token;
    next();
  } catch (e) {
    const msg = e.name === "TokenExpiredError" ? "Session expired. Please login again." : "Invalid token.";
    return res.status(401).json({ error: msg });
  }
};

const optionalAuth = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return next();
  const token = auth.split(" ")[1];
  try {
    const dec = jwt.verify(token, JWT_SECRET);
    const user = db.getUserById(dec.id);
    if (user && !user.isBanned) { db.checkPremiumExpiry(user.id); req.user = user; req.token = token; }
  } catch {}
  next();
};

const requireAdmin = (req, res, next) => {
  const pass = req.headers["x-admin-pass"] || req.body?.adminPassword;
  if (!pass || pass !== (process.env.ADMIN_PASSWORD || "straniq-admin"))
    return res.status(401).json({ error: "Unauthorized." });
  next();
};

const requirePremium = (req, res, next) => {
  if (!req.user?.isPremium)
    return res.status(403).json({ error: "Premium subscription required.", code: "PREMIUM_REQUIRED" });
  next();
};

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: "Too many attempts. Try again in 15 minutes." },
  standardHeaders: true, legacyHeaders: false,
});
const otpLimiter = rateLimit({
  windowMs: 60 * 1000, max: 3,
  message: { error: "Too many OTP requests. Wait 1 minute." },
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, max: 60,
  message: { error: "Too many requests. Slow down." },
});
const paymentLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, max: 5,
  message: { error: "Too many payment attempts." },
});

const makeToken = (user) =>
  jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: "30d" });

module.exports = { authenticate, optionalAuth, requireAdmin, requirePremium, authLimiter, otpLimiter, apiLimiter, paymentLimiter, makeToken };
