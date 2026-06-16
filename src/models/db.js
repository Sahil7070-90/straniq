// src/models/db.js — Straniq Complete Database

const { v4: uuidv4 } = require("uuid");

class Database {
  constructor() {
    this.users        = new Map(); // id → user
    this.byEmail      = new Map(); // email → id
    this.byUsername   = new Map(); // username_lower → id
    this.byPhone      = new Map(); // phone → id
    this.otpStore     = new Map(); // key → { otp, expires, attempts }
    this.sessions     = new Map(); // sessionId → { userId, createdAt }
    this.blacklist    = new Set(); // blacklisted tokens
    this.payments     = new Map(); // orderId → payment
    this.reports      = [];
    this.bannedIPs    = new Set();
    this.moderationLog= [];

    this.stats = {
      totalConnections: 0,
      totalChats: 0,
      totalMessages: 0,
      serverStart: new Date().toISOString(),
    };
  }

  // ══════════════════════════════════════
  // USER CRUD
  // ══════════════════════════════════════
  createUser({ username, email, phone, passwordHash, country }) {
    const id = uuidv4();
    const user = {
      id,
      username: username.trim(),
      email: email ? email.toLowerCase().trim() : null,
      phone: phone ? phone.trim() : null,
      passwordHash,
      avatar: username[0].toUpperCase(),
      bio: "",
      country: country || "",
      gender: "",
      interests: [],
      joinedAt: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      totalChats: 0,
      totalMessages: 0,
      isEmailVerified: false,
      isPhoneVerified: false,
      isPremium: false,
      premiumPlan: null,
      premiumExpiry: null,
      isBanned: false,
      banReason: "",
      bannedAt: null,
      warnCount: 0,
      role: "user",
      reportCount: 0,
    };
    this.users.set(id, user);
    if (email) this.byEmail.set(email.toLowerCase(), id);
    if (phone) this.byPhone.set(phone, id);
    this.byUsername.set(username.toLowerCase(), id);
    return user;
  }

  getUserById(id)       { return this.users.get(id) || null; }
  getUserByEmail(email) { const id = this.byEmail.get(email?.toLowerCase()); return id ? this.users.get(id) : null; }
  getUserByPhone(phone) { const id = this.byPhone.get(phone); return id ? this.users.get(id) : null; }
  getUserByUsername(u)  { const id = this.byUsername.get(u?.toLowerCase()); return id ? this.users.get(id) : null; }
  emailExists(email)    { return this.byEmail.has(email?.toLowerCase()); }
  phoneExists(phone)    { return this.byPhone.has(phone); }
  usernameExists(u)     { return this.byUsername.has(u?.toLowerCase()); }
  getAllUsers()          { return [...this.users.values()]; }

  updateUser(id, updates) {
    const user = this.users.get(id);
    if (!user) return null;
    Object.assign(user, updates, { lastSeen: new Date().toISOString() });
    return user;
  }

  // ══════════════════════════════════════
  // OTP SYSTEM
  // ══════════════════════════════════════
  saveOTP(key, otp, expiresMinutes = 10) {
    this.otpStore.set(key, {
      otp: String(otp),
      expires: Date.now() + expiresMinutes * 60 * 1000,
      attempts: 0,
      maxAttempts: 5,
    });
  }

  verifyOTP(key, inputOtp) {
    const record = this.otpStore.get(key);
    if (!record) return { ok: false, reason: "OTP not found or expired. Please request a new one." };
    if (Date.now() > record.expires) {
      this.otpStore.delete(key);
      return { ok: false, reason: "OTP has expired. Please request a new one." };
    }
    record.attempts++;
    if (record.attempts > record.maxAttempts) {
      this.otpStore.delete(key);
      return { ok: false, reason: "Too many wrong attempts. Please request a new OTP." };
    }
    if (record.otp !== String(inputOtp)) {
      return { ok: false, reason: `Wrong OTP. ${record.maxAttempts - record.attempts} attempts left.` };
    }
    this.otpStore.delete(key);
    return { ok: true };
  }

  // ══════════════════════════════════════
  // PREMIUM
  // ══════════════════════════════════════
  activatePremium(userId, { plan, days, paymentId }) {
    const user = this.users.get(userId);
    if (!user) return null;
    const expiry = new Date();
    expiry.setDate(expiry.getDate() + days);
    Object.assign(user, {
      isPremium: true,
      premiumPlan: plan,
      premiumExpiry: expiry.toISOString(),
      premiumPaymentId: paymentId,
    });
    return user;
  }

  checkPremiumExpiry(userId) {
    const user = this.users.get(userId);
    if (!user?.isPremium) return false;
    if (user.premiumExpiry && new Date() > new Date(user.premiumExpiry)) {
      user.isPremium = false; user.premiumPlan = null; user.premiumExpiry = null;
      return false;
    }
    return true;
  }

  // ══════════════════════════════════════
  // BAN / WARN
  // ══════════════════════════════════════
  banUser(userId, { reason, bannedBy }) {
    const user = this.users.get(userId);
    if (!user) return null;
    Object.assign(user, { isBanned: true, banReason: reason || "Policy violation", bannedAt: new Date().toISOString(), bannedBy });
    return user;
  }

  unbanUser(userId) {
    const user = this.users.get(userId);
    if (!user) return null;
    Object.assign(user, { isBanned: false, banReason: "", bannedAt: null });
    return user;
  }

  warnUser(userId, reason) {
    const user = this.users.get(userId);
    if (!user) return null;
    user.warnCount = (user.warnCount || 0) + 1;
    if (user.warnCount >= 3) this.banUser(userId, { reason: "Auto-banned: 3 warnings", bannedBy: "system" });
    return user;
  }

  banIP(ip) { this.bannedIPs.add(ip); }
  isIPBanned(ip) { return this.bannedIPs.has(ip); }

  // ══════════════════════════════════════
  // REPORTS
  // ══════════════════════════════════════
  addReport({ reason, details, reporterName, reporterId, reportedSocketId }) {
    const report = {
      id: uuidv4(),
      reason, details: details || "",
      reporterName: reporterName || "Anonymous",
      reporterId: reporterId || null,
      reportedSocketId: reportedSocketId || null,
      status: "pending",
      createdAt: new Date().toISOString(),
      reviewedAt: null,
    };
    this.reports.push(report);
    this.stats.totalReports = (this.stats.totalReports || 0) + 1;
    return report;
  }

  deleteReport(id) {
    const idx = this.reports.findIndex(r => r.id === id);
    if (idx !== -1) this.reports.splice(idx, 1);
  }

  // ══════════════════════════════════════
  // PAYMENTS
  // ══════════════════════════════════════
  createPayment({ userId, orderId, plan, amount, currency }) {
    const p = { id: uuidv4(), userId, orderId, plan, amount, currency, status: "pending", createdAt: new Date().toISOString() };
    this.payments.set(orderId, p);
    return p;
  }

  completePayment(orderId, { paymentId, signature }) {
    const p = this.payments.get(orderId);
    if (!p) return null;
    Object.assign(p, { status: "success", paymentId, signature, completedAt: new Date().toISOString() });
    return p;
  }

  getPaymentByOrder(orderId) { return this.payments.get(orderId); }

  getAllPayments() {
    return [...this.payments.values()].sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));
  }

  // ══════════════════════════════════════
  // TOKEN BLACKLIST
  // ══════════════════════════════════════
  blacklistToken(token) { this.blacklist.add(token); }
  isBlacklisted(token)  { return this.blacklist.has(token); }

  // ══════════════════════════════════════
  // MODERATION LOG
  // ══════════════════════════════════════
  logModeration({ socketId, type, action, confidence, details }) {
    this.moderationLog.push({
      id: uuidv4(), socketId, type, action, confidence, details,
      time: new Date().toISOString(),
    });
    if (this.moderationLog.length > 500) this.moderationLog.shift();
  }

  // ══════════════════════════════════════
  // STATS
  // ══════════════════════════════════════
  incStat(key) { if (key in this.stats) this.stats[key]++; }

  getStats() {
    const all = this.getAllUsers();
    return {
      ...this.stats,
      totalUsers: this.users.size,
      totalPremium: all.filter(u => u.isPremium).length,
      totalBanned: all.filter(u => u.isBanned).length,
      totalVerified: all.filter(u => u.isEmailVerified || u.isPhoneVerified).length,
      totalPayments: this.payments.size,
      totalReports: this.reports.length,
      revenue: this.getAllPayments().filter(p => p.status === "success").reduce((s,p) => s + p.amount, 0),
    };
  }

  safeUser(u) {
    if (!u) return null;
    const { passwordHash, ...rest } = u;
    return rest;
  }
}

module.exports = new Database();
