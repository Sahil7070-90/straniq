// src/app.js — Straniq Main Server

const express    = require("express");
const http       = require("http");
const { Server } = require("socket.io");
const helmet     = require("helmet");
const cors       = require("cors");
const path       = require("path");
const db         = require("./models/db");
const { initSocket, liveState } = require("./socket/handler");

const authRoutes    = require("./routes/auth");
const paymentRoutes = require("./routes/payment");
const adminRoutes   = require("./routes/admin");
const miscRoutes    = require("./routes/misc");

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
  pingTimeout: 60000,
  pingInterval: 25000,
  maxHttpBufferSize: 1e6, // 1MB max message
});

// ── Security ──────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(cors({ origin: "*", methods: ["GET","POST","PUT","DELETE","OPTIONS"], allowedHeaders: ["Content-Type","Authorization","X-Admin-Pass"] }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.set("trust proxy", 1);

// ── Static files ──────────────────────────────────────
app.use(express.static(path.join(__dirname, "..", "public")));

// ── Logging ───────────────────────────────────────────
app.use((req, res, next) => {
  if (req.path.startsWith("/api") && !req.path.includes("admin"))
    console.log(`[${new Date().toISOString().slice(11,19)}] ${req.method} ${req.path}`);
  next();
});

// ══════════════════════════════════════════════════════
// API ROUTES
// ══════════════════════════════════════════════════════

// Health
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", app: "Straniq", online: liveState.onlineCount, uptime: process.uptime() });
});

// Auth — /api/register, /api/login, /api/me, etc.
app.use("/api", authRoutes);

// Payment — /api/payment/*
app.use("/api/payment", paymentRoutes);

// Misc — /api/report, /api/stats/public
app.use("/api", miscRoutes);

// ── HIDDEN ADMIN PANEL ────────────────────────────────
// URL: /<ADMIN_SECRET_PATH> — set in .env, never expose publicly
const ADMIN_PATH = process.env.ADMIN_SECRET_PATH || "x-admin-9k2m";
console.log(`\n🔐 Admin path: /${ADMIN_PATH}`);
console.log(`   Keep this SECRET — never share publicly!\n`);

// Serve admin HTML at secret path
app.get(`/${ADMIN_PATH}`, (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "admin.html"));
});

// Admin API at secret path
app.use(`/api/${ADMIN_PATH}`, adminRoutes);

// ── Pages ─────────────────────────────────────────────
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "..", "public", "index.html")));

// Catch unknown admin paths — return 404 (don't reveal admin exists)
app.use("/api/admin", (req, res) => res.status(404).json({ error: "Not found." }));

// 404 API
app.use("/api/*", (req, res) => res.status(404).json({ error: "API endpoint not found." }));

// Catch-all → frontend
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "..", "public", "index.html")));

// ── Error handler ─────────────────────────────────────
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.message);
  res.status(err.status || 500).json({ error: "Something went wrong." });
});

// ── Socket ────────────────────────────────────────────
initSocket(io);

// ── Start ─────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("═══════════════════════════════════════");
  console.log(`⚡  Straniq v1.0 — Production Ready`);
  console.log(`🌐  http://localhost:${PORT}`);
  console.log(`🔐  Admin: http://localhost:${PORT}/${ADMIN_PATH}`);
  console.log(`📡  Health: http://localhost:${PORT}/api/health`);
  console.log("═══════════════════════════════════════");
});

process.on("SIGTERM", () => { server.close(() => process.exit(0)); });
process.on("uncaughtException", (e) => console.error("Uncaught:", e));
process.on("unhandledRejection", (r) => console.error("Rejection:", r));

module.exports = { app, server, io };
