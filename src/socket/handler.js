// src/socket/handler.js — Complete Socket Handler with Moderation

const jwt = require("jsonwebtoken");
const db  = require("../models/db");
const { moderateImageBase64, moderateText, MODERATION_ENABLED } = require("../services");

const JWT_SECRET = process.env.JWT_SECRET || "straniq_dev_secret_change_in_prod";

const liveState = {
  onlineCount:   0,
  waitingVideo:  null,
  waitingText:   null,
};

function initSocket(io) {
  // ── IP ban middleware ─────────────────────────────────
  io.use((socket, next) => {
    const ip = socket.handshake.headers["x-forwarded-for"]?.split(",")[0].trim() || socket.conn.remoteAddress;
    if (db.isIPBanned(ip)) return next(new Error("Access denied."));
    socket.clientIP = ip;
    next();
  });

  io.on("connection", (socket) => {
    liveState.onlineCount++;
    db.incStat("totalConnections");
    broadcastOnline(io);
    console.log(`[+] ${socket.id} | Online: ${liveState.onlineCount}`);

    // ── Auth ──────────────────────────────────────────
    socket.on("auth", (token) => {
      if (!token || typeof token !== "string") return;
      try {
        if (db.isBlacklisted(token)) return socket.emit("auth-error", "Session expired.");
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = db.getUserById(decoded.id);
        if (!user) return socket.emit("auth-error", "Account not found.");
        if (user.isBanned) {
          socket.emit("banned", { reason: user.banReason });
          socket.disconnect(true);
          return;
        }
        db.checkPremiumExpiry(user.id);
        socket.user = user;
        socket.isPremium = user.isPremium;
        socket.isVerified = user.isEmailVerified || user.isPhoneVerified;
        socket.emit("auth-success", {
          username: user.username,
          isPremium: user.isPremium,
          isVerified: socket.isVerified,
        });
        db.updateUser(user.id, { lastSeen: new Date().toISOString() });
      } catch {
        socket.emit("auth-error", "Session expired. Please login again.");
      }
    });

    // ── Guest ─────────────────────────────────────────
    socket.on("join-guest", (name) => {
      const clean = String(name || "Guest").replace(/[^a-zA-Z0-9_]/g, "").slice(0, 20) || "Guest";
      socket.user = { id: "g_" + socket.id, username: clean, isGuest: true };
      socket.isPremium = false;
      socket.isVerified = false;
    });

    // ── Find Stranger ──────────────────────────────────
    socket.on("find-stranger", (payload) => {
      if (!socket.user) {
        socket.emit("error-msg", "Please login or join as guest.");
        return;
      }
      const mode = (payload?.mode === "video" || payload?.mode === "text") ? payload.mode : "text";
      socket.chatMode = mode;
      socket.interests = payload?.interests || [];

      dropPartner(socket, true);
      cleanStaleQueues();
      matchOrWait(socket, io, mode);
    });

    // ── WebRTC Signaling ──────────────────────────────
    socket.on("rtc-offer",  (d) => { if (socket.partner?.connected && d) socket.partner.emit("rtc-offer",  d); });
    socket.on("rtc-answer", (d) => { if (socket.partner?.connected && d) socket.partner.emit("rtc-answer", d); });
    socket.on("rtc-ice",    (d) => {
      if (socket.partner?.connected && d) {
        try { socket.partner.emit("rtc-ice", d); } catch {}
      }
    });

    // ── Video Frame Moderation (snapshot check) ───────
    socket.on("video-snapshot", async (base64Data) => {
      if (!base64Data || typeof base64Data !== "string") return;
      if (base64Data.length > 500000) return; // Max ~375KB

      try {
        const result = await moderateImageBase64(base64Data);
        if (!result.safe && !result.demo) {
          db.logModeration({
            socketId: socket.id,
            type: "video",
            action: "warned",
            confidence: result.confidence || 0,
            details: result.issues?.map(i => i.type).join(", "),
          });

          socket.emit("content-warning", {
            message: "Inappropriate content detected. Please follow our community guidelines.",
            type: result.issues?.[0]?.type || "policy",
          });

          // Auto-warn user account
          if (socket.user && !socket.user.isGuest) {
            db.warnUser(socket.user.id, "Inappropriate video content: " + (result.issues?.map(i => i.type).join(", ")));
            const user = db.getUserById(socket.user.id);
            if (user?.isBanned) {
              socket.emit("banned", { reason: user.banReason });
              dropPartner(socket, true);
              socket.disconnect(true);
            }
          }

          // Notify partner — connection cut
          if (socket.partner) {
            socket.partner.emit("partner-left");
            socket.partner.partner = null;
            socket.partner = null;
          }
        }
      } catch (e) {
        console.error("Snapshot moderation error:", e.message);
      }
    });

    // ── Chat Message with Text Moderation ─────────────
    socket.on("chat-msg", (msg) => {
      if (!socket.partner?.connected || typeof msg !== "string") return;
      const clean = msg.trim().slice(0, 500);
      if (!clean) return;

      // Text moderation
      const modResult = moderateText(clean);
      if (!modResult.safe) {
        socket.emit("msg-blocked", {
          message: "Your message was blocked. It contains inappropriate content.",
          words: modResult.issues?.[0]?.words,
        });
        db.logModeration({
          socketId: socket.id,
          type: "text",
          action: "blocked",
          confidence: 1,
          details: modResult.issues?.[0]?.words?.join(", "),
        });

        if (socket.user && !socket.user.isGuest) {
          db.warnUser(socket.user.id, "Inappropriate text: " + modResult.issues?.[0]?.words?.join(", "));
        }
        return;
      }

      socket.partner.emit("chat-msg", {
        text: clean,
        name: socket.user?.username || "Stranger",
        time: new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }),
      });

      if (socket.user && !socket.user.isGuest) {
        const u = db.getUserById(socket.user.id);
        if (u) u.totalMessages++;
      }
      db.incStat("totalMessages");
    });

    // ── Typing ────────────────────────────────────────
    socket.on("typing", (v) => {
      if (socket.partner?.connected) socket.partner.emit("partner-typing", !!v);
    });

    // ── Skip ──────────────────────────────────────────
    socket.on("skip", () => {
      dropPartner(socket, true);
      if (liveState.waitingVideo === socket) liveState.waitingVideo = null;
      if (liveState.waitingText  === socket) liveState.waitingText  = null;
      socket.emit("skipped");
    });

    // ── Disconnect ────────────────────────────────────
    socket.on("disconnect", (reason) => {
      liveState.onlineCount = Math.max(0, liveState.onlineCount - 1);
      broadcastOnline(io);
      dropPartner(socket, true);
      if (liveState.waitingVideo === socket) liveState.waitingVideo = null;
      if (liveState.waitingText  === socket) liveState.waitingText  = null;
      if (socket.user && !socket.user.isGuest) {
        db.updateUser(socket.user.id, { lastSeen: new Date().toISOString() });
      }
      console.log(`[-] ${socket.id} (${reason}) | Online: ${liveState.onlineCount}`);
    });
  });
}

// ── Matching ──────────────────────────────────────────
function matchOrWait(socket, io, mode) {
  const key = mode === "video" ? "waitingVideo" : "waitingText";
  const waiting = liveState[key];

  if (waiting && waiting.id !== socket.id && waiting.connected) {
    startMatch(socket, waiting, mode);
    liveState[key] = null;
  } else {
    liveState[key] = socket;
    socket.emit("waiting");
  }
}

function startMatch(a, b, mode) {
  db.incStat("totalChats");
  a.partner = b; b.partner = a;
  const aN = a.user?.username || "Stranger";
  const bN = b.user?.username || "Stranger";

  a.emit("matched", { mode, partnerName: bN, partnerIsPremium: b.isPremium || false, role: "caller" });
  b.emit("matched", { mode, partnerName: aN, partnerIsPremium: a.isPremium || false, role: "receiver" });

  [a, b].forEach(sock => {
    if (sock.user && !sock.user.isGuest) {
      const u = db.getUserById(sock.user.id);
      if (u) u.totalChats++;
    }
  });
  console.log(`[MATCH] ${aN} ↔ ${bN} (${mode})`);
}

function dropPartner(socket, notify = false) {
  if (socket.partner) {
    if (notify && socket.partner.connected) socket.partner.emit("partner-left");
    socket.partner.partner = null;
    socket.partner = null;
  }
}

function cleanStaleQueues() {
  if (liveState.waitingVideo && !liveState.waitingVideo.connected) liveState.waitingVideo = null;
  if (liveState.waitingText  && !liveState.waitingText.connected)  liveState.waitingText  = null;
}

function broadcastOnline(io) {
  io.emit("online-count", liveState.onlineCount);
}

module.exports = { initSocket, liveState };
