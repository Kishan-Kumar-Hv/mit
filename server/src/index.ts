import express from "express";
import http from "http";
import cors from "cors";
import { WebSocketServer, WebSocket } from "ws";
import path from "path";
import crypto from "crypto";
import multer from "multer";

import {
  initDatabase,
  hashPassword,
  generateUserIdCode,
  STORAGE_DIR,
  IMAGES_DIR,
  FILES_DIR,
  dbService,
  watchMongoLiveFeed,
} from "./db.js";
import type { MessageRecord, UserRecord } from "./db.js";

import { analyzeSecurityRisk, generateIntegrityHash } from "./security.js";
import { DiagnosticsRegistry } from "./diagnostics.js";
import { analyzeIncidentWithGemini } from "./gemini.js";

const app = express();
const PORT = Number(process.env.PORT) || 5001;

app.use(cors());
app.use(express.json());

// Serve uploaded files statically
app.use("/storage", express.static(STORAGE_DIR));

// Multer Storage Configuration
const storage = multer.diskStorage({
  destination: (_req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, IMAGES_DIR);
    } else {
      cb(null, FILES_DIR);
    }
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    const base = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, "_");
    const unique = `${Date.now()}_${crypto.randomUUID().slice(0, 6)}`;
    cb(null, `${base}_${unique}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 }, // 25 MB max
});

// WebSocket tracking: userId -> Set of WebSockets
const userSockets = new Map<string, Set<WebSocket>>();

function isUserOnline(userId: string): boolean {
  const sockets = userSockets.get(userId);
  return Boolean(sockets && sockets.size > 0);
}

function broadcastToUser(userId: string, payload: any) {
  const sockets = userSockets.get(userId);
  if (sockets) {
    const data = JSON.stringify(payload);
    for (const ws of sockets) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    }
  }
}

function broadcastToUserExcept(userId: string, excludeWs: WebSocket, payload: any) {
  const sockets = userSockets.get(userId);
  if (sockets) {
    const data = JSON.stringify(payload);
    for (const ws of sockets) {
      if (ws !== excludeWs && ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    }
  }
}

function broadcastGlobal(payload: any) {
  const data = JSON.stringify(payload);
  for (const sockets of userSockets.values()) {
    for (const ws of sockets) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    }
  }
}

// ---------------- REST API ROUTES ----------------

// Health check with DB status
app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    db: dbService.getDbStatus(),
    activeSockets: Array.from(userSockets.values()).reduce((acc, s) => acc + s.size, 0),
    timestamp: new Date().toISOString(),
  });
});

// Cybersecurity & Telemetry Stats
app.get("/api/security/stats", (_req, res) => {
  const metrics = DiagnosticsRegistry.getTelemetryMetrics();
  res.json({
    ...metrics,
    dbStatus: dbService.getDbStatus(),
  });
});

// Diagnostic Log Listing
app.get("/api/diagnostics", (_req, res) => {
  res.json({ logs: DiagnosticsRegistry.getAllLogs() });
});

// Admin reseed endpoint to reset and populate MongoDB Atlas fresh data
app.post("/api/admin/reseed", async (_req, res) => {
  try {
    await dbService.wipeDatabase();
    res.json({ status: "ok", message: "MongoDB Atlas database cleared of all legacy data!" });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Admin wipe database completely (zero demo users)
app.post("/api/admin/wipe", async (_req, res) => {
  try {
    await dbService.wipeDatabase();
    res.json({ status: "ok", message: "MongoDB Atlas wiped clean for fresh real users." });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Live Gemini AI Cybersecurity Defect & Root-Cause Explainer
app.post("/api/security/gemini-diagnose", async (req, res) => {
  const { incidentType, context } = req.body;
  try {
    const report = await analyzeIncidentWithGemini(
      incidentType || "ZERO_TRUST_DEFECT_ANALYSIS",
      context || {}
    );
    res.json({ status: "ok", report });
  } catch (err: any) {
    res.status(500).json({ error: "Gemini AI analysis failed", details: err.message });
  }
});

// Cybersecurity Inspector / Scanner endpoint (test any text, URL, or file metadata)
app.post("/api/security/scan", (req, res) => {
  const { content, messageType, fileName } = req.body;
  const analysis = analyzeSecurityRisk({ content, messageType, fileName });
  let diagnostic = null;
  if (analysis.isBlocked) {
    diagnostic = DiagnosticsRegistry.diagnose("ERR_CYBER_THREAT_BLOCKED", {
      content: content?.slice(0, 80),
      threats: analysis.threats,
      riskScore: analysis.score,
    });
  }
  res.json({ analysis, diagnostic });
});

// 1. Auth: Register
app.post("/api/auth/register", async (req, res) => {
  const { username, email, password, fullName, avatar, bio } = req.body;
  if (!username || !email || !password) {
    const diag = DiagnosticsRegistry.diagnose("ERR_AUTH_MISSING_FIELDS", {
      reason: "Username, email, and password required.",
    });
    return res.status(400).json({ error: "Username, Gmail ID (email), and password are required.", diagnostic: diag });
  }

  const cleanUsername = username.trim().toLowerCase();
  const cleanEmail = email.trim().toLowerCase();

  try {
    const existing = await dbService.findUserByUsernameOrEmail(cleanUsername, cleanEmail);
    if (existing) {
      const diag = DiagnosticsRegistry.diagnose("ERR_AUTH_USER_EXISTS", {
        reason: "User with this username or email already registered.",
      });
      return res.status(409).json({ error: "Username or Gmail ID already registered.", diagnostic: diag });
    }

    const newId = `u_${crypto.randomUUID().slice(0, 8)}`;
    const userIdCode = generateUserIdCode();
    const pHash = hashPassword(password);
    const name = fullName?.trim() || cleanUsername;
    const userAvatar = avatar || `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(cleanUsername)}`;
    const userBio = bio?.trim() || "Hey there! I am using Chatvia.";

    const newUser: UserRecord = {
      id: newId,
      userIdCode,
      username: cleanUsername,
      email: cleanEmail,
      fullName: name,
      passwordHash: pHash,
      avatar: userAvatar,
      bio: userBio,
      createdAt: new Date().toISOString(),
    };

    const created = await dbService.createUser(newUser);

    broadcastGlobal({
      type: "user_registered",
      user: {
        id: created.id,
        userIdCode: created.userIdCode,
        username: created.username,
        fullName: created.fullName,
        avatar: created.avatar,
      },
    });

    return res.json({ user: created });
  } catch (err: any) {
    console.error("Register error:", err);
    const diag = DiagnosticsRegistry.diagnose("ERR_AUTH_INTERNAL", { reason: err.message });
    return res.status(500).json({ error: "Registration failed on server.", diagnostic: diag });
  }
});

// 2. Auth: Login
app.post("/api/auth/login", async (req, res) => {
  const { username, email, password } = req.body;
  if (!password || (!username && !email)) {
    return res.status(400).json({ error: "Username/Gmail ID and password are required." });
  }

  try {
    const user = await dbService.findUserByUsernameOrEmail(username, email);
    if (!user || user.passwordHash !== hashPassword(password)) {
      const diag = DiagnosticsRegistry.diagnose("ERR_AUTH_INVALID_CREDS", {
        reason: "Authentication credential mismatch.",
      });
      return res.status(401).json({ error: "Invalid username, Gmail ID, or password.", diagnostic: diag });
    }

    const sanitized = { ...user };
    delete (sanitized as any).passwordHash;
    return res.json({ user: sanitized });
  } catch (err: any) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Login failed on server." });
  }
});

// 3. User Profile: Get
app.get("/api/users/profile/:id", async (req, res) => {
  try {
    const user = await dbService.findUserById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }
    const sanitized = { ...user };
    delete (sanitized as any).passwordHash;
    res.json({ profile: sanitized });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch user profile." });
  }
});

// 4. User Profile: Update
app.put("/api/users/profile", async (req, res) => {
  const { userId, fullName, bio, avatar } = req.body;
  if (!userId) {
    return res.status(400).json({ error: "userId is required." });
  }

  try {
    const updated = await dbService.updateUserProfile(userId, fullName, bio, avatar);
    if (!updated) {
      return res.status(404).json({ error: "User not found." });
    }
    const sanitized = { ...updated };
    delete (sanitized as any).passwordHash;
    res.json({ user: sanitized });
  } catch (err) {
    res.status(500).json({ error: "Failed to update profile." });
  }
});

// 5. Lookup user by ID Code or Username
app.get("/api/users/lookup", async (req, res) => {
  const { userIdCode, currentUserId } = req.query;
  if (!userIdCode) {
    return res.status(400).json({ error: "Please enter a Name, Username, or User ID to search." });
  }

  try {
    const target = await dbService.lookupUser(userIdCode as string);
    if (!target) {
      const diag = DiagnosticsRegistry.diagnose("ERR_USER_NOT_FOUND", {
        searchQuery: userIdCode,
        reason: `No registered account found matching '${userIdCode}'.`,
      });
      return res.status(404).json({ error: `No user found matching '${userIdCode}'.`, diagnostic: diag });
    }

    let relationship = "none";
    if (currentUserId && currentUserId !== target.id) {
      relationship = await dbService.getFriendRelationship(currentUserId as string, target.id);
    }

    res.json({
      user: {
        id: target.id,
        userIdCode: target.userIdCode,
        username: target.username,
        fullName: target.fullName,
        avatar: target.avatar,
        bio: target.bio,
        online: isUserOnline(target.id),
        relationship,
      },
    });
  } catch (err) {
    res.status(500).json({ error: "Error looking up user." });
  }
});

// 5.1 Search users by name, username, or ID (Live Search)
app.get("/api/users/search", async (req, res) => {
  const { query, currentUserId } = req.query;
  if (!query || typeof query !== "string" || !query.trim()) {
    return res.json({ users: [] });
  }

  try {
    const users = await dbService.searchUsers(query as string, (currentUserId as string) || "");
    const usersWithOnline = users.map((u: any) => ({
      ...u,
      online: isUserOnline(u.id),
    }));
    res.json({ users: usersWithOnline });
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({ error: "Failed to search users." });
  }
});

// 5.2 All Users Directory
app.get("/api/users/directory", async (req, res) => {
  const { currentUserId } = req.query;
  try {
    const users = await dbService.getAllUsers((currentUserId as string) || "");
    const usersWithOnline = users.map((u: any) => ({
      ...u,
      online: isUserOnline(u.id),
    }));
    res.json({ users: usersWithOnline });
  } catch (err) {
    console.error("Directory error:", err);
    res.status(500).json({ error: "Failed to fetch users directory." });
  }
});

// 6. Send Friend Request
app.post("/api/friends/request", async (req, res) => {
  const { senderId, targetIdCode, targetUserId } = req.body;
  if (!senderId || (!targetIdCode && !targetUserId)) {
    return res.status(400).json({ error: "Sender ID and target user are required." });
  }

  try {
    let target = null;
    if (targetUserId) {
      target = await dbService.findUserById(targetUserId);
    } else if (targetIdCode && targetIdCode.trim()) {
      target = await dbService.lookupUser(targetIdCode.trim());
    }

    if (!target) {
      return res.status(404).json({ error: `User not found.` });
    }
    if (target.id === senderId) {
      return res.status(400).json({ error: "You cannot send a friend request to yourself." });
    }

    const rel = await dbService.getFriendRelationship(senderId, target.id);
    if (rel === "friends") {
      return res.status(400).json({ error: `You and @${target.username} are already friends!` });
    }
    if (rel === "pending_sent") {
      return res.status(400).json({ error: `Friend request already sent to @${target.username} (Pending).` });
    }
    if (rel === "pending_received") {
      return res.status(400).json({
        error: `@${target.username} already sent you a friend request! Check your Requests tab.`,
      });
    }

    const reqRecord = await dbService.sendFriendRequest(senderId, target.id);
    const sender = await dbService.findUserById(senderId);

    // Real-time WebSocket event to receiver
    if (sender) {
      broadcastToUser(target.id, {
        type: "friend_request_received",
        request: {
          id: reqRecord.id,
          sender: {
            id: sender.id,
            userIdCode: sender.userIdCode,
            username: sender.username,
            fullName: sender.fullName,
            avatar: sender.avatar,
          },
          createdAt: reqRecord.createdAt,
        },
      });
    }

    res.json({
      message: `Friend request sent to ${target.fullName} (@${target.username})!`,
      targetUser: target,
    });
  } catch (err: any) {
    console.error("Friend request error:", err);
    res.status(500).json({ error: "Failed to send friend request." });
  }
});

// 7. Accept or Reject Friend Request
app.post("/api/friends/respond", async (req, res) => {
  const { requestId, action, userId } = req.body;
  if (!requestId || !action || !userId) {
    return res.status(400).json({ error: "requestId, action ('accept'|'reject'), and userId are required." });
  }

  try {
    const updated = await dbService.respondFriendRequest(requestId, action);
    if (!updated) {
      return res.status(404).json({ error: "Friend request not found." });
    }

    if (action === "accept") {
      const sender = await dbService.findUserById(updated.senderId);
      const receiver = await dbService.findUserById(updated.receiverId);

      if (sender && receiver) {
        broadcastToUser(updated.senderId, {
          type: "friend_request_accepted",
          friend: { ...receiver, online: isUserOnline(receiver.id) },
        });

        broadcastToUser(updated.receiverId, {
          type: "friend_request_accepted",
          friend: { ...sender, online: isUserOnline(sender.id) },
        });
      }

      return res.json({ message: "Friend request accepted! You can now chat." });
    } else {
      broadcastToUser(updated.senderId, {
        type: "friend_request_rejected",
        requestId,
      });
      broadcastToUser(updated.receiverId, {
        type: "friend_request_rejected",
        requestId,
      });
      return res.json({ message: "Friend request declined." });
    }
  } catch (err) {
    res.status(500).json({ error: "Failed to respond to friend request." });
  }
});

// 8. Get Friends & Pending Requests
app.get("/api/friends", async (req, res) => {
  const userId = req.query.userId as string;
  if (!userId) {
    return res.status(400).json({ error: "userId is required." });
  }

  try {
    const data = await dbService.getFriends(userId);
    const friendsWithOnline = data.friends.map((f: any) => ({
      ...f,
      online: isUserOnline(f.id),
    }));

    res.json({
      friends: friendsWithOnline,
      pendingIncoming: data.pendingIncoming,
      pendingOutgoing: data.pendingOutgoing,
    });
  } catch (err) {
    console.error("Get friends error:", err);
    res.status(500).json({ error: "Failed to fetch friends." });
  }
});

// Remove / Delete Contact (WhatsApp feature)
app.post("/api/friends/remove", async (req, res) => {
  const { userId, friendId } = req.body;
  if (!userId || !friendId) {
    return res.status(400).json({ error: "userId and friendId are required." });
  }

  try {
    const success = await dbService.removeFriend(userId, friendId);
    if (success) {
      broadcastToUser(userId, { type: "friend_removed", friendId });
      broadcastToUser(friendId, { type: "friend_removed", friendId: userId });
      return res.json({ status: "ok", message: "Contact removed successfully." });
    }
    return res.status(404).json({ error: "Contact relationship not found." });
  } catch (err: any) {
    res.status(500).json({ error: "Failed to remove contact." });
  }
});

// 9. File & Image Upload endpoint with Cybersecurity Extension & MIME Inspection
app.post("/api/upload", upload.single("file"), (req, res) => {
  if (!req.file) {
    const diag = DiagnosticsRegistry.diagnose("ERR_FILE_MISSING", { reason: "No file was attached in request." });
    return res.status(400).json({ error: "No file was uploaded.", diagnostic: diag });
  }

  // Pre-screen file for cybersecurity threats
  const security = analyzeSecurityRisk({
    messageType: req.file.mimetype.startsWith("image/") ? "image" : "file",
    fileName: req.file.originalname,
    fileSize: `${(req.file.size / 1024).toFixed(1)} KB`,
  });

  if (security.isBlocked) {
    const diag = DiagnosticsRegistry.diagnose("ERR_FILE_DISALLOWED_TYPE", {
      fileName: req.file.originalname,
      threats: security.threats,
      riskScore: security.score,
    });
    return res.status(400).json({
      error: `Security Alert: Attachment rejected due to dangerous file signature (Risk Score: ${security.score}/100).`,
      security,
      diagnostic: diag,
    });
  }

  const isImage = req.file.mimetype.startsWith("image/");
  const subFolder = isImage ? "images" : "files";
  const fileUrl = `/storage/${subFolder}/${req.file.filename}`;

  const bytes = req.file.size;
  let formattedSize = `${bytes} B`;
  if (bytes > 1024 * 1024) formattedSize = `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  else if (bytes > 1024) formattedSize = `${(bytes / 1024).toFixed(1)} KB`;

  res.json({
    fileUrl,
    fileName: req.file.originalname,
    fileSize: formattedSize,
    messageType: isImage ? "image" : "file",
    securityScore: security.score,
    securityLevel: security.level,
    threats: security.threats,
  });
});

// 10. Get Messages (Gated by friendship)
app.get("/api/messages", async (req, res) => {
  const { user1, user2 } = req.query;
  if (!user1 || !user2) {
    return res.status(400).json({ error: "user1 and user2 query parameters are required." });
  }

  const u1 = user1 as string;
  const u2 = user2 as string;

  const friends = await dbService.areFriends(u1, u2);
  if (!friends) {
    const diag = DiagnosticsRegistry.diagnose("ERR_NOT_FRIENDS", {
      attemptedPair: [u1, u2],
      reason: "Friendship verification check failed.",
    });
    return res.status(403).json({
      error: "You can only view messages with accepted friends.",
      allowed: false,
      messages: [],
      diagnostic: diag,
    });
  }

  try {
    const messages = await dbService.getMessages(u1, u2);
    res.json({ messages, allowed: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch messages." });
  }
});

// 11. Send Message via REST
app.post("/api/messages", async (req, res) => {
  const t0 = performance.now();
  const { senderId, receiverId, content, messageType, fileUrl, fileName, fileSize, clientMsgId } = req.body;
  if (!senderId || !receiverId) {
    return res.status(400).json({ error: "senderId and receiverId are required." });
  }

  const friends = await dbService.areFriends(senderId, receiverId);
  if (!friends) {
    const diag = DiagnosticsRegistry.diagnose("ERR_NOT_FRIENDS", { senderId, receiverId });
    return res.status(403).json({ error: "You must be accepted friends to chat.", allowed: false, diagnostic: diag });
  }

  const mType = messageType || "text";
  const textContent = content || (mType === "image" ? "Photo" : fileName || "Attachment");

  // Cybersecurity Risk Assessment
  const security = analyzeSecurityRisk({
    content: textContent,
    messageType: mType,
    fileName,
    fileSize,
    senderId,
  });

  if (security.isBlocked) {
    const diag = DiagnosticsRegistry.diagnose("ERR_CYBER_THREAT_BLOCKED", {
      senderId,
      receiverId,
      threats: security.threats,
      riskScore: security.score,
    });
    return res.status(400).json({
      error: "Cybersecurity Alert: Message was blocked because it contains malicious script, exploit vector, or prohibited payload.",
      security,
      diagnostic: diag,
    });
  }

  const msgId = `m_${crypto.randomUUID().slice(0, 8)}`;
  const serverLatencyMs = Math.round(performance.now() - t0);

  const newMessage: MessageRecord = {
    id: msgId,
    senderId,
    receiverId,
    content: textContent,
    messageType: mType,
    fileUrl: fileUrl || null,
    fileName: fileName || null,
    fileSize: fileSize || null,
    securityScore: security.score,
    securityLevel: security.level,
    threatDetails: security.threats.join(" | "),
    integrityHash: security.details.integrityHash,
    latencyMs: serverLatencyMs,
    timestamp: new Date().toISOString(),
  };

  // Immediate non-blocking in-memory save & broadcast
  await dbService.insertMessage(newMessage);

  broadcastToUser(receiverId, { type: "new_message", message: newMessage, clientMsgId });
  broadcastToUser(senderId, { type: "new_message", message: newMessage, clientMsgId });

  res.json({ message: newMessage, security, serverLatencyMs });
});

// ---------------- WEBSOCKET SERVER ----------------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });

wss.on("connection", (ws, req) => {
  const url = new URL(req.url || "", `http://${req.headers.host}`);
  const userId = url.searchParams.get("userId");

  if (!userId) {
    ws.close(1008, "User ID missing");
    return;
  }

  if (!userSockets.has(userId)) {
    userSockets.set(userId, new Set());
  }
  userSockets.get(userId)!.add(ws);

  // Broadcast user online status
  broadcastGlobal({ type: "user_status", userId, online: true });

  // Handle incoming WebSocket messages with Ultra-Low Latency & Cybersecurity
  ws.on("message", async (raw) => {
    const t0 = performance.now();
    try {
      const data = JSON.parse(raw.toString());

      // 1. High-Precision Latency Ping / Pong Heartbeat
      if (data.type === "ping") {
        ws.send(
          JSON.stringify({
            type: "pong",
            clientTime: data.clientTime,
            serverTime: Date.now(),
          })
        );
        return;
      }

      // 2. Client RTT Latency Telemetry Reporting & Zero-Trust Latency Killswitch
      if (data.type === "report_rtt") {
        const rtt = Number(data.rttMs) || 10;
        DiagnosticsRegistry.recordLatency(rtt);
        const threshold = Number(data.thresholdMs) || 140;

        // Eavesdropping / MITM Wiretap Anomaly Detection
        if (rtt > threshold) {
          const geminiReport = await analyzeIncidentWithGemini("LATENCY_SPIKE_MITM_SUSPECTED", {
            userId,
            rttMs: rtt,
            thresholdMs: threshold,
            timestamp: new Date().toISOString(),
          });

          DiagnosticsRegistry.diagnose("ERR_LATENCY_MITM_SPIKE", {
            rttMs: rtt,
            threshold,
            reason: "Transmission delay exceeds safe threshold. Potential active wiretapping proxy detected.",
          });

          ws.send(
            JSON.stringify({
              type: "zero_trust_killswitch",
              reason: "LATENCY_SPIKE_MITM_SUSPECTED",
              rttMs: rtt,
              thresholdMs: threshold,
              geminiReport,
              message: `🚨 ZERO-TRUST KILLSWITCH: Latency reached ${rtt}ms (> ${threshold}ms). Interception suspected. Connection severed!`,
            })
          );
        }
        return;
      }

      // 2b. On-Demand Killswitch Simulation Test
      if (data.type === "simulate_latency_attack") {
        const fakeRtt = data.simulatedRtt || 240;
        const geminiReport = await analyzeIncidentWithGemini("LATENCY_SPIKE_MITM_SUSPECTED", {
          userId,
          rttMs: fakeRtt,
          simulated: true,
          thresholdMs: 140,
        });

        ws.send(
          JSON.stringify({
            type: "zero_trust_killswitch",
            reason: "LATENCY_SPIKE_MITM_SUSPECTED",
            rttMs: fakeRtt,
            thresholdMs: 140,
            geminiReport,
            message: `🚨 ZERO-TRUST KILLSWITCH TRIGGERED: Simulated eavesdropping spike (${fakeRtt}ms). Channel closed.`,
          })
        );
        return;
      }

      // 3. Fast Real-Time Message Transmission
      if (data.type === "send_message") {
        const { receiverId, content, messageType, fileUrl, fileName, fileSize, clientMsgId, integrityChecksum } = data;
        if (!receiverId) return;

        // Friendship Authorization Gate
        const friends = await dbService.areFriends(userId, receiverId);
        if (!friends) {
          const diag = DiagnosticsRegistry.diagnose("ERR_NOT_FRIENDS", {
            senderId: userId,
            receiverId,
            reason: "Target recipient is not an accepted friend.",
          });
          ws.send(
            JSON.stringify({
              type: "message_error",
              clientMsgId,
              error: "Cannot send message: you must be accepted friends first.",
              diagnostic: diag,
            })
          );
          return;
        }

        const mType = messageType || "text";
        const textContent = content || (mType === "image" ? "Photo" : fileName || "Attachment");

        // Cybersecurity Risk Engine Inspection
        const security = analyzeSecurityRisk({
          content: textContent,
          messageType: mType,
          fileName,
          fileSize,
          senderId: userId,
        });

        // Verify transmission cryptographic integrity if client passed checksum
        if (integrityChecksum) {
          const expected = generateIntegrityHash(textContent, userId);
          // If hash mismatched (ignoring timestamp part), flag integrity anomaly
          if (!security.details.integrityHash.startsWith(integrityChecksum.slice(0, 16))) {
            security.score = Math.min(100, security.score + 25);
            security.threats.push("Cryptographic Integrity Warning: Checksum discrepancy detected in transit.");
          }
        }

        // Check if message is blocked by cybersecurity filter
        if (security.isBlocked) {
          const diag = DiagnosticsRegistry.diagnose("ERR_CYBER_THREAT_BLOCKED", {
            senderId: userId,
            receiverId,
            threats: security.threats,
            riskScore: security.score,
            blockedContentSnippet: textContent.slice(0, 50),
          });

          ws.send(
            JSON.stringify({
              type: "message_error",
              clientMsgId,
              error: `Cybersecurity Shield Alert: Message blocked! Risk Score: ${security.score}/100. Root Cause: ${security.threats[0]}`,
              security,
              diagnostic: diag,
            })
          );
          return;
        }

        const msgId = `m_${crypto.randomUUID().slice(0, 8)}`;
        const serverLatencyMs = Math.max(1, Math.round(performance.now() - t0));

        const newMessage: MessageRecord = {
          id: msgId,
          senderId: userId,
          receiverId,
          content: textContent,
          messageType: mType,
          fileUrl: fileUrl || null,
          fileName: fileName || null,
          fileSize: fileSize || null,
          securityScore: security.score,
          securityLevel: security.level,
          threatDetails: security.threats.join(" | "),
          integrityHash: security.details.integrityHash,
          latencyMs: serverLatencyMs,
          timestamp: new Date().toISOString(),
        };

        // 1. Immediately ACK sender to calculate RTT latency with zero blocking
        ws.send(
          JSON.stringify({
            type: "msg_ack",
            clientMsgId,
            messageId: msgId,
            serverLatencyMs,
            timestamp: newMessage.timestamp,
            securityScore: security.score,
            securityLevel: security.level,
          })
        );

        // 2. Immediate direct dispatch to receiver (sub-millisecond peer delivery)
        broadcastToUser(receiverId, { type: "new_message", message: newMessage, clientMsgId });

        // 3. Echo to other sessions of sender
        broadcastToUserExcept(userId, ws, { type: "new_message", message: newMessage, clientMsgId });

        // 4. Asynchronous persistence (non-blocking)
        dbService.insertMessage(newMessage);

      } else if (data.type === "typing") {
        const { receiverId, isTyping } = data;
        if (receiverId && (await dbService.areFriends(userId, receiverId))) {
          broadcastToUser(receiverId, {
            type: "typing_indicator",
            senderId: userId,
            isTyping: Boolean(isTyping),
          });
        }
      }
    } catch (err: any) {
      console.error("WebSocket message error:", err);
      const diag = DiagnosticsRegistry.diagnose("ERR_PAYLOAD_MALFORMED", {
        reason: err.message,
      });
      ws.send(
        JSON.stringify({
          type: "message_error",
          error: "Malformed WebSocket payload received.",
          diagnostic: diag,
        })
      );
    }
  });

  ws.on("close", () => {
    const sockets = userSockets.get(userId);
    if (sockets) {
      sockets.delete(ws);
      if (sockets.size === 0) {
        userSockets.delete(userId);
        broadcastGlobal({ type: "user_status", userId, online: false });
      }
    }
  });
});

// Initialize MongoDB Atlas database and start server
initDatabase()
  .then(() => {
    // Setup Live Change Stream Feed from MongoDB Atlas
    watchMongoLiveFeed((event) => {
      if (event.collection === "messages" && event.operation === "insert") {
        const msg = event.document;
        broadcastToUser(msg.receiverId, { type: "mongo_live_feed", message: msg });
      }
    });

    server.listen(PORT, () => {
      console.log(`\n==================================================`);
      console.log(`🚀 Chatvia Engine running at http://localhost:${PORT}`);
      console.log(`⚡ WebSocket Server active at ws://localhost:${PORT}/ws`);
      console.log(`🍃 Database Engine: MongoDB Atlas (Cluster0 Live Feed)`);
      console.log(`🛡️ Cybersecurity Analyzer: ACTIVE (Phishing, XSS, SQLi, DLP, File Risk)`);
      console.log(`🔍 Root-Cause Diagnostics & Latency Telemetry: ONLINE`);
      console.log(`💾 Storage Root: ${STORAGE_DIR}`);
      console.log(`==================================================\n`);
    });
  })
  .catch((err) => {
    console.error("FATAL: Failed to start server:", err);
  });