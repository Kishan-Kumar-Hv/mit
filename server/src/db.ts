import { MongoClient, Db, Collection } from "mongodb";
import crypto from "crypto";
import fs from "fs";
import path from "path";

export const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://kishankumarhv5_db_user:AoJqQnF57zkBXgWe@cluster0.fqxsirr.mongodb.net/?appName=Cluster0";

export const DB_NAME = "chatvia";

// Password hashing helper
export function hashPassword(password: string): string {
  return crypto.createHash("sha256").update(password).digest("hex");
}

export function generateUserIdCode(): string {
  const randomNum = Math.floor(1000 + Math.random() * 9000);
  return `UID-${randomNum}`;
}

// Storage Directories
export const STORAGE_DIR = path.resolve("./storage");
export const CHAT_DIR = path.join(STORAGE_DIR, "chat");
export const IMAGES_DIR = path.join(STORAGE_DIR, "images");
export const FILES_DIR = path.join(STORAGE_DIR, "files");
export const AVATARS_DIR = path.join(STORAGE_DIR, "avatars");

export function initStorageFolders() {
  [STORAGE_DIR, CHAT_DIR, IMAGES_DIR, FILES_DIR, AVATARS_DIR].forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
}

export function backupChatToFile(user1: string, user2: string, messages: any[]) {
  try {
    initStorageFolders();
    const pairKey = [user1, user2].sort().join("_");
    const filePath = path.join(CHAT_DIR, `chat_${pairKey}.json`);
    fs.writeFileSync(filePath, JSON.stringify(messages, null, 2), "utf-8");
  } catch (err) {
    console.error("Failed to backup chat transcript to disk:", err);
  }
}

// MongoDB Models
export interface UserRecord {
  id: string;
  userIdCode: string;
  username: string;
  email: string;
  fullName: string;
  passwordHash: string;
  avatar: string;
  bio?: string;
  createdAt: string;
}

export interface FriendRequestRecord {
  id: string;
  senderId: string;
  receiverId: string;
  status: "pending" | "accepted" | "rejected";
  createdAt: string;
}

export interface MessageRecord {
  id: string;
  senderId: string;
  receiverId: string;
  content: string;
  messageType: "text" | "image" | "file";
  fileUrl?: string | null;
  fileName?: string | null;
  fileSize?: string | null;
  timestamp: string;
  securityScore?: number;
  securityLevel?: "safe" | "low" | "medium" | "high" | "critical";
  threatDetails?: string | null;
  integrityHash?: string | null;
  latencyMs?: number;
}

export interface DiagnosticRecord {
  id: string;
  timestamp: string;
  errorCode: string;
  category: string;
  severity: string;
  title: string;
  rootCause: string;
  recommendedAction: string;
  technicalDetails?: string;
}

// MongoClient instance
export const mongoClient = new MongoClient(MONGO_URI, {
  serverSelectionTimeoutMS: 20000,
  connectTimeoutMS: 20000,
  maxPoolSize: 20,
});

let db: Db;
let usersColl: Collection<UserRecord>;
let friendRequestsColl: Collection<FriendRequestRecord>;
let messagesColl: Collection<MessageRecord>;
let diagnosticsColl: Collection<DiagnosticRecord>;
export let isMongoConnected = false;

// Initialize MongoDB Connection (Clean, No Demo Users - 100% Real User Driven)
export async function initDatabase(): Promise<void> {
  initStorageFolders();

  let retries = 3;
  while (retries > 0) {
    try {
      console.log(`Connecting to MongoDB Atlas (attempts remaining: ${retries})...`);
      await mongoClient.connect();
      db = mongoClient.db(DB_NAME);
      usersColl = db.collection<UserRecord>("users");
      friendRequestsColl = db.collection<FriendRequestRecord>("friend_requests");
      messagesColl = db.collection<MessageRecord>("messages");
      diagnosticsColl = db.collection<DiagnosticRecord>("diagnostics");
      isMongoConnected = true;

      // Ensure clean indexes
      await usersColl.createIndex({ id: 1 }, { unique: true });
      await usersColl.createIndex({ userIdCode: 1 }, { unique: true });
      await usersColl.createIndex({ username: 1 }, { unique: true });
      await usersColl.createIndex({ email: 1 }, { unique: true });
      await friendRequestsColl.createIndex({ senderId: 1, receiverId: 1 });
      await messagesColl.createIndex({ senderId: 1, receiverId: 1, timestamp: 1 });

      const userCount = await usersColl.countDocuments();
      console.log(`✅ Connected to MongoDB Atlas: ${DB_NAME} at Cluster0! Real users count: ${userCount}`);
      return;
    } catch (err: any) {
      retries--;
      console.warn(`Connection attempt failed: ${err.message}. Retrying in 2s...`);
      if (retries === 0) {
        isMongoConnected = false;
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
}

// Change Stream Setup for Live Feed from MongoDB Atlas
export function watchMongoLiveFeed(onLiveEvent: (event: { collection: string; operation: string; document: any }) => void) {
  if (!isMongoConnected) return;

  try {
    const messageStream = messagesColl.watch([], { fullDocument: "updateLookup" });
    messageStream.on("change", (change) => {
      if (change.operationType === "insert" && change.fullDocument) {
        onLiveEvent({
          collection: "messages",
          operation: "insert",
          document: change.fullDocument,
        });
      }
    });

    const friendStream = friendRequestsColl.watch([], { fullDocument: "updateLookup" });
    friendStream.on("change", (change) => {
      onLiveEvent({
        collection: "friend_requests",
        operation: change.operationType,
        document: (change as any).fullDocument,
      });
    });

    console.log("⚡ MongoDB Atlas Live Feed Change Streams active.");
  } catch (e: any) {
    console.warn("MongoDB Change Streams notice (requires replica set):", e.message);
  }
}

// Unified Database Service using MongoDB Atlas
export const dbService = {
  getDbStatus(): string {
    return isMongoConnected
      ? "MongoDB Atlas (Connected • Cluster0 Live Feed 🍃)"
      : "MongoDB Atlas (Connecting...)";
  },

  async findUserByUsernameOrEmail(username?: string, email?: string): Promise<UserRecord | null> {
    const cleanUname = username?.trim().toLowerCase();
    const cleanEmail = email?.trim().toLowerCase();

    const query: any = {};
    if (cleanUname && cleanEmail) {
      query.$or = [{ username: cleanUname }, { email: cleanEmail }];
    } else if (cleanUname) {
      query.username = cleanUname;
    } else if (cleanEmail) {
      query.email = cleanEmail;
    }

    const doc = await usersColl.findOne(query);
    if (!doc) return null;
    return {
      id: doc.id,
      userIdCode: doc.userIdCode,
      username: doc.username,
      email: doc.email,
      fullName: doc.fullName,
      passwordHash: doc.passwordHash,
      avatar: doc.avatar,
      bio: doc.bio,
      createdAt: doc.createdAt,
    };
  },

  async findUserById(id: string): Promise<UserRecord | null> {
    const doc = await usersColl.findOne({ id });
    if (!doc) return null;
    return {
      id: doc.id,
      userIdCode: doc.userIdCode,
      username: doc.username,
      email: doc.email,
      fullName: doc.fullName,
      passwordHash: doc.passwordHash,
      avatar: doc.avatar,
      bio: doc.bio,
      createdAt: doc.createdAt,
    };
  },

  async lookupUser(codeOrUsername: string): Promise<UserRecord | null> {
    const clean = codeOrUsername.trim();
    const doc = await usersColl.findOne({
      $or: [
        { userIdCode: { $regex: `^${clean}$`, $options: "i" } },
        { username: { $regex: `^${clean}$`, $options: "i" } },
        { fullName: { $regex: `^${clean}$`, $options: "i" } },
      ],
    });

    if (!doc) return null;
    return {
      id: doc.id,
      userIdCode: doc.userIdCode,
      username: doc.username,
      email: doc.email,
      fullName: doc.fullName,
      passwordHash: doc.passwordHash,
      avatar: doc.avatar,
      bio: doc.bio,
      createdAt: doc.createdAt,
    };
  },

  async searchUsers(queryText: string, currentUserId: string): Promise<any[]> {
    const clean = queryText.trim();
    if (!clean) return [];

    const escaped = clean.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(escaped, "i");

    const docs = await usersColl
      .find({
        id: { $ne: currentUserId },
        $or: [
          { username: { $regex: regex } },
          { fullName: { $regex: regex } },
          { userIdCode: { $regex: regex } },
          { email: { $regex: regex } },
        ],
      })
      .limit(20)
      .toArray();

    const results = await Promise.all(
      docs.map(async (doc) => {
        const relationship = await this.getFriendRelationship(currentUserId, doc.id);
        return {
          id: doc.id,
          userIdCode: doc.userIdCode,
          username: doc.username,
          fullName: doc.fullName,
          avatar: doc.avatar,
          bio: doc.bio,
          relationship,
        };
      })
    );

    return results;
  },

  async getAllUsers(currentUserId: string): Promise<any[]> {
    const docs = await usersColl
      .find({ id: { $ne: currentUserId } })
      .limit(50)
      .toArray();

    const results = await Promise.all(
      docs.map(async (doc) => {
        const relationship = await this.getFriendRelationship(currentUserId, doc.id);
        return {
          id: doc.id,
          userIdCode: doc.userIdCode,
          username: doc.username,
          fullName: doc.fullName,
          avatar: doc.avatar,
          bio: doc.bio,
          relationship,
        };
      })
    );

    return results;
  },

  async createUser(user: UserRecord): Promise<UserRecord> {
    await usersColl.insertOne(user);
    return user;
  },

  async updateUserProfile(userId: string, fullName?: string, bio?: string, avatar?: string): Promise<UserRecord | null> {
    const updateFields: any = {};
    if (fullName) updateFields.fullName = fullName;
    if (bio !== undefined) updateFields.bio = bio;
    if (avatar) updateFields.avatar = avatar;

    await usersColl.updateOne({ id: userId }, { $set: updateFields });
    return this.findUserById(userId);
  },

  async areFriends(userId1: string, userId2: string): Promise<boolean> {
    if (userId1 === userId2) return false;
    const doc = await friendRequestsColl.findOne({
      status: "accepted",
      $or: [
        { senderId: userId1, receiverId: userId2 },
        { senderId: userId2, receiverId: userId1 },
      ],
    });
    return Boolean(doc);
  },

  async getFriendRelationship(currentUserId: string, targetId: string): Promise<"friends" | "pending_sent" | "pending_received" | "none"> {
    if (currentUserId === targetId) return "none";
    const doc = await friendRequestsColl.findOne({
      $or: [
        { senderId: currentUserId, receiverId: targetId },
        { senderId: targetId, receiverId: currentUserId },
      ],
    });

    if (!doc) return "none";
    if (doc.status === "accepted") return "friends";
    return doc.senderId === currentUserId ? "pending_sent" : "pending_received";
  },

  async sendFriendRequest(senderId: string, receiverId: string): Promise<FriendRequestRecord> {
    const id = `fr_${crypto.randomUUID().slice(0, 8)}`;
    const record: FriendRequestRecord = {
      id,
      senderId,
      receiverId,
      status: "pending",
      createdAt: new Date().toISOString(),
    };

    await friendRequestsColl.updateOne(
      { senderId, receiverId },
      { $set: record },
      { upsert: true }
    );
    return record;
  },

  async respondFriendRequest(requestId: string, action: "accept" | "reject"): Promise<FriendRequestRecord | null> {
    const status = action === "accept" ? "accepted" : "rejected";
    const res = await friendRequestsColl.findOneAndUpdate(
      { id: requestId },
      { $set: { status } },
      { returnDocument: "after" }
    );
    return res || null;
  },

  // Remove / Delete Contact (WhatsApp style)
  async removeFriend(userId: string, friendId: string): Promise<boolean> {
    const res = await friendRequestsColl.deleteMany({
      $or: [
        { senderId: userId, receiverId: friendId },
        { senderId: friendId, receiverId: userId },
      ],
    });
    return res.deletedCount > 0;
  },

  async getFriends(userId: string) {
    // 1. Accepted friends
    const acceptedRequests = await friendRequestsColl
      .find({
        status: "accepted",
        $or: [{ senderId: userId }, { receiverId: userId }],
      })
      .toArray();

    const friendIds = acceptedRequests.map((fr) => (fr.senderId === userId ? fr.receiverId : fr.senderId));
    const friendUsersDocs = await usersColl.find({ id: { $in: friendIds } }).toArray();

    const friends = await Promise.all(
      friendUsersDocs.map(async (u) => {
        const lastMsg = await messagesColl
          .find({
            $or: [
              { senderId: userId, receiverId: u.id },
              { senderId: u.id, receiverId: userId },
            ],
          })
          .sort({ timestamp: -1 })
          .limit(1)
          .next();

        let preview = null;
        if (lastMsg) {
          if (lastMsg.messageType === "image") preview = "📷 Photo";
          else if (lastMsg.messageType === "file") preview = `📄 ${lastMsg.fileName || "File"}`;
          else preview = lastMsg.content;
        }

        return {
          id: u.id,
          userIdCode: u.userIdCode,
          username: u.username,
          email: u.email,
          fullName: u.fullName,
          avatar: u.avatar,
          bio: u.bio,
          lastMessage: preview,
          lastMessageTime: lastMsg ? lastMsg.timestamp : null,
        };
      })
    );

    // 2. Pending Incoming
    const incomingReqs = await friendRequestsColl.find({ receiverId: userId, status: "pending" }).toArray();
    const incomingSenderIds = incomingReqs.map((r) => r.senderId);
    const incomingUsers = await usersColl.find({ id: { $in: incomingSenderIds } }).toArray();
    const userMap = new Map(incomingUsers.map((u) => [u.id, u]));

    const pendingIncoming = incomingReqs.map((r) => {
      const u = userMap.get(r.senderId);
      return {
        id: r.id,
        senderId: r.senderId,
        userIdCode: u?.userIdCode,
        username: u?.username,
        fullName: u?.fullName,
        avatar: u?.avatar,
        createdAt: r.createdAt,
      };
    });

    // 3. Pending Outgoing
    const outgoingReqs = await friendRequestsColl.find({ senderId: userId, status: "pending" }).toArray();
    const outgoingReceiverIds = outgoingReqs.map((r) => r.receiverId);
    const outgoingUsers = await usersColl.find({ id: { $in: outgoingReceiverIds } }).toArray();
    const outUserMap = new Map(outgoingUsers.map((u) => [u.id, u]));

    const pendingOutgoing = outgoingReqs.map((r) => {
      const u = outUserMap.get(r.receiverId);
      return {
        id: r.id,
        receiverId: r.receiverId,
        userIdCode: u?.userIdCode,
        username: u?.username,
        fullName: u?.fullName,
        avatar: u?.avatar,
        createdAt: r.createdAt,
      };
    });

    return { friends, pendingIncoming, pendingOutgoing };
  },

  async getMessages(user1: string, user2: string): Promise<MessageRecord[]> {
    const docs = await messagesColl
      .find({
        $or: [
          { senderId: user1, receiverId: user2 },
          { senderId: user2, receiverId: user1 },
        ],
      })
      .sort({ timestamp: 1 })
      .toArray();

    return docs.map((d) => ({
      id: d.id,
      senderId: d.senderId,
      receiverId: d.receiverId,
      content: d.content,
      messageType: d.messageType,
      fileUrl: d.fileUrl,
      fileName: d.fileName,
      fileSize: d.fileSize,
      securityScore: d.securityScore,
      securityLevel: d.securityLevel,
      threatDetails: d.threatDetails,
      integrityHash: d.integrityHash,
      latencyMs: d.latencyMs,
      timestamp: d.timestamp,
    }));
  },

  async insertMessage(msg: MessageRecord): Promise<MessageRecord> {
    await messagesColl.insertOne(msg);

    setImmediate(async () => {
      try {
        const history = await this.getMessages(msg.senderId, msg.receiverId);
        backupChatToFile(msg.senderId, msg.receiverId, history);
      } catch (err) {
        console.error("Backup file error:", err);
      }
    });

    return msg;
  },

  async logDiagnostic(report: DiagnosticRecord) {
    try {
      await diagnosticsColl.insertOne(report);
    } catch (e) {
      console.error("Diagnostic log insert error:", e);
    }
  },

  async getRecentDiagnostics(limit = 25): Promise<DiagnosticRecord[]> {
    const docs = await diagnosticsColl.find().sort({ timestamp: -1 }).limit(limit).toArray();
    return docs.map((d) => ({
      id: d.id,
      timestamp: d.timestamp,
      errorCode: d.errorCode,
      category: d.category,
      severity: d.severity,
      title: d.title,
      rootCause: d.rootCause,
      recommendedAction: d.recommendedAction,
      technicalDetails: d.technicalDetails,
    }));
  },

  async wipeDatabase(): Promise<void> {
    await usersColl.deleteMany({});
    await friendRequestsColl.deleteMany({});
    await messagesColl.deleteMany({});
    await diagnosticsColl.deleteMany({});
    console.log("MongoDB Atlas completely wiped for fresh real user onboarding.");
  },
};
