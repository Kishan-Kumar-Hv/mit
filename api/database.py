import sqlite3
import hashlib
import os
import random
import json
from datetime import datetime
from typing import Optional, List, Dict, Any

# Database file location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "database", "chatvia.db")
STORAGE_DIR = os.path.join(PROJECT_ROOT, "server", "storage")

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(os.path.join(STORAGE_DIR, "images"), exist_ok=True)
os.makedirs(os.path.join(STORAGE_DIR, "files"), exist_ok=True)
os.makedirs(os.path.join(STORAGE_DIR, "chat"), exist_ok=True)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def generate_user_id_code() -> str:
    return f"UID-{random.randint(1000, 9999)}"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            user_id_code TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            avatar TEXT,
            bio TEXT DEFAULT 'Hey there! I am using Chatvia.',
            created_at TEXT NOT NULL
        )
    """)

    # 2. Friend Requests Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS friend_requests (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'rejected')),
            created_at TEXT NOT NULL,
            UNIQUE(sender_id, receiver_id)
        )
    """)

    # 3. Messages Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            content TEXT NOT NULL,
            message_type TEXT DEFAULT 'text' CHECK(message_type IN ('text', 'image', 'file')),
            file_url TEXT,
            file_name TEXT,
            file_size TEXT,
            security_score INTEGER DEFAULT 0,
            security_level TEXT DEFAULT 'safe',
            threat_details TEXT,
            integrity_hash TEXT,
            latency_ms REAL DEFAULT 0,
            timestamp TEXT NOT NULL
        )
    """)

    # 4. Diagnostic Logs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS diagnostic_logs (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            error_code TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            root_cause TEXT NOT NULL,
            recommended_action TEXT NOT NULL,
            technical_details TEXT
        )
    """)

    # Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages (sender_id, receiver_id, timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_uid ON users (user_id_code)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_uname ON users (username)")

    # 5. Seed Initial Demo Users if Empty
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]

    if count == 0:
        demo_users = [
            ("u_doris", "UID-7001", "doris", "doris@gmail.com", "Doris Brown",
             hash_password("doris123"),
             "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=150",
             "Product Designer & Tech Enthusiast 🎨", datetime.utcnow().isoformat()),
            ("u_patrick", "UID-7002", "patrick", "patrick@gmail.com", "Patrick Hendricks",
             hash_password("patrick123"),
             "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150",
             "Software Architect & Coffee lover ☕", datetime.utcnow().isoformat()),
            ("u_steve", "UID-7004", "steve", "steve@gmail.com", "Steve Walker",
             hash_password("steve123"),
             "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150",
             "DevOps Engineer | Cloud Infrastructure ☁️", datetime.utcnow().isoformat()),
            ("u_mark", "UID-7003", "mark", "mark@gmail.com", "Mark Messer",
             hash_password("mark123"),
             "https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=150",
             "Full-Stack Developer 💻", datetime.utcnow().isoformat()),
            ("u_emily", "UID-7005", "emily", "emily@gmail.com", "Emily Clark",
             hash_password("emily123"),
             "https://images.unsplash.com/photo-1438761681033-6461ffad8d80?w=150",
             "UI/UX Researcher & Writer 📚", datetime.utcnow().isoformat()),
        ]

        cursor.executemany("""
            INSERT OR IGNORE INTO users (id, user_id_code, username, email, full_name, password_hash, avatar, bio, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, demo_users)

        # Seed Friendships: Doris & Patrick, Doris & Mark
        demo_friends = [
            ("fr_1", "u_patrick", "u_doris", "accepted", datetime.utcnow().isoformat()),
            ("fr_2", "u_mark", "u_doris", "accepted", datetime.utcnow().isoformat()),
        ]
        cursor.executemany("""
            INSERT OR IGNORE INTO friend_requests (id, sender_id, receiver_id, status, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, demo_friends)

        # Seed Initial Messages
        demo_messages = [
            ("m_1", "u_doris", "u_patrick", "Good morning", "text", None, None, None, 0, "safe", "Clean payload", "hash_m1", 8.0, datetime.utcnow().isoformat()),
            ("m_2", "u_doris", "u_patrick", "Yeah everything is fine", "text", None, None, None, 0, "safe", "Clean payload", "hash_m2", 11.0, datetime.utcnow().isoformat()),
            ("m_3", "u_doris", "u_patrick", "& Next meeting tomorrow 10.00AM", "text", None, None, None, 0, "safe", "Clean payload", "hash_m3", 7.0, datetime.utcnow().isoformat()),
        ]
        cursor.executemany("""
            INSERT OR IGNORE INTO messages (id, sender_id, receiver_id, content, message_type, file_url, file_name, file_size, security_score, security_level, threat_details, integrity_hash, latency_ms, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, demo_messages)

    conn.commit()
    conn.close()

# Database Query Functions
class DatabaseManager:
    @staticmethod
    def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        row = conn.execute("SELECT id, user_id_code, username, email, full_name, avatar, bio, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        if not row:
            return None
        return {
            "id": row["id"],
            "userIdCode": row["user_id_code"],
            "username": row["username"],
            "email": row["email"],
            "fullName": row["full_name"],
            "avatar": row["avatar"],
            "bio": row["bio"],
            "createdAt": row["created_at"],
        }

    @staticmethod
    def authenticate_user(username_or_email: str, password: str) -> Optional[Dict[str, Any]]:
        clean = username_or_email.strip().lower()
        p_hash = hash_password(password)
        conn = get_db_connection()
        row = conn.execute("""
            SELECT id, user_id_code, username, email, full_name, avatar, bio
            FROM users
            WHERE (LOWER(username) = ? OR LOWER(email) = ?) AND password_hash = ?
        """, (clean, clean, p_hash)).fetchone()
        conn.close()
        if not row:
            return None
        return {
            "id": row["id"],
            "userIdCode": row["user_id_code"],
            "username": row["username"],
            "email": row["email"],
            "fullName": row["full_name"],
            "avatar": row["avatar"],
            "bio": row["bio"],
        }

    @staticmethod
    def create_user(username: str, email: str, password: str, full_name: Optional[str] = None, avatar: Optional[str] = None, bio: Optional[str] = None) -> Optional[Dict[str, Any]]:
        clean_uname = username.strip().lower()
        clean_email = email.strip().lower()
        conn = get_db_connection()

        # Check existing
        existing = conn.execute("SELECT id FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (clean_uname, clean_email)).fetchone()
        if existing:
            conn.close()
            return None

        new_id = f"u_{hashlib.md5(f'{clean_uname}{datetime.utcnow()}'.encode()).hexdigest()[:8]}"
        user_id_code = generate_user_id_code()
        p_hash = hash_password(password)
        name = full_name.strip() if full_name else clean_uname
        user_avatar = avatar or f"https://api.dicebear.com/7.x/bottts/svg?seed={clean_uname}"
        user_bio = bio.strip() if bio else "Hey there! I am using Chatvia."
        created_at = datetime.utcnow().isoformat()

        conn.execute("""
            INSERT INTO users (id, user_id_code, username, email, full_name, password_hash, avatar, bio, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (new_id, user_id_code, clean_uname, clean_email, name, p_hash, user_avatar, user_bio, created_at))
        conn.commit()
        conn.close()

        return {
            "id": new_id,
            "userIdCode": user_id_code,
            "username": clean_uname,
            "email": clean_email,
            "fullName": name,
            "avatar": user_avatar,
            "bio": user_bio,
        }

    @staticmethod
    def update_profile(user_id: str, full_name: Optional[str], bio: Optional[str], avatar: Optional[str]) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        conn.execute("""
            UPDATE users
            SET full_name = COALESCE(?, full_name),
                bio = COALESCE(?, bio),
                avatar = COALESCE(?, avatar)
            WHERE id = ?
        """, (full_name, bio, avatar, user_id))
        conn.commit()
        conn.close()
        return DatabaseManager.get_user_by_id(user_id)

    @staticmethod
    def lookup_user(code_or_username: str) -> Optional[Dict[str, Any]]:
        clean = code_or_username.strip().upper()
        conn = get_db_connection()
        row = conn.execute("""
            SELECT id, user_id_code, username, full_name, avatar, bio
            FROM users
            WHERE UPPER(user_id_code) = ? OR UPPER(username) = ?
        """, (clean, clean)).fetchone()
        conn.close()
        if not row:
            return None
        return {
            "id": row["id"],
            "userIdCode": row["user_id_code"],
            "username": row["username"],
            "fullName": row["full_name"],
            "avatar": row["avatar"],
            "bio": row["bio"],
        }

    @staticmethod
    def are_friends(user1: str, user2: str) -> bool:
        if user1 == user2:
            return False
        conn = get_db_connection()
        row = conn.execute("""
            SELECT id FROM friend_requests
            WHERE status = 'accepted'
              AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        """, (user1, user2, user2, user1)).fetchone()
        conn.close()
        return bool(row)

    @staticmethod
    def get_relationship(user1: str, user2: str) -> str:
        if user1 == user2:
            return "none"
        conn = get_db_connection()
        row = conn.execute("""
            SELECT status, sender_id FROM friend_requests
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        """, (user1, user2, user2, user1)).fetchone()
        conn.close()
        if not row:
            return "none"
        if row["status"] == "accepted":
            return "friends"
        return "pending_sent" if row["sender_id"] == user1 else "pending_received"

    @staticmethod
    def send_friend_request(sender_id: str, receiver_id: str) -> Dict[str, Any]:
        req_id = f"fr_{hashlib.md5(f'{sender_id}{receiver_id}{datetime.utcnow()}'.encode()).hexdigest()[:8]}"
        now = datetime.utcnow().isoformat()
        conn = get_db_connection()
        conn.execute("""
            INSERT OR REPLACE INTO friend_requests (id, sender_id, receiver_id, status, created_at)
            VALUES (?, ?, ?, 'pending', ?)
        """, (req_id, sender_id, receiver_id, now))
        conn.commit()
        conn.close()
        return {"id": req_id, "senderId": sender_id, "receiverId": receiver_id, "status": "pending", "createdAt": now}

    @staticmethod
    def respond_friend_request(req_id: str, action: str) -> Optional[Dict[str, Any]]:
        status = "accepted" if action == "accept" else "rejected"
        conn = get_db_connection()
        row = conn.execute("SELECT id, sender_id, receiver_id FROM friend_requests WHERE id = ?", (req_id,)).fetchone()
        if not row:
            conn.close()
            return None
        conn.execute("UPDATE friend_requests SET status = ? WHERE id = ?", (status, req_id))
        conn.commit()
        conn.close()
        return {"id": row["id"], "senderId": row["sender_id"], "receiverId": row["receiver_id"], "status": status}

    @staticmethod
    def get_friends_data(user_id: str) -> Dict[str, Any]:
        conn = get_db_connection()

        # Accepted Friends
        friend_rows = conn.execute("""
            SELECT u.id, u.user_id_code, u.username, u.email, u.full_name, u.avatar, u.bio
            FROM users u
            JOIN friend_requests fr
              ON fr.status = 'accepted'
             AND ((fr.sender_id = ? AND fr.receiver_id = u.id) OR (fr.sender_id = u.id AND fr.receiver_id = ?))
            WHERE u.id != ?
        """, (user_id, user_id, user_id)).fetchall()

        friends = []
        for r in friend_rows:
            last_msg = conn.execute("""
                SELECT content, message_type, file_name, timestamp
                FROM messages
                WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
                ORDER BY timestamp DESC LIMIT 1
            """, (user_id, r["id"], r["id"], user_id)).fetchone()

            preview = None
            last_time = None
            if last_msg:
                last_time = last_msg["timestamp"]
                if last_msg["message_type"] == "image":
                    preview = "📷 Photo"
                elif last_msg["message_type"] == "file":
                    preview = f"📄 {last_msg['file_name'] or 'File'}"
                else:
                    preview = last_msg["content"]

            friends.append({
                "id": r["id"],
                "userIdCode": r["user_id_code"],
                "username": r["username"],
                "email": r["email"],
                "fullName": r["full_name"],
                "avatar": r["avatar"],
                "bio": r["bio"],
                "lastMessage": preview,
                "lastMessageTime": last_time,
            })

        # Pending Incoming
        incoming_rows = conn.execute("""
            SELECT fr.id, fr.sender_id, u.user_id_code, u.username, u.full_name, u.avatar, fr.created_at
            FROM friend_requests fr
            JOIN users u ON u.id = fr.sender_id
            WHERE fr.receiver_id = ? AND fr.status = 'pending'
        """, (user_id,)).fetchall()

        pending_incoming = [{
            "id": r["id"],
            "senderId": r["sender_id"],
            "userIdCode": r["user_id_code"],
            "username": r["username"],
            "fullName": r["full_name"],
            "avatar": r["avatar"],
            "createdAt": r["created_at"],
        } for r in incoming_rows]

        # Pending Outgoing
        outgoing_rows = conn.execute("""
            SELECT fr.id, fr.receiver_id, u.user_id_code, u.username, u.full_name, u.avatar, fr.created_at
            FROM friend_requests fr
            JOIN users u ON u.id = fr.receiver_id
            WHERE fr.sender_id = ? AND fr.status = 'pending'
        """, (user_id,)).fetchall()

        pending_outgoing = [{
            "id": r["id"],
            "receiverId": r["receiver_id"],
            "userIdCode": r["user_id_code"],
            "username": r["username"],
            "fullName": r["full_name"],
            "avatar": r["avatar"],
            "createdAt": r["created_at"],
        } for r in outgoing_rows]

        conn.close()
        return {"friends": friends, "pendingIncoming": pending_incoming, "pendingOutgoing": pending_outgoing}

    @staticmethod
    def get_messages(user1: str, user2: str) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        rows = conn.execute("""
            SELECT id, sender_id, receiver_id, content, message_type, file_url, file_name, file_size,
                   security_score, security_level, threat_details, integrity_hash, latency_ms, timestamp
            FROM messages
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
            ORDER BY timestamp ASC
        """, (user1, user2, user2, user1)).fetchall()
        conn.close()

        return [{
            "id": r["id"],
            "senderId": r["sender_id"],
            "receiverId": r["receiver_id"],
            "content": r["content"],
            "messageType": r["message_type"],
            "fileUrl": r["file_url"],
            "fileName": r["file_name"],
            "fileSize": r["file_size"],
            "securityScore": r["security_score"],
            "securityLevel": r["security_level"],
            "threatDetails": r["threat_details"],
            "integrityHash": r["integrity_hash"],
            "latencyMs": r["latency_ms"],
            "timestamp": r["timestamp"],
        } for r in rows]

    @staticmethod
    def insert_message(msg: Dict[str, Any]) -> Dict[str, Any]:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO messages (id, sender_id, receiver_id, content, message_type, file_url, file_name, file_size,
                                  security_score, security_level, threat_details, integrity_hash, latency_ms, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            msg["id"], msg["senderId"], msg["receiverId"], msg["content"], msg.get("messageType", "text"),
            msg.get("fileUrl"), msg.get("fileName"), msg.get("fileSize"),
            msg.get("securityScore", 0), msg.get("securityLevel", "safe"), msg.get("threatDetails"),
            msg.get("integrityHash"), msg.get("latencyMs", 0), msg["timestamp"]
        ))
        conn.commit()
        conn.close()
        return msg

    @staticmethod
    def log_diagnostic(report: Dict[str, Any]):
        conn = get_db_connection()
        conn.execute("""
            INSERT OR REPLACE INTO diagnostic_logs (id, timestamp, error_code, category, severity, title, root_cause, recommended_action, technical_details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report["id"], report["timestamp"], report["errorCode"], report["category"],
            report["severity"], report["title"], report["rootCause"],
            report["recommendedAction"], report.get("technicalDetails")
        ))
        conn.commit()
        conn.close()

    @staticmethod
    def get_recent_diagnostics(limit: int = 25) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        rows = conn.execute("""
            SELECT id, timestamp, error_code, category, severity, title, root_cause, recommended_action, technical_details
            FROM diagnostic_logs
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [{
            "id": r["id"],
            "timestamp": r["timestamp"],
            "errorCode": r["error_code"],
            "category": r["category"],
            "severity": r["severity"],
            "title": r["title"],
            "rootCause": r["root_cause"],
            "recommendedAction": r["recommended_action"],
            "technicalDetails": r["technical_details"],
        } for r in rows]
