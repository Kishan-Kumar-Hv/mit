import os
import hashlib
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from pymongo import MongoClient

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb+srv://kishankumarhv5_db_user:AoJqQnF57zkBXgWe@cluster0.fqxsirr.mongodb.net/?appName=Cluster0"
)

app = FastAPI(title="Chatvia FastAPI MongoDB Atlas Service", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect to MongoDB Atlas
mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=15000)
db = mongo_client["chatvia"]
users_coll = db["users"]
friend_requests_coll = db["friend_requests"]
messages_coll = db["messages"]
diagnostics_coll = db["diagnostics"]

@app.get("/")
def home():
    return {
        "message": "Chatvia FastAPI MongoDB Atlas Service Online",
        "database": "MongoDB Atlas (Cluster0 Live Feed 🍃)",
        "collections": ["users", "friend_requests", "messages", "diagnostics"]
    }

@app.get("/api/health")
def health():
    try:
        user_count = users_coll.count_documents({})
        msg_count = messages_coll.count_documents({})
        return {
            "status": "ok",
            "db": "MongoDB Atlas (Connected • Cluster0 Live Feed 🍃)",
            "usersCount": user_count,
            "messagesCount": msg_count,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/messages")
def get_messages(user1: str, user2: str):
    docs = list(messages_coll.find({
        "$or": [
            {"senderId": user1, "receiverId": user2},
            {"senderId": user2, "receiverId": user1}
        ]
    }, {"_id": 0}).sort("timestamp", 1))
    return {"messages": docs, "allowed": True}

@app.get("/api/users/lookup")
def lookup_user(userIdCode: str):
    clean = userIdCode.strip()
    doc = users_coll.find_one({
        "$or": [
            {"userIdCode": {"$regex": f"^{clean}$", "$options": "i"}},
            {"username": {"$regex": f"^{clean}$", "$options": "i"}}
        ]
    }, {"_id": 0, "passwordHash": 0})
    if not doc:
        raise HTTPException(status_code=404, detail=f"No user found with ID '{clean}'.")
    return {"user": doc}

@app.post("/api/admin/reseed")
def reseed_mongo():
    from database import hash_password
    users_coll.delete_many({})
    friend_requests_coll.delete_many({})
    messages_coll.delete_many({})
    diagnostics_coll.delete_many({})

    demo_users = [
        {
            "id": "u_doris",
            "userIdCode": "UID-7001",
            "username": "doris",
            "email": "doris@gmail.com",
            "fullName": "Doris Brown",
            "passwordHash": hashlib.sha256("doris123".encode()).hexdigest(),
            "avatar": "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=150",
            "bio": "Product Designer & Tech Enthusiast 🎨",
            "createdAt": datetime.utcnow().isoformat()
        },
        {
            "id": "u_patrick",
            "userIdCode": "UID-7002",
            "username": "patrick",
            "email": "patrick@gmail.com",
            "fullName": "Patrick Hendricks",
            "passwordHash": hashlib.sha256("patrick123".encode()).hexdigest(),
            "avatar": "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150",
            "bio": "Software Architect & Coffee lover ☕",
            "createdAt": datetime.utcnow().isoformat()
        },
        {
            "id": "u_steve",
            "userIdCode": "UID-7004",
            "username": "steve",
            "email": "steve@gmail.com",
            "fullName": "Steve Walker",
            "passwordHash": hashlib.sha256("steve123".encode()).hexdigest(),
            "avatar": "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150",
            "bio": "DevOps Engineer | Cloud Infrastructure ☁️",
            "createdAt": datetime.utcnow().isoformat()
        },
        {
            "id": "u_mark",
            "userIdCode": "UID-7003",
            "username": "mark",
            "email": "mark@gmail.com",
            "fullName": "Mark Messer",
            "passwordHash": hashlib.sha256("mark123".encode()).hexdigest(),
            "avatar": "https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=150",
            "bio": "Full-Stack Developer 💻",
            "createdAt": datetime.utcnow().isoformat()
        },
        {
            "id": "u_emily",
            "userIdCode": "UID-7005",
            "username": "emily",
            "email": "emily@gmail.com",
            "fullName": "Emily Clark",
            "passwordHash": hashlib.sha256("emily123".encode()).hexdigest(),
            "avatar": "https://images.unsplash.com/photo-1438761681033-6461ffad8d80?w=150",
            "bio": "UI/UX Researcher & Writer 📚",
            "createdAt": datetime.utcnow().isoformat()
        }
    ]
    users_coll.insert_many(demo_users)

    demo_friends = [
        {"id": "fr_1", "senderId": "u_patrick", "receiverId": "u_doris", "status": "accepted", "createdAt": datetime.utcnow().isoformat()},
        {"id": "fr_2", "senderId": "u_mark", "receiverId": "u_doris", "status": "accepted", "createdAt": datetime.utcnow().isoformat()}
    ]
    friend_requests_coll.insert_many(demo_friends)

    demo_msgs = [
        {"id": "m_1", "senderId": "u_doris", "receiverId": "u_patrick", "content": "Good morning", "messageType": "text", "securityScore": 0, "securityLevel": "safe", "latencyMs": 8, "timestamp": datetime.utcnow().isoformat()},
        {"id": "m_2", "senderId": "u_doris", "receiverId": "u_patrick", "content": "Yeah everything is fine", "messageType": "text", "securityScore": 0, "securityLevel": "safe", "latencyMs": 11, "timestamp": datetime.utcnow().isoformat()},
        {"id": "m_3", "senderId": "u_doris", "receiverId": "u_patrick", "content": "& Next meeting tomorrow 10.00AM", "messageType": "text", "securityScore": 0, "securityLevel": "safe", "latencyMs": 7, "timestamp": datetime.utcnow().isoformat()}
    ]
    messages_coll.insert_many(demo_msgs)

    return {"status": "ok", "message": "MongoDB Atlas cleared and fresh seed data created!"}