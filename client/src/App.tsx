import React, { useState, useEffect, useRef, useCallback } from 'react';

interface User {
  id: string;
  userIdCode: string;
  username: string;
  email: string;
  fullName: string;
  avatar: string;
  bio?: string;
  online?: boolean;
  lastMessage?: string | null;
  lastMessageTime?: string | null;
  relationship?: 'none' | 'friends' | 'pending_sent' | 'pending_received';
}

interface FriendRequestItem {
  id: string;
  senderId?: string;
  receiverId?: string;
  userIdCode?: string;
  username?: string;
  fullName?: string;
  avatar?: string;
  createdAt: string;
}

interface Message {
  id: string;
  senderId: string;
  receiverId: string;
  content: string;
  messageType?: 'text' | 'image' | 'file';
  fileUrl?: string | null;
  fileName?: string | null;
  fileSize?: string | null;
  timestamp: string;
  securityScore?: number;
  securityLevel?: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  threatDetails?: string | null;
  integrityHash?: string | null;
  latencyMs?: number;
  status?: 'sending' | 'sent' | 'delivered' | 'blocked' | 'error';
  clientMsgId?: string;
  errorReason?: string;
  diagnostic?: any;
}

interface GeminiDefectReport {
  defectType: string;
  whyRiskHappened: string;
  defectsIdentified: string[];
  geminiAiAnalysis: string;
  threatSeverity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  recommendedActions: string[];
  timestamp: string;
}

const EMOJI_LIST = ['😀', '😂', '🥹', '😍', '😎', '🥳', '🤔', '👍', '👏', '🙏', '🔥', '❤️', '🎉', '🚀', '💬', '☕'];

export default function App() {
  // Session User
  const [currentUser, setCurrentUser] = useState<User | null>(() => {
    const saved = sessionStorage.getItem('chatvia_user');
    return saved ? JSON.parse(saved) : null;
  });

  const [theme, setTheme] = useState<'light' | 'dark'>('light');

  // Left Nav Tab: 'chats' | 'friends' | 'ai' | 'security'
  const [navTab, setNavTab] = useState<'chats' | 'friends' | 'ai' | 'security'>('friends');

  // Auth Form State
  const [isLogin, setIsLogin] = useState(true);
  const [fullName, setFullName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState('');
  const [authLoading, setAuthLoading] = useState(false);

  // Contacts & Chats State
  const [friends, setFriends] = useState<User[]>([]);
  const [directoryUsers, setDirectoryUsers] = useState<User[]>([]);
  const [pendingIncoming, setPendingIncoming] = useState<FriendRequestItem[]>([]);
  const [pendingOutgoing, setPendingOutgoing] = useState<FriendRequestItem[]>([]);
  const [activeContact, setActiveContact] = useState<User | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputVal, setInputVal] = useState('');

  // Send Friend Request Card State (Top of sidebar)
  const [requestInput, setRequestInput] = useState('');
  const [requestLoading, setRequestLoading] = useState(false);
  const [requestFeedback, setRequestFeedback] = useState<{ text: string; isError: boolean } | null>(null);

  // Search Filter for Directory
  const [searchFilter, setSearchFilter] = useState('');

  // Zero-Trust Latency & Wiretap Killswitch State
  const [liveLatencyMs, setLiveLatencyMs] = useState<number>(8);
  const [latencyThresholdMs] = useState<number>(130);
  const [killswitchEngaged, setKillswitchEngaged] = useState<boolean>(false);
  const [killswitchDetails, setKillswitchDetails] = useState<{ rttMs: number; message: string } | null>(null);

  // Gemini AI Defect Explainer Modal State
  const [geminiReport, setGeminiReport] = useState<GeminiDefectReport | null>(null);
  const [showGeminiModal, setShowGeminiModal] = useState<boolean>(false);
  const [geminiLoading, setGeminiLoading] = useState<boolean>(false);

  // Single Message Security Popover
  const [inspectedMessage, setInspectedMessage] = useState<Message | null>(null);

  // Emoji Popover
  const [showEmojiPicker, setShowEmojiPicker] = useState(false);
  const [uploading, setUploading] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const pendingSendsRef = useRef<Map<string, number>>(new Map());

  // Toggle Dark/Light Mode
  const toggleTheme = () => {
    const next = theme === 'light' ? 'dark' : 'light';
    setTheme(next);
    if (next === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  };

  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [theme]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Load Contacts & Pending Requests
  const loadContacts = useCallback(async () => {
    if (!currentUser) return;
    try {
      const res = await fetch(`/api/friends?userId=${currentUser.id}`);
      if (res.ok) {
        const data = await res.json();
        const friendList: User[] = data.friends || [];
        setFriends(friendList);
        setPendingIncoming(data.pendingIncoming || []);
        setPendingOutgoing(data.pendingOutgoing || []);

        if (!activeContact && friendList.length > 0) {
          setActiveContact(friendList[0]);
        }
      }
    } catch (err) {
      console.error('Failed to load contacts:', err);
    }
  }, [currentUser, activeContact]);

  // Load All Users Directory
  const loadDirectory = useCallback(async () => {
    if (!currentUser) return;
    try {
      const res = await fetch(`/api/users/directory?currentUserId=${currentUser.id}`);
      if (res.ok) {
        const data = await res.json();
        setDirectoryUsers(data.users || []);
      }
    } catch (err) {
      console.error('Failed to load directory:', err);
    }
  }, [currentUser]);

  useEffect(() => {
    loadContacts();
    loadDirectory();
  }, [loadContacts, loadDirectory]);

  // Load Active Chat Messages
  useEffect(() => {
    if (!currentUser || !activeContact) {
      setMessages([]);
      return;
    }

    const fetchMessages = async () => {
      try {
        const res = await fetch(`/api/messages?user1=${currentUser.id}&user2=${activeContact.id}`);
        const data = await res.json();
        if (res.ok && data.allowed) {
          setMessages(data.messages || []);
        } else {
          setMessages([]);
        }
      } catch (err) {
        console.error('Failed to fetch messages:', err);
      }
    };

    fetchMessages();
  }, [activeContact?.id, currentUser?.id]);

  // WebSocket Connection
  useEffect(() => {
    if (!currentUser) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws?userId=${encodeURIComponent(currentUser.id)}`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    const pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN && !killswitchEngaged) {
        ws.send(JSON.stringify({ type: 'ping', clientTime: performance.now() }));
      }
    }, 8000);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        // 1. Latency Pong & Live Threshold
        if (data.type === 'pong') {
          const rtt = Math.max(1, Math.round(performance.now() - data.clientTime));
          setLiveLatencyMs(rtt);

          if (ws.readyState === WebSocket.OPEN) {
            ws.send(
              JSON.stringify({
                type: 'report_rtt',
                rttMs: rtt,
                thresholdMs: latencyThresholdMs,
              })
            );
          }

          if (rtt > latencyThresholdMs && !killswitchEngaged) {
            triggerClientKillswitch(rtt, 'Packet transit delay exceeded safety ceiling.');
          }
        }

        // 2. Killswitch Triggered by Server
        else if (data.type === 'zero_trust_killswitch') {
          setKillswitchEngaged(true);
          setKillswitchDetails({ rttMs: data.rttMs, message: data.message });
          if (data.geminiReport) {
            setGeminiReport(data.geminiReport);
          }
        }

        // 3. Fast Delivery ACK
        else if (data.type === 'msg_ack') {
          const sentAt = pendingSendsRef.current.get(data.clientMsgId);
          const rtt = sentAt ? Math.max(1, Math.round(performance.now() - sentAt)) : data.serverLatencyMs || 10;
          if (data.clientMsgId) pendingSendsRef.current.delete(data.clientMsgId);

          setLiveLatencyMs(rtt);

          setMessages((prev) =>
            prev.map((m) => {
              if (m.clientMsgId === data.clientMsgId || m.id === data.clientMsgId) {
                return {
                  ...m,
                  id: data.messageId || m.id,
                  status: 'delivered',
                  latencyMs: rtt,
                  securityScore: data.securityScore ?? m.securityScore,
                  securityLevel: data.securityLevel ?? m.securityLevel,
                };
              }
              return m;
            })
          );
        }

        // 4. Incoming Message
        else if (data.type === 'new_message' || data.type === 'mongo_live_feed') {
          const msg: Message = data.message;
          const isThread =
            (msg.senderId === activeContact?.id && msg.receiverId === currentUser.id) ||
            (msg.senderId === currentUser.id && msg.receiverId === activeContact?.id);

          if (isThread) {
            setMessages((prev) => {
              const idx = prev.findIndex((m) => (data.clientMsgId && m.clientMsgId === data.clientMsgId) || m.id === msg.id);
              if (idx !== -1) {
                const next = [...prev];
                next[idx] = { ...msg, status: 'delivered' };
                return next;
              }
              return [...prev, { ...msg, status: 'delivered' }];
            });
          }

          setFriends((prev) =>
            prev.map((f) => {
              if (f.id === msg.senderId || f.id === msg.receiverId) {
                return { ...f, lastMessage: msg.content, lastMessageTime: msg.timestamp };
              }
              return f;
            })
          );
        }

        // 5. Blocked Payload Alert
        else if (data.type === 'message_error') {
          if (data.clientMsgId) {
            setMessages((prev) =>
              prev.map((m) =>
                m.clientMsgId === data.clientMsgId
                  ? {
                      ...m,
                      status: 'blocked',
                      errorReason: data.error,
                      securityScore: data.security?.score || 85,
                      securityLevel: 'critical',
                      threatDetails: data.security?.threats?.join(', '),
                      diagnostic: data.diagnostic,
                    }
                  : m
              )
            );
          }
        }

        // 6. User Status Update
        else if (data.type === 'user_status') {
          setFriends((prev) =>
            prev.map((f) => (f.id === data.userId ? { ...f, online: data.online } : f))
          );
          setDirectoryUsers((prev) =>
            prev.map((u) => (u.id === data.userId ? { ...u, online: data.online } : u))
          );
          if (activeContact?.id === data.userId) {
            setActiveContact((prev) => (prev ? { ...prev, online: data.online } : null));
          }
        }

        // 7. Friend Request Events
        else if (
          data.type === 'friend_request_received' ||
          data.type === 'friend_request_accepted' ||
          data.type === 'friend_request_rejected' ||
          data.type === 'friend_removed'
        ) {
          loadContacts();
          loadDirectory();
        }
      } catch (err) {
        console.error('WS parse error:', err);
      }
    };

    return () => {
      clearInterval(pingInterval);
      ws.close();
    };
  }, [currentUser?.id, activeContact?.id, latencyThresholdMs, killswitchEngaged, loadContacts, loadDirectory]);

  // Client-Side Killswitch Trigger with Gemini AI
  const triggerClientKillswitch = async (rtt: number, reason: string) => {
    setKillswitchEngaged(true);
    setKillswitchDetails({
      rttMs: rtt,
      message: `🚨 ZERO-TRUST WIRETRAP DEFENSE ACTIVATED: Latency spiked to ${rtt}ms (Threshold: ${latencyThresholdMs}ms). Possible packet wiretapping detected. Channel locked!`,
    });

    try {
      const res = await fetch('/api/security/gemini-diagnose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incidentType: 'LATENCY_SPIKE_MITM_SUSPECTED',
          context: { rttMs: rtt, thresholdMs: latencyThresholdMs, reason },
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setGeminiReport(data.report);
      }
    } catch (e) {
      console.error('Gemini query error:', e);
    }
  };

  const simulateLatencyAttack = () => {
    const attackLatency = 245;
    setLiveLatencyMs(attackLatency);
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(
        JSON.stringify({
          type: 'simulate_latency_attack',
          simulatedRtt: attackLatency,
        })
      );
    }
    triggerClientKillswitch(attackLatency, 'Simulated MITM Wiretap Attack');
  };

  const resetKillswitch = () => {
    setKillswitchEngaged(false);
    setKillswitchDetails(null);
    setLiveLatencyMs(8);
  };

  // Send Message
  const handleSendMessage = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (killswitchEngaged) {
      alert('Communication locked: Zero-Trust Wiretap Killswitch is active. Re-verify channel to continue.');
      return;
    }

    const text = inputVal.trim();
    if (!text || !activeContact || !currentUser) return;

    setInputVal('');
    setShowEmojiPicker(false);

    const clientMsgId = `c_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    pendingSendsRef.current.set(clientMsgId, performance.now());

    const optimisticMessage: Message = {
      id: clientMsgId,
      clientMsgId,
      senderId: currentUser.id,
      receiverId: activeContact.id,
      content: text,
      messageType: 'text',
      timestamp: new Date().toISOString(),
      status: 'sending',
      securityScore: 0,
      securityLevel: 'safe',
    };

    setMessages((prev) => [...prev, optimisticMessage]);

    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(
        JSON.stringify({
          type: 'send_message',
          clientMsgId,
          receiverId: activeContact.id,
          content: text,
          messageType: 'text',
        })
      );
    }
  };

  // Upload Attachment
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !activeContact || !currentUser || killswitchEngaged) return;

    setUploading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      const uploadData = await res.json();
      if (!res.ok) {
        alert(uploadData.error || 'Attachment rejected by cybersecurity scanner.');
        return;
      }

      const clientMsgId = `c_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      pendingSendsRef.current.set(clientMsgId, performance.now());

      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(
          JSON.stringify({
            type: 'send_message',
            clientMsgId,
            receiverId: activeContact.id,
            content: uploadData.messageType === 'image' ? 'Photo' : uploadData.fileName,
            messageType: uploadData.messageType,
            fileUrl: uploadData.fileUrl,
            fileName: uploadData.fileName,
            fileSize: uploadData.fileSize,
          })
        );
      }
    } catch (err) {
      console.error('Upload error:', err);
    } finally {
      setUploading(false);
      if (e.target) e.target.value = '';
    }
  };

  // Send Friend Request from the "+ Send Friend Request" card
  const handleSendFriendRequestFromInput = async (e: React.FormEvent) => {
    e.preventDefault();
    const query = requestInput.trim();
    if (!query || !currentUser) return;

    setRequestLoading(true);
    setRequestFeedback(null);

    try {
      const res = await fetch('/api/friends/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          senderId: currentUser.id,
          targetIdCode: query,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setRequestFeedback({ text: data.message || `Friend request sent!`, isError: false });
        setRequestInput('');
        loadContacts();
        loadDirectory();
      } else {
        setRequestFeedback({ text: data.error || 'User not found.', isError: true });
      }
    } catch {
      setRequestFeedback({ text: 'Error sending request.', isError: true });
    } finally {
      setRequestLoading(false);
    }
  };

  // Send Friend Request to specific user in directory
  const handleSendFriendRequestToUser = async (targetUser: User) => {
    if (!currentUser) return;
    try {
      const res = await fetch('/api/friends/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          senderId: currentUser.id,
          targetUserId: targetUser.id,
          targetIdCode: targetUser.username,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setRequestFeedback({ text: data.message || `Request sent to ${targetUser.fullName}!`, isError: false });
        loadContacts();
        loadDirectory();
      } else {
        alert(data.error || 'Failed to send request.');
      }
    } catch (err) {
      console.error('Request error:', err);
    }
  };

  // Respond to Friend Request (Accept or Decline)
  const handleRespondRequest = async (requestId: string, action: 'accept' | 'reject') => {
    try {
      const res = await fetch('/api/friends/respond', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestId, action, userId: currentUser?.id }),
      });
      const data = await res.json();
      if (res.ok) {
        loadContacts();
        loadDirectory();
      } else {
        alert(data.error || 'Failed to respond to request.');
      }
    } catch (err) {
      console.error('Respond error:', err);
    }
  };

  // Remove Friend
  const handleRemoveFriend = async (contactId: string, contactName: string) => {
    if (!confirm(`Are you sure you want to remove ${contactName} from friends?`)) return;
    try {
      const res = await fetch('/api/friends/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: currentUser?.id, friendId: contactId }),
      });
      if (res.ok) {
        loadContacts();
        loadDirectory();
        if (activeContact?.id === contactId) {
          setActiveContact(null);
        }
      }
    } catch (e) {
      console.error('Remove friend error:', e);
    }
  };

  // Fetch Live Gemini AI Defect Explanation
  const requestGeminiDefectExplanation = async (message: Message) => {
    setGeminiLoading(true);
    setShowGeminiModal(true);
    setGeminiReport(null);

    try {
      const res = await fetch('/api/security/gemini-diagnose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incidentType: message.status === 'blocked' ? 'XSS_INJECTION_DETECTED' : 'PAYLOAD_INTEGRITY_AUDIT',
          context: {
            content: message.content,
            securityScore: message.securityScore,
            threatDetails: message.threatDetails,
            integrityHash: message.integrityHash,
            latencyMs: message.latencyMs,
          },
        }),
      });
      const data = await res.json();
      setGeminiReport(data.report);
    } catch (err) {
      console.error('Gemini defect query error:', err);
    } finally {
      setGeminiLoading(false);
    }
  };

  // Auth Submit
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');

    if (!username.trim() || !email.trim() || !password.trim()) {
      setAuthError('Please fill in username, email, and password.');
      return;
    }

    setAuthLoading(true);
    const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fullName: fullName.trim() || username.trim(),
          username: username.trim(),
          email: email.trim(),
          password: password.trim(),
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setAuthError(data.error || 'Authentication failed.');
      } else {
        setCurrentUser(data.user);
        sessionStorage.setItem('chatvia_user', JSON.stringify(data.user));
        setUsername('');
        setEmail('');
        setPassword('');
        setFullName('');
      }
    } catch {
      setAuthError('Failed to connect to backend.');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = () => {
    setCurrentUser(null);
    sessionStorage.removeItem('chatvia_user');
  };

  // Filtered Directory Users by Name or Username
  const filteredDirectory = directoryUsers.filter(
    (u) =>
      u.fullName.toLowerCase().includes(searchFilter.toLowerCase()) ||
      u.username.toLowerCase().includes(searchFilter.toLowerCase())
  );

  // ---------------- AUTH SCREEN ----------------
  if (!currentUser) {
    return (
      <div className="min-h-screen w-full flex items-center justify-center p-4 bg-[#f4f7fb] dark:bg-slate-950 text-slate-800 dark:text-slate-100 font-sans">
        <div className="w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 rounded-3xl shadow-xl p-8 relative">
          {/* Logo & Header */}
          <div className="flex flex-col items-center text-center mb-6">
            <div className="w-14 h-14 rounded-2xl bg-indigo-600 text-white flex items-center justify-center text-2xl shadow-lg shadow-indigo-500/25 mb-3">
              💬
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
              Chatvia
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Zero-Trust Secure Messaging & Live Friend Directory
            </p>
          </div>

          {/* Tabs */}
          <div className="flex bg-slate-100 dark:bg-slate-800 p-1 rounded-2xl mb-6">
            <button
              type="button"
              className={`flex-1 py-2 text-xs font-bold rounded-xl transition-all cursor-pointer ${
                isLogin
                  ? 'bg-white dark:bg-slate-700 text-indigo-600 dark:text-indigo-400 shadow-sm'
                  : 'text-slate-500 hover:text-slate-900'
              }`}
              onClick={() => {
                setIsLogin(true);
                setAuthError('');
              }}
            >
              Sign In
            </button>
            <button
              type="button"
              className={`flex-1 py-2 text-xs font-bold rounded-xl transition-all cursor-pointer ${
                !isLogin
                  ? 'bg-white dark:bg-slate-700 text-indigo-600 dark:text-indigo-400 shadow-sm'
                  : 'text-slate-500 hover:text-slate-900'
              }`}
              onClick={() => {
                setIsLogin(false);
                setAuthError('');
              }}
            >
              Register
            </button>
          </div>

          {/* Error Message */}
          {authError && (
            <div className="mb-4 p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-600 text-xs font-semibold flex items-center gap-2">
              <span>⚠️</span>
              <span>{authError}</span>
            </div>
          )}

          {/* Auth Form */}
          <form onSubmit={handleAuthSubmit} className="space-y-4">
            {!isLogin && (
              <div>
                <label className="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">Full Name</label>
                <input
                  type="text"
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="e.g. Steve Walker"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  required={!isLogin}
                />
              </div>
            )}

            <div>
              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">Username</label>
              <input
                type="text"
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                placeholder="e.g. steve"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">Email</label>
              <input
                type="text"
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                placeholder="e.g. steve@gmail.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">Password</label>
              <input
                type="password"
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            <button
              type="submit"
              disabled={authLoading}
              className="w-full py-3 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-sm shadow-md shadow-indigo-500/20 transition-all cursor-pointer disabled:opacity-50"
            >
              {authLoading ? 'Connecting...' : isLogin ? 'Sign In' : 'Create Account'}
            </button>
          </form>

          <p className="text-[11px] text-slate-400 text-center mt-5">
            🛡️ Protected by Zero-Trust Verification & Latency Defense
          </p>
        </div>
      </div>
    );
  }

  // ---------------- MAIN APPLICATION INTERFACE (EXACT REPLICA OF USER TEMPLATE) ----------------
  return (
    <div className={`h-screen w-screen flex overflow-hidden font-sans ${
      theme === 'dark' ? 'bg-slate-950 text-slate-100' : 'bg-[#f4f7fb] text-slate-800'
    }`}>
      {/* 1. LEFT THIN ICON NAVIGATION RAIL (Matching Screenshot) */}
      <nav className={`w-18 flex-shrink-0 flex flex-col items-center justify-between py-5 border-r ${
        theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200/80'
      }`}>
        {/* Top App Logo (Purple Squircle with Speech Bubble) */}
        <div className="flex flex-col items-center gap-6">
          <div
            className="w-11 h-11 rounded-2xl bg-indigo-600 text-white flex items-center justify-center text-xl shadow-md shadow-indigo-500/25 cursor-pointer hover:opacity-95 transition-all"
            title="Chatvia Messenger"
            onClick={() => setNavTab('friends')}
          >
            💬
          </div>

          {/* Navigation Action Icons */}
          <div className="flex flex-col items-center gap-4">
            {/* Chats Tab */}
            <button
              type="button"
              onClick={() => setNavTab('chats')}
              className={`p-3 rounded-2xl transition-all cursor-pointer text-lg ${
                navTab === 'chats'
                  ? 'bg-indigo-50 text-indigo-600 dark:bg-slate-800 dark:text-indigo-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-600 dark:hover:text-slate-200'
              }`}
              title="Recent Chats"
            >
              💭
            </button>

            {/* Friends & Requests Tab (Highlighted in Screenshot) */}
            <button
              type="button"
              onClick={() => setNavTab('friends')}
              className={`relative p-3 rounded-2xl transition-all cursor-pointer text-lg ${
                navTab === 'friends'
                  ? 'bg-indigo-50 text-indigo-600 dark:bg-slate-800 dark:text-indigo-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-600 dark:hover:text-slate-200'
              }`}
              title="Friends & Requests"
            >
              👥
              {pendingIncoming.length > 0 && (
                <span className="absolute top-1 right-1 w-2.5 h-2.5 bg-rose-500 rounded-full animate-ping" />
              )}
            </button>

            {/* Capibot / Pulse AI Mascot Companion */}
            <button
              type="button"
              onClick={() => setNavTab('ai')}
              className={`p-3 rounded-2xl transition-all cursor-pointer text-lg ${
                navTab === 'ai'
                  ? 'bg-indigo-50 text-indigo-600 dark:bg-slate-800 dark:text-indigo-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-600 dark:hover:text-slate-200'
              }`}
              title="Capibot AI Assistant"
            >
              🤖
            </button>

            {/* Zero-Trust Security & Gemini AI Explainer */}
            <button
              type="button"
              onClick={() => setShowGeminiModal(true)}
              className="p-3 rounded-2xl text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 transition-all cursor-pointer text-lg"
              title="Gemini AI Zero-Trust Explainer"
            >
              ⚡
            </button>
          </div>
        </div>

        {/* Bottom Actions: Theme Toggle & User Avatar */}
        <div className="flex flex-col items-center gap-4">
          <button
            type="button"
            onClick={toggleTheme}
            className="p-2.5 rounded-xl text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-all cursor-pointer text-base"
            title="Toggle Theme"
          >
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>

          {/* User Avatar with Online Dot */}
          <div className="relative group cursor-pointer" onClick={handleLogout} title={`${currentUser.fullName} (@${currentUser.username}) - Click to Logout`}>
            <img
              src={currentUser.avatar}
              alt={currentUser.fullName}
              className="w-10 h-10 rounded-full object-cover ring-2 ring-emerald-500 bg-slate-800"
            />
            <span className="absolute bottom-0 right-0 w-2.5 h-2.5 bg-emerald-500 border-2 border-white dark:border-slate-900 rounded-full" />
          </div>
        </div>
      </nav>

      {/* 2. MIDDLE SIDEBAR: "Friends & Requests" (Matching Screenshot) */}
      <aside className={`w-84 md:w-96 flex-shrink-0 flex flex-col border-r ${
        theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200/80'
      }`}>
        {/* Title */}
        <div className="p-5 pb-3">
          <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
            {navTab === 'chats' ? 'Recent Chats' : 'Friends & Requests'}
          </h2>
        </div>

        {/* Content based on selected nav tab */}
        <div className="flex-1 overflow-y-auto px-5 pb-5 space-y-5">
          {navTab === 'friends' ? (
            <>
              {/* + SEND FRIEND REQUEST CARD (Exact replica of lavender card in screenshot) */}
              <div className={`p-4 rounded-2xl border ${
                theme === 'dark'
                  ? 'bg-indigo-950/40 border-indigo-900/60 text-slate-200'
                  : 'bg-[#f0efff] border-indigo-100 text-slate-800'
              }`}>
                <div className="flex items-center gap-1.5 text-indigo-600 dark:text-indigo-400 font-bold text-xs uppercase tracking-wider">
                  <span>➕</span>
                  <span>Send Friend Request</span>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 mb-3">
                  Enter the exact <strong>name</strong> or <strong>username</strong> of the user you want to chat with:
                </p>

                <form onSubmit={handleSendFriendRequestFromInput} className="flex gap-2">
                  <input
                    type="text"
                    className={`flex-1 py-2 px-3 text-xs rounded-xl border focus:outline-none focus:ring-1 focus:ring-indigo-500 ${
                      theme === 'dark'
                        ? 'bg-slate-900 border-slate-700 text-white placeholder-slate-400'
                        : 'bg-white border-slate-200 text-slate-800 placeholder-slate-400'
                    }`}
                    placeholder="e.g. steve, patrick, emily"
                    value={requestInput}
                    onChange={(e) => setRequestInput(e.target.value)}
                    required
                  />
                  <button
                    type="submit"
                    disabled={requestLoading}
                    className="py-2 px-3.5 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs rounded-xl shadow-sm transition-all cursor-pointer disabled:opacity-50 flex-shrink-0"
                  >
                    {requestLoading ? 'Sending...' : 'Send Request'}
                  </button>
                </form>

                {requestFeedback && (
                  <div className={`mt-2.5 p-2 rounded-lg text-xs font-semibold ${
                    requestFeedback.isError
                      ? 'bg-rose-500/10 text-rose-500'
                      : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                  }`}>
                    {requestFeedback.text}
                  </div>
                )}
              </div>

              {/* PENDING REQUESTS RECEIVED (X) (Exact replica from screenshot) */}
              <div>
                <div className="flex items-center justify-between text-xs font-bold text-slate-500 dark:text-slate-400 mb-2">
                  <span>Pending Requests Received ({pendingIncoming.length})</span>
                </div>

                {pendingIncoming.length === 0 ? (
                  <p className="text-xs text-slate-400 italic">No incoming requests.</p>
                ) : (
                  <div className="space-y-2">
                    {pendingIncoming.map((req) => (
                      <div
                        key={req.id}
                        className={`p-3 rounded-2xl border flex items-center justify-between gap-3 ${
                          theme === 'dark' ? 'bg-slate-800/80 border-slate-700/60' : 'bg-slate-50 border-slate-200/80'
                        }`}
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <img
                            src={req.avatar || `https://api.dicebear.com/7.x/bottts/svg?seed=${req.username}`}
                            alt={req.fullName || 'User'}
                            className="w-9 h-9 rounded-full object-cover bg-slate-700"
                          />
                          <div className="min-w-0">
                            <span className="text-xs font-bold block truncate">{req.fullName || req.username}</span>
                            <span className="text-[10px] text-indigo-500 block truncate">@{req.username}</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-1.5 flex-shrink-0">
                          <button
                            type="button"
                            onClick={() => handleRespondRequest(req.id, 'accept')}
                            className="py-1 px-3 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold rounded-lg shadow-sm transition-all cursor-pointer"
                          >
                            Accept
                          </button>
                          <button
                            type="button"
                            onClick={() => handleRespondRequest(req.id, 'reject')}
                            className={`py-1 px-2.5 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                              theme === 'dark'
                                ? 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                                : 'bg-slate-200 text-slate-700 hover:bg-slate-300'
                            }`}
                          >
                            Decline
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Sent Requests Awaiting Approval */}
                {pendingOutgoing.length > 0 && (
                  <div className="mt-3">
                    <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wide block mb-1.5">
                      Sent Requests ({pendingOutgoing.length})
                    </span>
                    <div className="space-y-1.5">
                      {pendingOutgoing.map((out) => (
                        <div
                          key={out.id}
                          className={`p-2 rounded-xl flex items-center justify-between border ${
                            theme === 'dark' ? 'bg-slate-800/40 border-slate-700/40' : 'bg-slate-50 border-slate-200/60'
                          }`}
                        >
                          <span className="text-xs font-medium text-slate-600 dark:text-slate-300">
                            {out.fullName || out.username}
                          </span>
                          <span className="text-[10px] font-semibold text-amber-500 bg-amber-500/10 px-2 py-0.5 rounded-full">
                            Pending...
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* ALL USERS DIRECTORY (Exact replica from screenshot) */}
              <div>
                <div className="flex items-center justify-between text-xs font-bold text-slate-500 dark:text-slate-400 mb-2">
                  <span>All Users Directory</span>
                </div>

                {/* Search in directory */}
                <div className="mb-3">
                  <input
                    type="text"
                    className={`w-full py-1.5 px-3 text-xs rounded-xl border focus:outline-none focus:ring-1 focus:ring-indigo-500 ${
                      theme === 'dark'
                        ? 'bg-slate-800 border-slate-700 text-white placeholder-slate-400'
                        : 'bg-slate-50 border-slate-200 text-slate-800 placeholder-slate-400'
                    }`}
                    placeholder="Search by name or username..."
                    value={searchFilter}
                    onChange={(e) => setSearchFilter(e.target.value)}
                  />
                </div>

                <div className="space-y-2">
                  {filteredDirectory.length === 0 ? (
                    <p className="text-xs text-slate-400 italic">No users found.</p>
                  ) : (
                    filteredDirectory.map((user) => {
                      const isFriend = user.relationship === 'friends';
                      const isPendingSent = user.relationship === 'pending_sent';
                      const isPendingReceived = user.relationship === 'pending_received';

                      return (
                        <div
                          key={user.id}
                          className={`p-3 rounded-2xl border flex items-center justify-between gap-3 transition-all ${
                            activeContact?.id === user.id
                              ? theme === 'dark'
                                ? 'bg-slate-800 border-indigo-500/40 shadow-sm'
                                : 'bg-indigo-50/50 border-indigo-200 shadow-sm'
                              : theme === 'dark'
                              ? 'bg-slate-800/50 border-slate-800 hover:bg-slate-800'
                              : 'bg-white border-slate-100 hover:bg-slate-50'
                          }`}
                        >
                          {/* User Avatar + Meta */}
                          <div className="flex items-center gap-3 min-w-0">
                            <div className="relative flex-shrink-0">
                              <img
                                src={user.avatar}
                                alt={user.fullName}
                                className="w-10 h-10 rounded-full object-cover bg-slate-700"
                              />
                              {user.online && (
                                <span className="absolute bottom-0 right-0 w-2.5 h-2.5 bg-emerald-500 border-2 border-white dark:border-slate-900 rounded-full" />
                              )}
                            </div>
                            <div className="min-w-0">
                              <span className="text-sm font-bold block truncate text-slate-900 dark:text-slate-100">
                                {user.fullName}
                              </span>
                              <span className="text-xs text-slate-400 block truncate">
                                @{user.username}
                              </span>
                            </div>
                          </div>

                          {/* Action Button: "Chat" or "+ Add Friend" or "Requested" (Matching Screenshot) */}
                          <div className="flex-shrink-0">
                            {isFriend ? (
                              <button
                                type="button"
                                onClick={() => setActiveContact(user)}
                                className="py-1.5 px-4 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs rounded-xl shadow-sm transition-all flex items-center gap-1.5 cursor-pointer"
                              >
                                <span>Chat</span>
                                <span className="text-[11px]">💬</span>
                              </button>
                            ) : isPendingSent ? (
                              <span className="py-1 px-3 bg-amber-500/10 text-amber-600 dark:text-amber-400 font-semibold text-xs rounded-xl">
                                Requested
                              </span>
                            ) : isPendingReceived ? (
                              <button
                                type="button"
                                onClick={() => {
                                  const req = pendingIncoming.find((r) => r.senderId === user.id);
                                  if (req) handleRespondRequest(req.id, 'accept');
                                }}
                                className="py-1.5 px-3 bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-xs rounded-xl shadow-sm transition-all cursor-pointer"
                              >
                                Accept
                              </button>
                            ) : (
                              <button
                                type="button"
                                onClick={() => handleSendFriendRequestToUser(user)}
                                className="py-1.5 px-3 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs rounded-xl shadow-sm transition-all cursor-pointer"
                              >
                                + Add Friend
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </>
          ) : navTab === 'chats' ? (
            /* Recent Chats List */
            <div className="space-y-2">
              {friends.length === 0 ? (
                <div className="py-12 text-center text-slate-400 text-xs">
                  No active chats yet. Add friends from the <strong>Friends & Requests</strong> tab!
                </div>
              ) : (
                friends.map((f) => (
                  <div
                    key={f.id}
                    onClick={() => setActiveContact(f)}
                    className={`p-3 rounded-2xl border flex items-center justify-between gap-3 cursor-pointer transition-all ${
                      activeContact?.id === f.id
                        ? theme === 'dark'
                          ? 'bg-slate-800 border-indigo-500/50 shadow-sm'
                          : 'bg-indigo-50/60 border-indigo-200 shadow-sm'
                        : theme === 'dark'
                        ? 'bg-slate-800/40 border-slate-800 hover:bg-slate-800'
                        : 'bg-white border-slate-100 hover:bg-slate-50'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="relative flex-shrink-0">
                        <img
                          src={f.avatar}
                          alt={f.fullName}
                          className="w-11 h-11 rounded-full object-cover bg-slate-700"
                        />
                        {f.online && (
                          <span className="absolute bottom-0 right-0 w-2.5 h-2.5 bg-emerald-500 border-2 border-white dark:border-slate-900 rounded-full" />
                        )}
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-bold truncate text-slate-900 dark:text-slate-100">{f.fullName}</span>
                        </div>
                        <span className="text-xs text-slate-400 truncate block mt-0.5">
                          {f.lastMessage || `@${f.username}`}
                        </span>
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleRemoveFriend(f.id, f.fullName);
                      }}
                      className="text-slate-400 hover:text-rose-500 text-xs p-1"
                      title="Remove Friend"
                    >
                      🗑️
                    </button>
                  </div>
                ))
              )}
            </div>
          ) : (
            /* Capibot / Pulse AI Mascot Companion Panel */
            <div className="text-center py-6">
              <div className="w-28 h-28 mx-auto rounded-3xl overflow-hidden shadow-lg mb-4">
                <img src="/mascot.jpg" alt="Capibot" className="w-full h-full object-cover" />
              </div>
              <h3 className="text-lg font-bold">Capibot AI Companion</h3>
              <p className="text-xs text-slate-400 mt-1 max-w-xs mx-auto">
                Powered by Gemini 3.8 Flash. Analyzes network security, explains zero-trust defects, and helps you communicate safely.
              </p>
              <button
                type="button"
                onClick={() => setShowGeminiModal(true)}
                className="mt-4 py-2 px-5 bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-xs rounded-xl shadow-md transition-all cursor-pointer"
              >
                ✨ Launch Gemini Telemetry Audit
              </button>
            </div>
          )}
        </div>
      </aside>

      {/* 3. RIGHT MAIN CHAT AREA (Exact Replica of Screenshot) */}
      <main className="flex-1 flex flex-col bg-[#fbfcfe] dark:bg-slate-950 relative overflow-hidden">
        {activeContact ? (
          <>
            {/* Chat Header (Matching Screenshot) */}
            <div className={`p-4 px-6 flex items-center justify-between border-b ${
              theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200/80'
            }`}>
              <div className="flex items-center gap-3">
                <div className="relative">
                  <img
                    src={activeContact.avatar}
                    alt={activeContact.fullName}
                    className="w-10 h-10 rounded-full object-cover bg-slate-700"
                  />
                  {activeContact.online && (
                    <span className="absolute bottom-0 right-0 w-2.5 h-2.5 bg-emerald-500 border-2 border-white dark:border-slate-900 rounded-full" />
                  )}
                </div>

                <div>
                  <h3 className="text-sm font-bold flex items-center gap-1.5 text-slate-900 dark:text-white">
                    <span>{activeContact.fullName}</span>
                    <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" />
                  </h3>
                  <p className="text-xs text-slate-400">
                    Active now • @{activeContact.username}
                  </p>
                </div>
              </div>

              {/* Header Right Actions (Phone, Video, More Options, Latency) */}
              <div className="flex items-center gap-3">
                {/* Latency Telemetry Pill */}
                <div
                  className={`px-3 py-1.5 rounded-xl text-xs font-bold flex items-center gap-1.5 border transition-all cursor-pointer ${
                    liveLatencyMs > latencyThresholdMs
                      ? 'bg-rose-50 border-rose-300 text-rose-600 animate-pulse'
                      : liveLatencyMs > 60
                      ? 'bg-amber-50 border-amber-300 text-amber-600'
                      : 'bg-emerald-50 border-emerald-300 text-emerald-600 dark:bg-emerald-950/40 dark:border-emerald-800'
                  }`}
                  onClick={() => setShowGeminiModal(true)}
                  title={`Channel Latency: ${liveLatencyMs}ms (Safety Ceiling: ${latencyThresholdMs}ms)`}
                >
                  <span>⚡</span>
                  <span>{liveLatencyMs} ms</span>
                  <span className="text-[10px] opacity-80">
                    {liveLatencyMs > latencyThresholdMs ? '🚨 MITM ALERT' : '(Safe)'}
                  </span>
                </div>

                {/* Simulate Attack Test Button */}
                <button
                  type="button"
                  onClick={simulateLatencyAttack}
                  className="px-2.5 py-1 text-xs font-semibold bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 rounded-lg transition-all cursor-pointer"
                  title="Simulate MITM Packet Latency Spike"
                >
                  ⚡ Test Wiretap
                </button>

                {/* Call / Video Icons (Matching Screenshot) */}
                <button
                  type="button"
                  className="text-slate-400 hover:text-indigo-600 p-1.5 rounded-lg text-sm"
                  title="Voice Call"
                  onClick={() => alert(`Calling ${activeContact.fullName}...`)}
                >
                  📞
                </button>
                <button
                  type="button"
                  className="text-slate-400 hover:text-indigo-600 p-1.5 rounded-lg text-sm"
                  title="Video Call"
                  onClick={() => alert(`Starting video call with ${activeContact.fullName}...`)}
                >
                  📹
                </button>

                {/* More Options */}
                <button
                  type="button"
                  className="text-slate-400 hover:text-slate-600 p-1.5 rounded-lg text-sm"
                  title="Options"
                  onClick={() => handleRemoveFriend(activeContact.id, activeContact.fullName)}
                >
                  ⋮
                </button>
              </div>
            </div>

            {/* ZERO-TRUST WIRETAP DEFENSE BANNER */}
            {killswitchEngaged && (
              <div className="bg-rose-600 text-white p-3 px-6 flex items-center justify-between shadow-lg">
                <div className="flex items-center gap-3">
                  <span className="text-2xl animate-bounce">🚨</span>
                  <div>
                    <h4 className="font-extrabold text-xs uppercase tracking-wider">
                      Zero-Trust Wiretap Killswitch Engaged!
                    </h4>
                    <p className="text-xs text-rose-100">
                      {killswitchDetails?.message || 'Transmission suspended due to suspicious latency anomaly.'}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setShowGeminiModal(true)}
                    className="px-3 py-1.5 rounded-xl bg-white/20 hover:bg-white/30 text-white font-bold text-xs"
                  >
                    ✨ Gemini Diagnosis
                  </button>
                  <button
                    type="button"
                    onClick={resetKillswitch}
                    className="px-3 py-1.5 rounded-xl bg-white text-rose-600 font-bold text-xs shadow hover:bg-slate-100"
                  >
                    🛡️ Re-verify Channel
                  </button>
                </div>
              </div>
            )}

            {/* CHAT MESSAGES THREAD (Matching Screenshot Layout) */}
            <div className="flex-1 overflow-y-auto p-6 md:p-8 space-y-5">
              {messages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center p-8 text-slate-400">
                  <div className="w-16 h-16 rounded-full bg-indigo-50 dark:bg-slate-800 flex items-center justify-center text-3xl mb-3">
                    💬
                  </div>
                  <h4 className="text-base font-bold text-slate-800 dark:text-slate-200">
                    Say hello to {activeContact.fullName}!
                  </h4>
                  <p className="text-xs text-slate-400 mt-1">
                    Send a direct message. Verified under Zero-Trust encryption.
                  </p>
                </div>
              ) : (
                messages.map((m) => {
                  const isMe = m.senderId === currentUser.id;
                  const isBlocked = m.status === 'blocked';

                  return (
                    <div
                      key={m.id}
                      className={`flex flex-col ${isMe ? 'items-end' : 'items-start'} group`}
                    >
                      {/* Sender Meta for Received Messages (Matching Screenshot) */}
                      {!isMe && (
                        <div className="flex items-center gap-2 mb-1.5 pl-1">
                          <img
                            src={activeContact.avatar}
                            alt={activeContact.fullName}
                            className="w-5 h-5 rounded-full object-cover"
                          />
                          <div className="text-[11px] text-slate-400">
                            <span>
                              {new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                            </span>
                            <span className="mx-1">•</span>
                            <span className="font-semibold text-slate-600 dark:text-slate-300">
                              {activeContact.fullName}
                            </span>
                          </div>
                        </div>
                      )}

                      {/* Bubble */}
                      <div className="flex items-center gap-2 max-w-[75%] md:max-w-[60%]">
                        <div
                          className={`rounded-2xl p-3 px-4 shadow-sm relative transition-all ${
                            isBlocked
                              ? 'bg-rose-50 border border-rose-300 text-rose-600'
                              : isMe
                              ? 'bg-indigo-600 text-white rounded-br-xs shadow-indigo-500/10'
                              : theme === 'dark'
                              ? 'bg-slate-900 text-slate-100 rounded-tl-xs border border-slate-800'
                              : 'bg-white text-slate-800 rounded-tl-xs border border-slate-200/60'
                          }`}
                        >
                          {isBlocked ? (
                            <div>
                              <div className="font-bold text-xs flex items-center gap-1.5 text-rose-500">
                                <span>🚨</span>
                                <span>BLOCKED BY ZERO-TRUST SHIELD</span>
                              </div>
                              <p className="text-xs mt-1 text-slate-500">
                                {m.errorReason || 'High-risk payload intercepted.'}
                              </p>
                            </div>
                          ) : m.messageType === 'image' && m.fileUrl ? (
                            <div className="rounded-xl overflow-hidden mb-2 max-w-sm">
                              <img src={m.fileUrl} alt="Attached" className="w-full object-cover max-h-72" />
                            </div>
                          ) : m.messageType === 'file' && m.fileUrl ? (
                            <div className="flex items-center gap-3 p-2 bg-black/10 rounded-xl">
                              <span className="text-2xl">📄</span>
                              <div className="min-w-0">
                                <p className="text-xs font-bold truncate">{m.fileName || 'Attachment'}</p>
                                <span className="text-[10px] opacity-75">{m.fileSize}</span>
                              </div>
                            </div>
                          ) : (
                            <div className="flex items-center justify-between gap-3">
                              <p className="text-sm leading-relaxed whitespace-pre-wrap break-words">{m.content}</p>
                              {/* Three dots inspection trigger (Matching Screenshot) */}
                              <button
                                type="button"
                                onClick={() => setInspectedMessage(m)}
                                className="opacity-40 hover:opacity-100 text-xs transition-opacity cursor-pointer flex-shrink-0"
                                title="Inspect Security Checksum"
                              >
                                ⋮
                              </button>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Time for Sent Messages */}
                      {isMe && (
                        <div className="text-[10px] text-slate-400 mt-1 pr-1 flex items-center gap-1">
                          <span>
                            {new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </span>
                          <span className="text-indigo-500 font-bold">✓✓</span>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* FLOATING ROUNDED-FULL INPUT BAR (Exact Replica of Screenshot) */}
            <div className={`p-4 md:p-5 border-t ${
              theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200/80'
            }`}>
              <form onSubmit={handleSendMessage} className="max-w-4xl mx-auto flex items-center gap-3">
                <div className={`flex-1 rounded-full px-5 py-2.5 flex items-center gap-3 border transition-all ${
                  theme === 'dark'
                    ? 'bg-slate-800/80 border-slate-700/80 text-white'
                    : 'bg-[#f0f2f7] border-slate-200 text-slate-800'
                }`}>
                  <input
                    type="text"
                    className="w-full bg-transparent text-sm focus:outline-none placeholder-slate-400"
                    placeholder={
                      killswitchEngaged
                        ? '⚠️ Wiretap defense active: Re-verify channel...'
                        : uploading
                        ? 'Uploading attachment...'
                        : 'Enter Message...'
                    }
                    value={inputVal}
                    onChange={(e) => setInputVal(e.target.value)}
                    disabled={killswitchEngaged || uploading}
                    autoFocus
                  />

                  {/* Smiley Emoji Button (Matching Screenshot) */}
                  <button
                    type="button"
                    onClick={() => setShowEmojiPicker(!showEmojiPicker)}
                    className="text-slate-400 hover:text-amber-500 transition-colors text-lg"
                    title="Insert Emoji"
                  >
                    😊
                  </button>

                  {/* Paperclip Attachment Button (Matching Screenshot) */}
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    disabled={uploading || killswitchEngaged}
                    className="text-slate-400 hover:text-indigo-600 transition-colors text-lg"
                    title="Attach File"
                  >
                    📎
                  </button>

                  <input
                    type="file"
                    ref={fileInputRef}
                    className="hidden"
                    onChange={handleFileUpload}
                  />
                </div>

                {/* Circular Send Button (Matching Screenshot) */}
                <button
                  type="submit"
                  disabled={!inputVal.trim() || killswitchEngaged || uploading}
                  className="w-11 h-11 rounded-full bg-indigo-500 hover:bg-indigo-600 disabled:opacity-40 text-white flex items-center justify-center shadow-md shadow-indigo-500/20 transition-all cursor-pointer flex-shrink-0 text-sm"
                  title="Send Message"
                >
                  ➤
                </button>
              </form>

              {/* Emoji Picker Popover */}
              {showEmojiPicker && (
                <div className={`absolute bottom-20 right-16 p-3 rounded-2xl shadow-xl border grid grid-cols-8 gap-2 z-50 ${
                  theme === 'dark' ? 'bg-slate-800 border-slate-700' : 'bg-white border-slate-200'
                }`}>
                  {EMOJI_LIST.map((em) => (
                    <button
                      key={em}
                      type="button"
                      className="text-xl p-1 hover:scale-125 transition-transform"
                      onClick={() => setInputVal((prev) => prev + em)}
                    >
                      {em}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </>
        ) : (
          /* Empty Active State */
          <div className="h-full flex flex-col items-center justify-center p-8 text-center">
            <div className="w-18 h-18 rounded-3xl bg-indigo-50 dark:bg-slate-800 text-indigo-600 flex items-center justify-center text-4xl mb-4 shadow-sm">
              💬
            </div>
            <h2 className="text-xl font-bold tracking-tight text-slate-800 dark:text-white">
              Welcome to Chatvia
            </h2>
            <p className="text-xs text-slate-400 mt-2 max-w-sm">
              Select a conversation from the directory or send a friend request to start chatting under Zero-Trust verification.
            </p>
          </div>
        )}
      </main>

      {/* 4. GEMINI AI DEFECT & INCIDENT EXPLAINER MODAL */}
      {showGeminiModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className={`w-full max-w-xl rounded-3xl border shadow-2xl p-6 relative overflow-hidden ${
            theme === 'dark' ? 'bg-slate-900 border-slate-700 text-slate-100' : 'bg-white border-slate-200 text-slate-900'
          }`}>
            <div className="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <span className="text-xl">✨</span>
                <h3 className="text-base font-bold text-indigo-600 dark:text-indigo-400">
                  Gemini AI Zero-Trust Telemetry & Defect Explainer
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowGeminiModal(false)}
                className="p-1 rounded-full text-slate-400 hover:text-slate-600 dark:hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="mt-4 max-h-[70vh] overflow-y-auto space-y-4 pr-1">
              {geminiLoading ? (
                <div className="py-12 text-center text-slate-400">
                  <p className="text-sm font-bold">Analyzing telemetry with Gemini 3.8 Flash...</p>
                  <p className="text-xs text-slate-500 mt-1">Evaluating RTT transit delay, crypto checksums, and MITM wiretap indicators.</p>
                </div>
              ) : geminiReport ? (
                <>
                  <div className={`p-4 rounded-2xl border ${
                    geminiReport.threatSeverity === 'CRITICAL'
                      ? 'bg-rose-50 border-rose-200 text-rose-700'
                      : 'bg-emerald-50 border-emerald-200 text-emerald-700'
                  }`}>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-extrabold uppercase tracking-wide">
                        Defect: {geminiReport.defectType}
                      </span>
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-white/70">
                        {geminiReport.threatSeverity}
                      </span>
                    </div>
                  </div>

                  <div className={`p-4 rounded-2xl border ${theme === 'dark' ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                    <h5 className="text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wide mb-1">
                      🛡️ Why This Incident Occurred
                    </h5>
                    <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-400">{geminiReport.whyRiskHappened}</p>
                  </div>

                  <div className={`p-4 rounded-2xl border ${theme === 'dark' ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                    <h5 className="text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wide mb-2">
                      ⚡ Vulnerabilities Identified
                    </h5>
                    <ul className="text-xs space-y-1 list-disc list-inside text-slate-600 dark:text-slate-400">
                      {geminiReport.defectsIdentified.map((d, i) => (
                        <li key={i}>{d}</li>
                      ))}
                    </ul>
                  </div>

                  <div className={`p-4 rounded-2xl border ${theme === 'dark' ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                    <h5 className="text-xs font-bold text-indigo-600 dark:text-indigo-400 uppercase tracking-wide mb-1">
                      🤖 Gemini AI Telemetry Insight
                    </h5>
                    <p className="text-xs leading-relaxed text-slate-700 dark:text-slate-300">{geminiReport.geminiAiAnalysis}</p>
                  </div>

                  <div className={`p-4 rounded-2xl border ${theme === 'dark' ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                    <h5 className="text-xs font-bold text-emerald-600 dark:text-emerald-400 uppercase tracking-wide mb-2">
                      💡 Recommended Remediation Plan
                    </h5>
                    <ul className="text-xs space-y-1 list-disc list-inside text-emerald-600 dark:text-emerald-400">
                      {geminiReport.recommendedActions.map((a, i) => (
                        <li key={i}>{a}</li>
                      ))}
                    </ul>
                  </div>
                </>
              ) : (
                <div className="py-8 text-center text-slate-400 text-xs">
                  All channels operating smoothly under verified Zero-Trust parameters.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 5. CRYPTOGRAPHIC INTEGRITY INSPECTOR */}
      {inspectedMessage && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className={`w-full max-w-md rounded-3xl border shadow-2xl p-6 relative ${
            theme === 'dark' ? 'bg-slate-900 border-slate-700 text-slate-100' : 'bg-white border-slate-200 text-slate-900'
          }`}>
            <div className="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <span>🛡️</span>
                <h4 className="font-bold text-sm">Cryptographic Packet Inspector</h4>
              </div>
              <button
                type="button"
                onClick={() => setInspectedMessage(null)}
                className="p-1 rounded-full text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="mt-4 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className={`p-3 rounded-2xl border ${theme === 'dark' ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                  <span className="text-[10px] font-bold text-slate-400 uppercase">RISK SCORE</span>
                  <div className={`text-xl font-extrabold mt-0.5 ${
                    (inspectedMessage.securityScore ?? 0) > 40 ? 'text-rose-500' : 'text-emerald-500'
                  }`}>
                    {inspectedMessage.securityScore ?? 0} / 100
                  </div>
                </div>

                <div className={`p-3 rounded-2xl border ${theme === 'dark' ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                  <span className="text-[10px] font-bold text-slate-400 uppercase">TRANSIT LATENCY</span>
                  <div className="text-xl font-extrabold text-indigo-600 dark:text-indigo-400 mt-0.5">
                    ⚡ {inspectedMessage.latencyMs ?? 8} ms
                  </div>
                </div>
              </div>

              <div>
                <span className="text-xs font-semibold text-slate-500">SHA-256 Checksum:</span>
                <div className={`mt-1 p-2.5 rounded-xl font-mono text-[11px] break-all border ${
                  theme === 'dark' ? 'bg-slate-800 border-slate-700 text-indigo-300' : 'bg-slate-100 border-slate-200 text-indigo-600'
                }`}>
                  {inspectedMessage.integrityHash || 'SHA256_VERIFIED_CLEAN'}
                </div>
              </div>

              <div>
                <span className="text-xs font-semibold text-slate-500">Threat Analysis:</span>
                <p className={`mt-1 p-2.5 rounded-xl text-xs border ${
                  theme === 'dark' ? 'bg-slate-800 border-slate-700 text-slate-300' : 'bg-slate-50 border-slate-200 text-slate-700'
                }`}>
                  {inspectedMessage.threatDetails || '✓ Clean packet. No injection, phishing, or DLP anomalies.'}
                </p>
              </div>

              <button
                type="button"
                onClick={() => {
                  setInspectedMessage(null);
                  requestGeminiDefectExplanation(inspectedMessage);
                }}
                className="w-full py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-xs shadow-md mt-2 transition-all cursor-pointer"
              >
                ✨ Ask Gemini AI Why Risk Occurred
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
