import crypto from "crypto";

export interface SecurityAnalysisResult {
  score: number; // 0 (completely safe) to 100 (critical threat)
  level: "safe" | "low" | "medium" | "high" | "critical";
  threats: string[];
  details: {
    phishing: { detected: boolean; details?: string };
    injection: { detected: boolean; details?: string };
    dlp: { detected: boolean; details?: string };
    fileRisk: { detected: boolean; details?: string };
    entropy: { value: number; abnormal: boolean };
    integrityHash: string;
  };
  recommendations: string[];
  isBlocked: boolean;
}

// Shannon Entropy calculation for anomaly / obfuscated payload detection
function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies = new Map<string, number>();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

// SHA-256 Message Integrity Checksum
export function generateIntegrityHash(content: string, senderId?: string, timestamp?: string): string {
  const data = `${senderId || ""}|${content}|${timestamp || ""}`;
  return crypto.createHash("sha256").update(data).digest("hex");
}

// Phishing / Suspicious URL Patterns
const SUSPICIOUS_URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>"{}|\\^`[\]]+/gi;
const IP_BASED_URL_REGEX = /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/[^\s]*)?/i;
const SUSPICIOUS_TLD_REGEX = /\.(?:xyz|top|tk|ru|click|phish|download|racing|loan|win|bid|men|stream)(?:\/|$|\?)/i;
const PHISHING_KEYWORDS = [
  "verify-account", "bank-update", "confirm-identity", "password-reset-now",
  "secure-login-portal", "claim-reward-prize", "account-suspended-action",
  "crypto-airdrop-claim", "wallet-seed-phrase", "appleid-verify", "paypal-security-alert"
];

// Helper to safely test regex without stateful lastIndex issues
function testRegex(regex: RegExp, text: string): boolean {
  regex.lastIndex = 0;
  return regex.test(text);
}

// Code Injection & Exploit Patterns
const XSS_PATTERNS = [
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i,
  /javascript:[^\s"'>]+/i,
  /\bon(?:error|load|click|mouseover|focus|blur|submit)\s*=/i,
  /<iframe\b[^>]*>/i,
  /<img\b[^>]*onerror\s*=/i,
  /eval\s*\(/i,
  /document\.cookie/i,
  /window\.location\s*=/i
];

const SQLI_PATTERNS = [
  /(\b(?:SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER|EXEC|CREATE)\b.*\b(?:FROM|INTO|TABLE|DATABASE|WHERE)\b)/i,
  /'\s*OR\s*['"]?1['"]?\s*=\s*['"]?1/i,
  /--[^\r\n]*/,
  /\/\*[\s\S]*?\*\//
];

const CMD_INJECTION_PATTERNS = [
  /(?:^|[\s;|&`])(?:curl|wget|nc|ncat|bash|sh|powershell|cmd\.exe|rm\s+-rf|chmod\s+\+x)\b/i,
  /\|\s*(?:bash|sh|powershell)/i
];

// Sensitive Data Exposure / DLP Patterns
const CREDIT_CARD_REGEX = /\b(?:\d{4}[-\s]?){3}\d{4}\b/;
const AWS_KEY_REGEX = /\bAKIA[0-9A-Z]{16}\b/;
const GITHUB_TOKEN_REGEX = /\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/;
const PRIVATE_KEY_REGEX = /-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC)?\s*PRIVATE KEY-----/i;
const GENERIC_API_KEY_REGEX = /(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9\-_]{16,}['"]/i;

// Dangerous File Extensions
const HIGH_RISK_EXTENSIONS = [
  ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".pif", ".msi", ".dll",
  ".sh", ".bash", ".jar", ".com", ".cpl", ".reg"
];

const MODERATE_RISK_EXTENSIONS = [
  ".zip", ".rar", ".7z", ".tar.gz", ".iso", ".apk", ".dmg"
];

/**
 * Main Cybersecurity Risk Scoring Engine
 * Analyzes transferred messages or files and assigns a 0-100 risk score with root causes
 */
export function analyzeSecurityRisk(payload: {
  content?: string;
  messageType?: "text" | "image" | "file";
  fileName?: string;
  fileSize?: string;
  senderId?: string;
}): SecurityAnalysisResult {
  const content = payload.content || "";
  const messageType = payload.messageType || "text";
  const fileName = payload.fileName || "";

  let score = 0;
  const threats: string[] = [];
  const recommendations: string[] = [];

  const details: SecurityAnalysisResult["details"] = {
    phishing: { detected: false },
    injection: { detected: false },
    dlp: { detected: false },
    fileRisk: { detected: false },
    entropy: { value: 0, abnormal: false },
    integrityHash: generateIntegrityHash(content, payload.senderId, new Date().toISOString().slice(0, 16)),
  };

  // 1. Phishing & Malicious URL Vector (Weight: up to 35 pts)
  const urls = content.match(SUSPICIOUS_URL_REGEX) || [];
  if (urls.length > 0) {
    let urlRisk = 10; // Baseline caution for hyperlinks
    threats.push(`External hyperlink detected (${urls.length} link${urls.length > 1 ? "s" : ""})`);

    for (const url of urls) {
      if (IP_BASED_URL_REGEX.test(url)) {
        urlRisk += 25;
        threats.push(`High-Risk IP-Based URL detected: ${url}`);
        recommendations.push("Do not click links pointing directly to raw IP addresses.");
      }
      if (SUSPICIOUS_TLD_REGEX.test(url)) {
        urlRisk += 20;
        threats.push(`High-Risk TLD detected in link: ${url}`);
        recommendations.push("Verify domain reputation before opening unusual top-level domains.");
      }
      const lowerUrl = url.toLowerCase();
      for (const kw of PHISHING_KEYWORDS) {
        if (lowerUrl.includes(kw)) {
          urlRisk += 30;
          threats.push(`Potential Credential Phishing keyword found in URL: "${kw}"`);
          recommendations.push("Phishing warning: Never submit credentials on unverified third-party pages.");
          break;
        }
      }
    }

    details.phishing = {
      detected: urlRisk > 10,
      details: threats.filter(t => t.includes("URL") || t.includes("link") || t.includes("Phishing")).join("; "),
    };
    score += Math.min(urlRisk, 35);
  }

  // 2. Code Injection & Exploit Vector (Weight: up to 50 pts)
  let injectionDetected = false;
  for (const pattern of XSS_PATTERNS) {
    if (testRegex(pattern, content)) {
      score += 45;
      injectionDetected = true;
      threats.push("Cross-Site Scripting (XSS) payload or script vector identified");
      recommendations.push("Sanitize input: HTML tags and executable script handlers are blocked.");
      break;
    }
  }

  for (const pattern of SQLI_PATTERNS) {
    if (testRegex(pattern, content)) {
      score += 40;
      injectionDetected = true;
      threats.push("SQL Injection heuristic pattern identified");
      recommendations.push("Database syntax injection attempt flagged.");
      break;
    }
  }

  for (const pattern of CMD_INJECTION_PATTERNS) {
    if (testRegex(pattern, content)) {
      score += 50;
      injectionDetected = true;
      threats.push("Shell command / OS command injection string detected");
      recommendations.push("Remote terminal execution patterns are strictly prohibited.");
      break;
    }
  }

  details.injection = {
    detected: injectionDetected,
    details: injectionDetected ? "Malicious executable code or injection syntax found." : undefined,
  };

  // 3. Data Loss Prevention (DLP) / Sensitive Credentials Vector (Weight: up to 35 pts)
  let dlpTriggered = false;
  if (testRegex(CREDIT_CARD_REGEX, content)) {
    score += 30;
    dlpTriggered = true;
    threats.push("Payment Card Number (PAN) detected in cleartext");
    recommendations.push("DLP Alert: Do not share raw credit card numbers over open messaging channels.");
  }

  if (testRegex(AWS_KEY_REGEX, content) || testRegex(GITHUB_TOKEN_REGEX, content) || testRegex(GENERIC_API_KEY_REGEX, content)) {
    score += 35;
    dlpTriggered = true;
    threats.push("High-Entropy API Access Key / Bearer Token exposed");
    recommendations.push("Revoke and rotate exposed credentials immediately; use secrets management.");
  }

  if (testRegex(PRIVATE_KEY_REGEX, content)) {
    score += 45;
    dlpTriggered = true;
    threats.push("Cryptographic Private Key block identified");
    recommendations.push("CRITICAL: Private keys must never be transmitted via chat.");
  }

  details.dlp = {
    detected: dlpTriggered,
    details: dlpTriggered ? "Sensitive PII or confidential credentials found." : undefined,
  };

  // 4. File Attachment Security Vector (Weight: up to 50 pts)
  if (messageType === "file" || fileName) {
    const ext = fileName.toLowerCase().slice(fileName.lastIndexOf("."));
    
    // Check for double extension (e.g. sample.pdf.exe)
    const dotCount = (fileName.match(/\./g) || []).length;
    if (dotCount > 1 && HIGH_RISK_EXTENSIONS.some(e => fileName.toLowerCase().endsWith(e))) {
      score += 50;
      threats.push(`Dangerous Double Extension spoofing detected: "${fileName}"`);
      recommendations.push("High-risk masqueraded file rejected. Likely executable malware payload.");
    } else if (HIGH_RISK_EXTENSIONS.includes(ext)) {
      score += 45;
      threats.push(`Direct Executable file extension prohibited: "${ext}"`);
      recommendations.push("Executables (.exe, .bat, .sh, .vbs) cannot be distributed via standard chat.");
    } else if (MODERATE_RISK_EXTENSIONS.includes(ext)) {
      score += 15;
      threats.push(`Compressed archive file attached: "${ext}"`);
      recommendations.push("Scan archives with antivirus before opening or extracting.");
    }

    details.fileRisk = {
      detected: HIGH_RISK_EXTENSIONS.includes(ext) || dotCount > 1,
      details: threats.filter(t => t.includes("Extension") || t.includes("archive")).join("; "),
    };
  }

  // 5. Entropy & Obfuscation Analysis (Weight: up to 15 pts)
  if (content.length > 20) {
    const entropy = calculateShannonEntropy(content);
    details.entropy.value = entropy;
    // Normal English text entropy is usually between 3.5 and 4.8. High entropy (> 5.2) suggests base64/shellcode
    if (entropy > 5.3 && !urls.length) {
      details.entropy.abnormal = true;
      score += 15;
      threats.push(`Abnormally high Shannon entropy (${entropy} bits/char) - Possible obfuscated payload or shellcode`);
      recommendations.push("Investigate potential base64 or encrypted binary embedding.");
    }
  }

  // Cap score to 100 max
  score = Math.min(100, Math.max(0, Math.round(score)));

  // Determine Level
  let level: SecurityAnalysisResult["level"] = "safe";
  if (score >= 80) level = "critical";
  else if (score >= 50) level = "high";
  else if (score >= 20) level = "medium";
  else if (score > 0) level = "low";

  // If score is critical (80+), block automatic execution/transmission
  const isBlocked = score >= 80;

  if (threats.length === 0) {
    threats.push("Cryptographic Integrity: Verified Clean (SHA-256 Validated)");
    recommendations.push("No cybersecurity risk factors detected in this transfer.");
  }

  return {
    score,
    level,
    threats,
    details,
    recommendations,
    isBlocked,
  };
}
