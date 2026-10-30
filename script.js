/**
 * CyberBuddy — Cybersecurity Awareness Assistant
 * 
 * Architecture & Modules:
 * 1. UI Controller & Modal System (Accessible Focus Management)
 * 2. Sensitive Information Detection Layer (Privacy Pre-Filter)
 * 3. Emergency Response Engine (High-Priority Intent Classification)
 * 4. Knowledge Base & Topic Matching Engine (8 Comprehensive Modules)
 * 5. Interactive Follow-up Action System
 * 6. Mini Cyber Quiz Engine (5 Realistic Scenarios)
 * 7. Daily Safety Tips Rotator
 */

// Global App State
const state = {
  isTyping: false,
  messageCount: 0,
  currentTipIndex: 0,
  lastFocusedElement: null,
  quiz: {
    currentIndex: 0,
    score: 0,
    answered: false,
    userAnswers: []
  }
};

/* ==========================================================================
   1. Cyber Safety Tips Data
   ========================================================================== */
const SAFETY_TIPS = [
  "Never share one-time passwords (OTPs) with anyone. Legitimate banks and support teams will never ask for your verification codes.",
  "Use a passphrase of 4+ random words (e.g. 'purple-guitar-orbit-ocean') for a password that is easy for you to remember but practically impossible to crack.",
  "Never click links in unexpected text messages or emails claiming your bank account, package, or electricity will be suspended.",
  "Enable an Authenticator App (like Google Authenticator or Aegis) instead of SMS 2FA whenever possible to prevent SIM-swapping attacks.",
  "Avoid conducting banking or entering passwords on open public Wi-Fi networks unless you are connected through a trustworthy VPN.",
  "Cracked games, software 'activators', and pirated torrents are the #1 delivery method for info-stealing trojans and ransomware.",
  "Before entering credentials on any website, carefully examine the address bar for typos (e.g., 'paypa1.com' or 'amaz0n-security.com').",
  "If an urgent caller claims to be your family member in distress or a police officer demanding immediate payment, pause and call them back on their known number."
];

/* ==========================================================================
   2. Mini Cyber Quiz Data (5 Core Scenarios)
   ========================================================================== */
const QUIZ_QUESTIONS = [
  {
    category: "Phishing Identification",
    question: "You receive an urgent email from 'support@paypa1-update.com' stating: 'Your account is suspended! Click here within 1 hour to verify.' What is the safest course of action?",
    options: [
      { text: "Click the link immediately to prevent suspension", correct: false },
      { text: "Open the official website/app manually in a new tab without clicking the email link", correct: true },
      { text: "Reply to the email asking if it is genuine", correct: false },
      { text: "Forward the email to all your friends to warn them", correct: false }
    ],
    explanation: "Scammers use artificial urgency and typosquatted domains (like 'paypa1' instead of 'paypal'). Never click links in alarmist emails; always navigate directly to the official platform yourself."
  },
  {
    category: "OTP Safety",
    question: "A polite caller claiming to be your bank's fraud manager says: 'We blocked an unauthorized transfer. I just sent a 6-digit reversal code to your phone. Read it to me to cancel the charge.' What should you do?",
    options: [
      { text: "Share the code because they are trying to help reverse fraud", correct: false },
      { text: "Share only the last 3 digits of the code", correct: false },
      { text: "Refuse immediately, hang up, and call the verified bank helpline on your card", correct: true },
      { text: "Ask them to verify their employee ID first, then share it", correct: false }
    ],
    explanation: "OTPs are authorization keys, never 'reversal codes'. Banks never ask for OTPs over the phone. The scammer is actively attempting to drain your account while talking to you."
  },
  {
    category: "Password Security",
    question: "Why is reusing the same strong password across multiple websites considered dangerous by security professionals?",
    options: [
      { text: "If one service suffers a data breach, hackers will use credential stuffing to unlock all your other accounts", correct: true },
      { text: "Reused passwords expire automatically every 30 days", correct: false },
      { text: "Browsers cannot autofill passwords that are reused", correct: false },
      { text: "Reused passwords weaken your home Wi-Fi encryption", correct: false }
    ],
    explanation: "In 'credential stuffing' attacks, automated bots test breached username/password pairs on thousands of popular websites. One compromised gaming forum could unlock your primary email."
  },
  {
    category: "Public Wi-Fi",
    question: "You are sitting in an airport and see an unsecured Wi-Fi named 'Free_Airport_WiFi_Fast'. How should you handle sensitive transactions (like banking or work logins)?",
    options: [
      { text: "It is completely safe as long as the airport is reputable", correct: false },
      { text: "Use your personal cellular mobile data or a trusted VPN connection instead", correct: true },
      { text: "Switch your browser to Incognito/Private mode", correct: false },
      { text: "Only perform banking if you keep the session under 5 minutes", correct: false }
    ],
    explanation: "Incognito mode only prevents local history saving—it does not encrypt network traffic. Anyone can set up a rogue 'Evil Twin' hotspot to intercept unencrypted public Wi-Fi traffic. Use cellular data or a VPN."
  },
  {
    category: "Downloads & Malware",
    question: "You want to download a premium photo editor. A forum offers a 'Free Cracked Full Version .exe' download. What risk are you taking?",
    options: [
      { text: "No risk if your antivirus is temporarily disabled during installation", correct: false },
      { text: "Cracked installers frequently bundle infostealers, cryptominers, or ransomware", correct: true },
      { text: "It will only fail to receive official software updates", correct: false },
      { text: "It is legal and safe if downloaded through a private torrent tracker", correct: false }
    ],
    explanation: "Pirated software is the primary vector for modern infostealers (e.g. RedLine, Lumma) which harvest saved browser passwords, session cookies, and crypto wallets within seconds of execution."
  }
];

/* ==========================================================================
   3. Sensitive Data Protection Layer (Pre-filter)
   ========================================================================== */
const SENSITIVE_PATTERNS = [
  // Explicit OTP declarations with numeric codes (4-8 digits)
  {
    type: "OTP / Verification Code",
    regex: /\b(?:otp|verification\s+code)\s*(?:is|:|=)?\s*([0-9]{4,8})\b/i
  },
  // PIN declarations with numeric codes
  {
    type: "PIN Code",
    regex: /\b(?:my\s+)?(?:pin|security\s+code)\s*(?:is|:|=)?\s*([0-9]{4,8})\b/i
  },
  // Credit / Debit card patterns (13-19 digits, with or without spaces/dashes)
  {
    type: "Payment Card Number",
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b/
  },
  {
    type: "Payment Card Number",
    regex: /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/
  },
  // CVV patterns
  {
    type: "Card CVV",
    regex: /\b(?:cvv|cvc)\s*(?:is|:|=)?\s*([0-9]{3,4})\b/i
  },
  // Passwords declarations
  {
    type: "Password / Secret",
    regex: /\b(?:my\s+password\s+is|password\s*[:=]\s*\S+)/i
  },
  // Recovery codes
  {
    type: "Recovery Code",
    regex: /\b(?:recovery\s+code\s*(?:is|:|=)?\s*[a-zA-Z0-9\-_]{6,30})/i
  },
  // API Keys / Secrets tokens
  {
    type: "API Key / Token",
    regex: /\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|bearer\s+[a-zA-Z0-9_\-\.]{20,})\b/i
  }
];

/**
 * Checks if user input contains sensitive credentials or confidential tokens.
 * NEVER echoes back the secret to prevent reflection exposure!
 */
function checkSensitiveInformation(text) {
  for (const item of SENSITIVE_PATTERNS) {
    if (item.regex.test(text)) {
      return {
        detected: true,
        type: item.type
      };
    }
  }
  return { detected: false };
}

/* ==========================================================================
   4. High-Priority Emergency Classifier & Generators
   ========================================================================== */

/**
 * Robust Regex-based Intent Detection for Emergency Scenarios.
 * Handles diverse natural language variations, tenses, and phrasings.
 */
function classifyEmergencyIntent(rawInput) {
  const norm = rawInput.toLowerCase().trim();

  // 1. File executed / opened
  if (/(?:opened|executed|ran|launch(?:ed)?|install(?:ed)?)\s+(?:a\s+)?(?:suspicious|unknown|bad|infected)?\s*(?:file|attachment|exe|installer|program|software|script)/i.test(norm) ||
      /(?:opened|executed)\s+a\s+suspicious\s+file/i.test(norm)) {
    return "FILE_EXECUTED";
  }

  // 2. File downloaded (not yet executed)
  if (/(?:downloaded|downloading|saved)\s+(?:a\s+)?(?:suspicious|unknown|bad)?\s*(?:file|attachment|installer|zip|rar|archive|exe)/i.test(norm) ||
      /downloaded\s+a\s+suspicious\s+file/i.test(norm)) {
    return "FILE_DOWNLOADED";
  }

  // 3. Payment information entered on unverified/fake site
  if (/(?:entered|typed|submitted|gave|provided)\s+(?:a\s+|my\s+|the\s+)?(?:card|payment|credit card|debit card|bank details|cvv)/i.test(norm) ||
      /(?:entered|submitted)\s+payment\s+information/i.test(norm)) {
    return "PAYMENT_ENTERED";
  }

  // 4. Password entered on unverified/fake website
  if (/(?:entered|typed|submitted|gave|provided)\s+(?:a\s+|my\s+|the\s+)?(?:password|credentials|login)/i.test(norm)) {
    return "PASSWORD_ENTERED";
  }

  // 5. Received a suspicious link (did not click)
  if (/(?:received|got|sent\s+me)\s+(?:a\s+)?(?:suspicious|fake|phishing)?\s*(?:link|url|sms|message|email)/i.test(norm) ||
      /received\s+a\s+suspicious\s+link/i.test(norm)) {
    return "LINK_RECEIVED";
  }

  // 6. Clicked link (entered nothing)
  if (/(?:clicked|opened|tapped|visited)\s+(?:a\s+)?(?:suspicious|phishing|bad|fake)?\s*(?:link|url|website|site)/i.test(norm) ||
      /clicked\s+a\s+suspicious\s+link/i.test(norm)) {
    return "LINK_CLICKED";
  }

  // 7. OTP already shared
  if (/(?:already|i)\s+(?:shared|gave|provided|sent|entered|typed)\s+(?:my\s+|the\s+)?(?:otp|pin|code)/i.test(norm)) {
    return "OTP_ALREADY_SHARED";
  }

  // 8. OTP asked / requested (Suspected Scam)
  if (/(?:ask|asks|asking|asked|demand|demands|demanded|want|wants|request|requests|requested|need|share|send|give|telling me to give)\s+(?:me\s+for\s+|for\s+)?(?:my\s+|the\s+|an\s+)?(?:otp|pin|verification code|upi pin)/i.test(norm) ||
      /(?:someone|caller|person|stranger|agent)\s+(?:is\s+)?(?:asking|asked|demanding)\s+(?:for\s+)?(?:my\s+)?(?:otp|pin)/i.test(norm)) {
    return "OTP_ASKED";
  }

  // 9. Financial fraud: money already transferred / debited
  if (/(?:i\s+)?(?:transferred|sent|paid|lost|scammed out of)\s+(?:money|cash|funds|amount|rupees)/i.test(norm) ||
      /(?:money|funds|amount)\s+(?:got\s+)?(?:debited|stolen|deducted)/i.test(norm) ||
      /(?:unauthorized|fraudulent)\s+(?:transaction|debit|transfer|withdrawal)/i.test(norm)) {
    return "MONEY_TRANSFERRED";
  }

  // 10. Urgent transfer demand (Suspected Scam)
  if (/(?:ask|asks|asking|asked|demanding|pressuring|told)\s+(?:me\s+)?to\s+transfer\s+money/i.test(norm) ||
      /(?:transfer|send|pay)\s+money\s+(?:urgently|immediately|fast|right now)/i.test(norm) ||
      /(?:urgent|immediate)\s+(?:money\s+transfer|transfer|payment)/i.test(norm)) {
    return "URGENT_TRANSFER_DEMAND";
  }

  // 11. Impersonation / Fake support / Suspicious bank call
  if (/(?:suspicious|fake|fraud)\s+(?:bank\s+)?(?:call|caller|phone call)/i.test(norm) ||
      /(?:received|got)\s+(?:a\s+)?(?:suspicious|fake)\s+(?:bank\s+)?call/i.test(norm) ||
      /(?:impersonat(?:e|es|ed|ing)?|pretending to be|posing as|claiming to be)\s+(?:customer\s+support|bank|police|customs|cbi|support|agent)/i.test(norm) ||
      /(?:fake|fraudulent)\s+customer\s+(?:support|care|service)/i.test(norm) ||
      /(?:digital\s+arrest)/i.test(norm)) {
    return "IMPERSONATION_SCAM";
  }

  // 12. General scam suspicion ("I think I am being scammed")
  if (/(?:i\s+think\s+(?:i\s+am|i'm)\s+being\s+scammed)/i.test(norm) ||
      /(?:think\s+(?:this\s+is|it's)\s+a\s+scam)/i.test(norm) ||
      /(?:suspected\s+scam|am\s+i\s+being\s+scammed|is\s+this\s+a\s+scam)/i.test(norm)) {
    return "GENERAL_SCAM_SUSPICION";
  }

  // 13. Compromised account (Hacked, unauthorized access, password shared)
  if (/(?:account|instagram|email|google|facebook|gmail|whatsapp|social media)\s+(?:was\s+|got\s+|is\s+)?(?:hacked|compromised|breached|hijacked)/i.test(norm) ||
      /(?:my\s+)?(?:instagram|email|google|facebook|gmail|whatsapp)\s+(?:account\s+)?(?:was\s+|got\s+|is\s+)?(?:hacked|compromised|breached|hijacked)/i.test(norm) ||
      /(?:someone\s+)?(?:logged\s+into|accessed)\s+my\s+(?:account|email|instagram|google)/i.test(norm) ||
      /(?:i\s+)?(?:cannot|can't|cant)\s+access\s+my\s+account/i.test(norm) ||
      /(?:unknown|unauthorized)\s+login/i.test(norm) ||
      /(?:i\s+)?(?:shared|gave)\s+my\s+password\s+(?:with|to)\s+someone/i.test(norm) ||
      /(?:my\s+)?password\s+(?:was\s+|is\s+)?(?:leaked|stolen|compromised)/i.test(norm)) {
    return "ACCOUNT_COMPROMISED";
  }

  return null;
}

/**
 * Generates structured, high-priority emergency responses based on intent code.
 */
function generateEmergencyResponse(intentCode) {
  switch (intentCode) {
    case "OTP_ASKED":
      return {
        type: "emergency",
        title: "CRITICAL: Never Share Your OTP or PIN!",
        html: `
          <div class="emergency-header-strip">
            <i data-lucide="shield-alert"></i>
            <span>DO NOT SHARE THIS CODE UNDER ANY CIRCUMSTANCES</span>
          </div>
          <p><strong>This is almost certainly a scam.</strong> Legitimate banks, customer care, courier agents, and law enforcement will <strong>NEVER</strong> ask for your One-Time Password (OTP), UPI PIN, or password.</p>
          
          <h4>Immediate Protective Actions:</h4>
          <ol>
            <li><strong>Hang up or stop replying:</strong> Cut off communication immediately. Do not explain or argue.</li>
            <li><strong>Do not approve prompts:</strong> If you received a UPI collect request or SMS verification link, decline or ignore it.</li>
            <li><strong>Verify independently:</strong> If the caller claimed to be from your bank or an agency, call the verified number printed on your debit card or their official website.</li>
            <li><strong>Block and report:</strong> Mark the number or sender as spam.</li>
          </ol>

          <div class="tip-box">
            <strong>Golden Rule:</strong> An OTP is an authorization to <em>debit</em> money or log into your account. There is no such thing as an "OTP to receive money" or a "cancellation OTP".
          </div>
        `,
        followUps: [
          { label: "What if I already shared it?", query: "I already shared my OTP. What should I do?" },
          { label: "How do OTP scams work?", query: "How do scammers use OTPs to steal money?" },
          { label: "Report Financial Fraud (1930)", query: "How do I report financial cyber fraud?" }
        ]
      };

    case "OTP_ALREADY_SHARED":
      return {
        type: "emergency",
        title: "URGENT ACTION REQUIRED: Code Already Disclosed",
        html: `
          <div class="emergency-header-strip">
            <i data-lucide="alert-triangle"></i>
            <span>CODE COMPROMISED — IMMEDIATE DAMAGE CONTROL</span>
          </div>
          <p>If you have already shared an OTP, the attacker may be actively logging into your account or executing a money transfer.</p>
          
          <h4>Take these steps RIGHT NOW:</h4>
          <ol>
            <li><strong>Call Your Bank Immediately:</strong> Call the 24/7 emergency customer care number (printed on your bank card) and request an immediate freeze on net banking, cards, and UPI.</li>
            <li><strong>Change Account Passwords:</strong> If the OTP was for an email or social account, change the password from a trusted device and select <em>"Log out of all other sessions"</em>.</li>
            <li><strong>In India &mdash; Dial 1930:</strong> If money was stolen, call <span class="highlight-code">1930</span> immediately to report financial fraud to the cyber police. Quick reporting helps freeze funds before withdrawal.</li>
            <li><strong>File Official Report:</strong> Submit transaction details at <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a>.</li>
          </ol>
        `,
        followUps: [
          { label: "Check Compromised Account Checklist", query: "My account was hacked. What should I do?" },
          { label: "How to Freeze Bank Account", query: "How do I contact my bank to freeze transactions?" }
        ]
      };

    case "URGENT_TRANSFER_DEMAND":
      return {
        type: "emergency",
        title: "Scam Warning: Urgent Money Transfer Demand",
        html: `
          <div class="emergency-header-strip">
            <i data-lucide="alert-octagon"></i>
            <span>DO NOT TRANSFER MONEY — SUSPECTED SCAM</span>
          </div>
          <p><strong>STOP immediately.</strong> Artificial urgency is the single most common psychological tactic used by cyber fraudsters.</p>
          
          <h4>Critical Guidance:</h4>
          <ol>
            <li><strong>Do NOT send funds:</strong> Scammers use pressure (e.g. <em>"Pay within 15 minutes or your account will be frozen/arrested"</em>) to bypass your rational thinking.</li>
            <li><strong>Hang up the call:</strong> Disconnect any active call or chat immediately.</li>
            <li><strong>Independently verify:</strong> Call the genuine organization or person using their verified contact number (not any number provided by the caller).</li>
            <li><strong>Report the attempt:</strong> Report the sender number or UPI ID to the National Cyber Crime Reporting Portal at <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a>.</li>
          </ol>
        `,
        followUps: [
          { label: "What is social engineering?", query: "What is social engineering?" },
          { label: "I already transferred money", query: "I transferred money to a scammer. What should I do?" }
        ]
      };

    case "MONEY_TRANSFERRED":
      return {
        type: "emergency",
        title: "Financial Fraud Recovery Protocol",
        html: `
          <div class="emergency-header-strip">
            <i data-lucide="phone-call"></i>
            <span>GOLDEN HOUR PROTOCOL FOR FINANCIAL CYBER FRAUD</span>
          </div>
          <p>The first <strong>2 hours ('Golden Hours')</strong> following an unauthorized transfer are vital for banks and law enforcement to track and freeze stolen funds before they are withdrawn at ATMs.</p>
          
          <h4>Essential Steps:</h4>
          <ol>
            <li><strong>Contact Your Bank / Payment App:</strong> Notify them immediately of the unauthorized transfer. Request the transaction reference number (UTR/RRN).</li>
            <li><strong>In India &mdash; Dial 1930:</strong> Call the Ministry of Home Affairs' Citizen Financial Cyber Fraud Helpline at <span class="highlight-code">1930</span>. Provide victim details, bank name, account number, transaction ID, and beneficiary details.</li>
            <li><strong>Lodge Formal Complaint:</strong> Register the incident on the National Cyber Crime Reporting Portal: <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a>.</li>
            <li><strong>Preserve All Evidence:</strong> Take clear screenshots of transaction SMS, UPI IDs, chat history, call logs, and fake websites. <em>Do not delete these chats</em> as they serve as legal evidence.</li>
          </ol>
        `,
        followUps: [
          { label: "National Portal Links", query: "Where do I report cybercrime in India?" },
          { label: "How to identify future scams", query: "How do I spot fake customer care scams?" }
        ]
      };

    case "IMPERSONATION_SCAM":
      return {
        type: "emergency",
        title: "Impersonation Scam Alert",
        html: `
          <div class="emergency-header-strip">
            <i data-lucide="user-x"></i>
            <span>IMPERSONATION TACTIC DETECTED</span>
          </div>
          <p>Scammers routinely impersonate bank fraud departments, courier services, utility boards, CBI, or police officers to induce panic.</p>
          
          <h4>How to Protect Yourself:</h4>
          <ol>
            <li><strong>Never install remote desktop apps:</strong> Scammers often tell you to download apps like <em>AnyDesk, TeamViewer, or RustDesk</em> to "assist you". This gives them complete remote control of your device!</li>
            <li><strong>No 'Digital Arrests':</strong> Real police, courts, and government agencies NEVER conduct video calls to interrogative suspects or demand deposits to "verification accounts".</li>
            <li><strong>Hang up and call back:</strong> Use the verified phone number printed on the back of your bank card or official company website.</li>
            <li><strong>Block and report:</strong> Report fraudulent caller details to <span class="highlight-code">1930</span> or <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a>.</li>
          </ol>
        `,
        followUps: [
          { label: "What is social engineering?", query: "What is social engineering?" },
          { label: "Someone asked for my OTP", query: "Someone asked for my OTP. What should I do?" }
        ]
      };

    case "GENERAL_SCAM_SUSPICION":
      return {
        type: "emergency",
        title: "Suspected Scam Defense Checklist",
        html: `
          <div class="emergency-header-strip">
            <i data-lucide="shield-alert"></i>
            <span>5-STEP SCAM DEFENSE PROTOCOL</span>
          </div>
          <p>If something feels suspicious, your instincts are likely right. Follow this protocol to stay safe:</p>
          <ol>
            <li><strong>Pause & Disengage:</strong> Discontinue contact with the suspicious party. Do not reply to messages or follow urgent phone instructions.</li>
            <li><strong>Protect Credentials:</strong> Never share passwords, OTPs, UPI PINs, or card CVVs.</li>
            <li><strong>Never Send Money:</strong> Do not transfer "processing fees", "customs clearance", or "refundable deposits".</li>
            <li><strong>Verify Out-of-Band:</strong> Call the genuine organization using their verified public helpline.</li>
            <li><strong>In India:</strong> If financial fraud is attempted or completed, call <span class="highlight-code">1930</span> and report to <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a>.</li>
          </ol>
        `,
        followUps: [
          { label: "Someone asked for my OTP", query: "Someone asked for my OTP. What should I do?" },
          { label: "How to report cyber fraud", query: "How do I report financial cyber fraud?" }
        ]
      };

    case "ACCOUNT_COMPROMISED":
      return {
        type: "emergency",
        title: "Compromised Account Recovery Checklist",
        html: `
          <div class="emergency-header-strip">
            <i data-lucide="shield-alert"></i>
            <span>STEP-BY-STEP RECOVERY PROCESS</span>
          </div>
          <p>If you suspect an unauthorized person has accessed your account, follow this ordered checklist:</p>

          <h4>If you STILL have access:</h4>
          <ol>
            <li><strong>Change Password Immediately:</strong> Use a trusted, malware-free device and create a strong, unique 14+ character password.</li>
            <li><strong>Update Reused Passwords:</strong> If you used that same password on your email, banking, or other accounts, change those immediately too.</li>
            <li><strong>Sign Out Other Sessions:</strong> Look for <em>"Active Sessions"</em> or <em>"Where You're Logged In"</em> in security settings and click <strong>"Log Out of All Devices"</strong>.</li>
            <li><strong>Enable 2FA:</strong> Turn on Two-Factor Authentication, preferably using an Authenticator app (e.g. Google Authenticator) rather than SMS.</li>
            <li><strong>Inspect Recovery Info:</strong> Ensure the attacker hasn't added their phone number, recovery email, or linked third-party app.</li>
            <li><strong>Revoke Connected Apps:</strong> Remove unfamiliar third-party permissions in account settings.</li>
          </ol>

          <h4>If you are LOCKED OUT:</h4>
          <ol>
            <li>Use the platform's official account recovery portal directly (e.g. <code>instagram.com/hacked</code> or <code>accounts.google.com/signin/recovery</code>).</li>
            <li>Secure your primary recovery email account first, as reset codes will be sent there.</li>
            <li>Beware of fake "Instagram Recovery Experts" in comments or DMs—they are recovery scammers.</li>
          </ol>
        `,
        followUps: [
          { label: "How do I secure my primary email?", query: "How do I secure my Google or email account?" },
          { label: "How do I set up 2FA properly?", query: "What is two-factor authentication and how to set it up?" },
          { label: "Check if my password was leaked", query: "How do I check if my password was leaked in a breach?" }
        ]
      };

    case "LINK_RECEIVED":
      return {
        type: "assistant",
        title: "Guidance: Received a Suspicious Link",
        html: `
          <p>You received an unexpected or suspicious link via SMS, WhatsApp, or email. Here is how to handle it safely:</p>
          <h4>Recommended Protocol:</h4>
          <ol>
            <li><strong>Do NOT click it:</strong> Unopened links cannot compromise your device.</li>
            <li><strong>Inspect the sender:</strong> Check the phone number or email address. Legitimate organizations rarely send shortlinks (like <code>bit.ly</code> or <code>tinyurl</code>) for critical account actions.</li>
            <li><strong>Navigate manually:</strong> If the message claims your bank, package, or account requires action, open your browser and navigate directly to the official website yourself.</li>
            <li><strong>Block & Report:</strong> Mark the message as spam/phishing on your phone or messaging app.</li>
          </ol>
          <div class="tip-box">
            <strong>Good to know:</strong> Simply receiving a link does not infect your device. The risk occurs when you open it, download files, or enter credentials.
          </div>
        `,
        followUps: [
          { label: "What if I already clicked it?", query: "Clicked a suspicious link but entered nothing" },
          { label: "How do I identify phishing emails?", query: "How do I identify a phishing email?" }
        ]
      };

    case "LINK_CLICKED":
      return {
        type: "warning",
        title: "Suspicious Link Clicked (Nothing Entered)",
        html: `
          <div class="warning-header-strip">
            <i data-lucide="external-link"></i>
            <span>LINK OPENED — CONTAINMENT CHECK</span>
          </div>
          <p>If you clicked a suspicious link but did <strong>NOT</strong> enter passwords, cards, or personal details:</p>
          <ol>
            <li><strong>Close the tab immediately:</strong> Do not interact with popups or click "Allow" on any prompts.</li>
            <li><strong>Check your Downloads:</strong> Open your browser's download manager (Ctrl+J) and make sure no file was silently downloaded. If one was, delete it without opening.</li>
            <li><strong>Clear Browser Cache & Cookies:</strong> In your browser settings, clear recent cookies and site data for that domain.</li>
            <li><strong>Do not approve browser prompts:</strong> Never click "Install", "Update Flash", or "Allow Notifications" on unfamiliar landing pages.</li>
          </ol>
          <div class="tip-box">
            <strong>Good news:</strong> Simply viewing a web page in a modern updated browser rarely installs malware unless you manually approve downloads or enter credentials.
          </div>
        `,
        followUps: [
          { label: "What if I entered a password?", query: "Entered a password on a fake website" },
          { label: "What if I entered card details?", query: "Entered payment information" }
        ]
      };

    case "PASSWORD_ENTERED":
      return {
        type: "emergency",
        title: "Password Entered on Suspicious Page",
        html: `
          <div class="emergency-header-strip">
            <i data-lucide="key-round"></i>
            <span>CREDENTIALS EXPOSED — TAKE ACTION</span>
          </div>
          <p>Because you submitted credentials on an unverified page, the attacker likely has your login information.</p>
          <ol>
            <li><strong>Change Password Immediately:</strong> Open a new browser tab, go directly to the legitimate website, and change your password.</li>
            <li><strong>Change Reused Passwords:</strong> If this password was used elsewhere, update those accounts immediately.</li>
            <li><strong>Terminate Sessions:</strong> Go to security settings and force <em>"Sign out everywhere"</em>.</li>
            <li><strong>Turn on 2FA:</strong> Enable two-factor authentication so stolen passwords alone cannot grant access.</li>
          </ol>
        `,
        followUps: [
          { label: "How to secure the rest of my accounts?", query: "How can I secure my accounts after a breach?" },
          { label: "Password managers guide", query: "Why should I use a password manager?" }
        ]
      };

    case "PAYMENT_ENTERED":
      return {
        type: "emergency",
        title: "Payment Card Details Submitted",
        html: `
          <div class="emergency-header-strip">
            <i data-lucide="credit-card"></i>
            <span>CARD COMPROMISED — FREEZE IMMEDIATELY</span>
          </div>
          <p>You may have submitted financial details to a phishing clone. Act without delay:</p>
          <ol>
            <li><strong>Block / Freeze the Card:</strong> Open your banking app or call your bank's fraud line immediately to block the card.</li>
            <li><strong>Monitor Transactions:</strong> Check statements for micro-transactions or unauthorized debits.</li>
            <li><strong>Request a Replacement Card:</strong> Ask your bank to issue a new card with a fresh CVV and number.</li>
            <li><strong>In India:</strong> If money was debited, call <span class="highlight-code">1930</span> and file a report at <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a>.</li>
          </ol>
        `,
        followUps: [
          { label: "Report Financial Fraud (1930)", query: "I transferred money to a scammer. What should I do?" }
        ]
      };

    case "FILE_DOWNLOADED":
      return {
        type: "warning",
        title: "Suspicious File Downloaded (Not Executed)",
        html: `
          <div class="warning-header-strip">
            <i data-lucide="download"></i>
            <span>SUSPICIOUS DOWNLOAD CONTAINMENT</span>
          </div>
          <p>If you downloaded an unknown file but have <strong>NOT</strong> opened or run it yet:</p>
          <ol>
            <li><strong>DO NOT OPEN OR DOUBLE-CLICK IT:</strong> A file cannot harm your system simply sitting in your Downloads folder.</li>
            <li><strong>Scan Without Opening:</strong> Upload the file to <a href="https://www.virustotal.com" target="_blank" rel="noopener noreferrer">VirusTotal.com</a> to scan it against 70+ antivirus engines.</li>
            <li><strong>Delete the File:</strong> Delete the file and immediately empty your Recycle Bin / Trash.</li>
            <li><strong>Run Antivirus Scan:</strong> Run a quick scan with Microsoft Defender or your installed antivirus software to ensure no background installer was triggered.</li>
          </ol>
        `,
        followUps: [
          { label: "What if I already opened the file?", query: "Opened or executed a suspicious file" },
          { label: "How to download software safely", query: "How can I download software safely?" }
        ]
      };

    case "FILE_EXECUTED":
      return {
        type: "emergency",
        title: "Suspicious File Opened or Executed",
        html: `
          <div class="emergency-header-strip">
            <i data-lucide="bug"></i>
            <span>MALWARE CONTAINMENT STEPS</span>
          </div>
          <p>If you opened or executed an unknown file (.exe, .scr, .bat, .zip):</p>
          <ol>
            <li><strong>Disconnect from Network IMMEDIATELY:</strong> Turn off Wi-Fi and unplug Ethernet. This stops infostealers from transmitting stolen browser passwords and stops ransomware from communicating with Command & Control servers.</li>
            <li><strong>Do NOT test it further:</strong> Never launch it again to see what it does.</li>
            <li><strong>Run Antivirus Scan:</strong> Run a full offline scan using Windows Defender or reputable offline security software.</li>
            <li><strong>Check Active Processes:</strong> Look for unfamiliar background tasks in Task Manager.</li>
            <li><strong>If Ransomware is suspected:</strong> Do not pay the ransom. Keep the computer powered off to prevent further encryption and consult trusted cybersecurity professionals.</li>
          </ol>
        `,
        followUps: [
          { label: "What is ransomware?", query: "What is ransomware and how does it spread?" },
          { label: "How to scan files safely", query: "How do I scan files without opening them?" }
        ]
      };

    default:
      return null;
  }
}

/* ==========================================================================
   5. General Knowledge Base Modules (8 Comprehensive Topics)
   ========================================================================== */
const TOPIC_MODULES = [
  // Module 1: Phishing & Email Scams
  {
    topic: "phishing",
    keywords: [
      "phishing", "fake email", "scam email", "identify phishing", "spot phishing",
      "suspicious email", "fake bank message", "delivery scam", "fake job",
      "lottery scam", "prize scam", "courier scam", "sms phishing", "smishing"
    ],
    generate: (input) => {
      const lower = input.toLowerCase();

      if (lower.includes("job") || lower.includes("internship")) {
        return {
          type: "assistant",
          title: "Identifying Fake Job & Internship Offers",
          html: `
            <p>Fake job offers frequently target students and graduates via WhatsApp, Telegram, or LinkedIn.</p>
            <h4>Common Warning Signs:</h4>
            <ul>
              <li><strong>Offers without interviews:</strong> Receiving an immediate offer letter without any rigorous technical or behavioral interview.</li>
              <li><strong>Free email domains:</strong> Official recruiters write from official company domains (e.g. <code>@company.com</code>), not generic <code>@gmail.com</code>.</li>
              <li><strong>Task-based fee traps:</strong> Requiring you to pay an "application fee", "equipment deposit", or "task rating" balance. <em>Legitimate jobs pay you, they never ask you to pay them.</em></li>
              <li><strong>Communication only on Telegram/WhatsApp:</strong> Professional HR teams maintain corporate email correspondence.</li>
            </ul>
          `,
          followUps: [
            { label: "Common phishing warning signs", query: "What are common phishing warning signs?" },
            { label: "How do I report a fake job?", query: "How do I report a scam job offer?" }
          ]
        };
      }

      if (lower.includes("delivery") || lower.includes("package") || lower.includes("courier")) {
        return {
          type: "assistant",
          title: "Package & Courier Phishing Scams (Smishing)",
          html: `
            <p>Fake package delivery SMS messages claim your package cannot be delivered due to an incorrect address or unpaid ₹25 customs fee.</p>
            <h4>How the Scam Works:</h4>
            <ul>
              <li>They send a short link (e.g., <code>bit.ly</code> or <code>indiapost-track.top</code>) claiming urgency.</li>
              <li>Clicking prompts you to "update your address" and pay a trivial amount.</li>
              <li>The payment page is a credential harvester that steals your card number, CVV, and OTP!</li>
            </ul>
            <div class="tip-box">
              <strong>Protection Tip:</strong> Track shipments only on the official courier website or app using your original tracking number. Never follow links sent via SMS.
            </div>
          `,
          followUps: [
            { label: "How do I identify phishing emails?", query: "How do I identify a phishing email?" },
            { label: "Someone asked for my OTP", query: "Someone asked for my OTP. What should I do?" }
          ]
        };
      }

      return {
        type: "assistant",
        title: "Recognizing & Defending Against Phishing",
        html: `
          <p><strong>Phishing</strong> is a social engineering attack where cybercriminals impersonate trusted brands, banks, or colleagues to trick you into revealing sensitive credentials or downloading malware.</p>
          
          <h4>5 Tell-Tale Phishing Red Flags:</h4>
          <ul>
            <li><strong>Artificial Urgency & Fear:</strong> Phrases like <em>"Account suspended within 24 hours!"</em> or <em>"Tax refund expiring today!"</em> designed to bypass rational thinking.</li>
            <li><strong>Mismatched Sender Address:</strong> The display name might say "PayPal", but the actual sender address is <code>service@secure-pay-auth.biz</code>.</li>
            <li><strong>Generic Greetings:</strong> Using "Dear Customer" or "Dear User" instead of your actual registered name.</li>
            <li><strong>Deceptive Hyperlinks:</strong> Hovering over a link reveals a destination domain completely different from the displayed text.</li>
            <li><strong>Unexpected Attachments:</strong> Invoices, receipts, or ZIP files you never requested.</li>
          </ul>

          <div class="tip-box">
            <strong>Best Practice:</strong> When in doubt, navigate to the organization's official website manually in a new tab. Never click links inside unsolicited emails.
          </div>
        `,
        followUps: [
          { label: "Show fake delivery scam examples", query: "How do package delivery scams work?" },
          { label: "How to report phishing", query: "How do I report phishing emails?" },
          { label: "What if I clicked a phishing link?", query: "Clicked a suspicious link but entered nothing" }
        ]
      };
    }
  },

  // Module 2: Password Security & 2FA
  {
    topic: "passwords",
    keywords: [
      "password", "passwords", "strong password", "2fa", "two-factor", "mfa",
      "authenticator", "passkey", "passkeys", "password manager", "recovery code",
      "credential", "reuse password", "password security"
    ],
    generate: (input) => {
      const lower = input.toLowerCase();

      if (lower.includes("manager") || lower.includes("password managers")) {
        return {
          type: "assistant",
          title: "Why You Should Use a Password Manager",
          html: `
            <p>Humans cannot memorize 100+ unique, 16-character random passwords. A <strong>Password Manager</strong> solves this securely.</p>
            <h4>Key Advantages:</h4>
            <ul>
              <li><strong>Zero Password Reuse:</strong> Automatically generates and stores unique, complex passwords for every single website.</li>
              <li><strong>Built-in Phishing Protection:</strong> A password manager will NOT autofill your credentials on a fake domain like <code>amaz0n.com</code> because the URL does not match.</li>
              <li><strong>Cross-Device Sync:</strong> Access credentials seamlessly on your phone, laptop, and browser with encrypted vaults.</li>
              <li><strong>Reputable Recommendations:</strong> Bitwarden (open source), 1Password, or Apple/Google built-in credential managers.</li>
            </ul>
          `,
          followUps: [
            { label: "What is 2FA?", query: "What is two-factor authentication?" },
            { label: "How to create a strong password", query: "How can I create a strong password?" }
          ]
        };
      }

      if (lower.includes("passkey") || lower.includes("passkeys")) {
        return {
          type: "assistant",
          title: "What are Passkeys?",
          html: `
            <p><strong>Passkeys</strong> are the modern replacement for passwords built on public-key cryptography (FIDO Alliance & W3C standards).</p>
            <h4>Why Passkeys are the Future:</h4>
            <ul>
              <li><strong>Phishing-Proof:</strong> A passkey cannot be entered on a fake website because the cryptographic handshake only works with the genuine domain.</li>
              <li><strong>No Passwords to Remember:</strong> Authenticate using your device's fingerprint, face unlock (FaceID), or screen PIN.</li>
              <li><strong>Supported Platforms:</strong> Supported natively by Google, Apple, Microsoft, Amazon, WhatsApp, and GitHub.</li>
            </ul>
          `,
          followUps: [
            { label: "How does 2FA work?", query: "What is two-factor authentication?" },
            { label: "How to secure my Google account", query: "How can I secure my account?" }
          ]
        };
      }

      return {
        type: "assistant",
        title: "Password Strength & Two-Factor Authentication (2FA)",
        html: `
          <p>Strong authentication is your frontline defense against automated credential stuffing and dictionary attacks.</p>

          <h4>Creating an Uncrackable Password:</h4>
          <ul>
            <li><strong>Use Passphrases:</strong> Combine 4 or more random words (e.g. <code>crimson-galaxy-waffle-orbit</code>). Length beats complexity!</li>
            <li><strong>Never Reuse Passwords:</strong> If one gaming or shopping website is breached, hackers will test that password on your email and banking.</li>
            <li><strong>Use a Password Manager:</strong> Store long, unique passwords without memorizing them.</li>
          </ul>

          <h4>Two-Factor Authentication (2FA) Hierarchy:</h4>
          <ol>
            <li><strong>Hardware Keys / Passkeys (Most Secure):</strong> YubiKeys or cryptographic passkeys—immune to phishing.</li>
            <li><strong>Authenticator Apps (High Security):</strong> Google Authenticator, Aegis, 2FAS, Bitwarden. Time-based codes (TOTP) that cannot be intercepted via cellular networks.</li>
            <li><strong>SMS OTP (Basic):</strong> Better than nothing, but susceptible to SIM-swapping and social engineering.</li>
          </ol>
        `,
        followUps: [
          { label: "Why should I use a password manager?", query: "Tell me about password managers" },
          { label: "What are passkeys?", query: "What are passkeys?" },
          { label: "Check if my password was leaked", query: "How do I check if my password was leaked in a breach?" }
        ]
      };
    }
  },

  // Module 3: Malware & Safe Downloads
  {
    topic: "malware",
    keywords: [
      "malware", "virus", "spyware", "ransomware", "trojan", "cracked",
      "pirated", "torrent", "safe download", "antivirus", "scan file",
      "virustotal", "suspicious download", "extension", "keylogger"
    ],
    generate: (input) => {
      const lower = input.toLowerCase();

      if (lower.includes("ransomware")) {
        return {
          type: "assistant",
          title: "Understanding & Preventing Ransomware",
          html: `
            <p><strong>Ransomware</strong> is malicious software that encrypts your files and demands payment (usually cryptocurrency) in exchange for a decryption key.</p>
            <h4>Critical Defense Rules:</h4>
            <ul>
              <li><strong>Maintain Offline Backups:</strong> Follow the 3-2-1 backup rule (3 copies, 2 different media, 1 stored offline/offsite). Ransomware cannot encrypt disconnected drives.</li>
              <li><strong>Disconnect Immediately if Infected:</strong> Unplug power and network cables to stop encryption from spreading across network shares.</li>
              <li><strong>Do Not Pay the Ransom:</strong> Paying does not guarantee you get your files back, and funds criminal syndicates. Consult <a href="https://www.nomoreransom.org" target="_blank" rel="noopener noreferrer">NoMoreRansom.org</a> for free public decryptors.</li>
            </ul>
          `,
          followUps: [
            { label: "How to safely download software", query: "How can I download software safely?" },
            { label: "What are trojans and infostealers?", query: "What is an infostealer?" }
          ]
        };
      }

      return {
        type: "assistant",
        title: "Malware Defense & Safe Download Guidelines",
        html: `
          <p><strong>Malware</strong> (Malicious Software) includes trojans, viruses, infostealers, spyware, and ransomware designed to compromise your device and data.</p>

          <h4>Common Infection Vectors:</h4>
          <ul>
            <li><strong>Cracked & Pirated Software:</strong> Keygens, torrents, and 'free' cracks are the #1 delivery method for infostealers (which steal saved browser passwords, session cookies, and crypto keys).</li>
            <li><strong>Fake Updates & Malvertising:</strong> Deceptive ads in search results masquerading as official software installers (e.g. VLC, OBS Studio, Blender).</li>
            <li><strong>Malicious Browser Extensions:</strong> Extensions with excessive permissions that inject affiliate ads or log keystrokes.</li>
          </ul>

          <h4>Practical Safety Checklist:</h4>
          <ol>
            <li>Always download software from the developer's official domain or verified app stores.</li>
            <li>Scan suspicious files or URLs with <a href="https://www.virustotal.com" target="_blank" rel="noopener noreferrer">VirusTotal.com</a> before opening.</li>
            <li>Keep your operating system and web browser updated with the latest security patches.</li>
            <li>Enable built-in defenses like Microsoft Defender and SmartScreen.</li>
          </ol>
        `,
        followUps: [
          { label: "What is ransomware?", query: "What is ransomware?" },
          { label: "I downloaded a suspicious file", query: "Downloaded a suspicious file" },
          { label: "How to check suspicious links", query: "How do I check if a URL is safe?" }
        ]
      };
    }
  },

  // Module 4: Public Wi-Fi & VPN
  {
    topic: "wifi",
    keywords: [
      "wifi", "wi-fi", "public wifi", "airport wifi", "hotel wifi", "vpn",
      "hotspot", "evil twin", "man in the middle", "mitm", "https", "captive portal"
    ],
    generate: (input) => {
      const lower = input.toLowerCase();

      if (lower.includes("vpn")) {
        return {
          type: "assistant",
          title: "What a VPN Does (And What It CANNOT Do)",
          html: `
            <p>A <strong>Virtual Private Network (VPN)</strong> creates an encrypted tunnel between your device and the VPN server.</p>
            <h4>What a VPN DOES:</h4>
            <ul>
              <li>Encrypts your internet traffic from local snoopers on public Wi-Fi networks.</li>
              <li>Hides your true IP address and geographic location from websites you visit.</li>
              <li>Prevents local internet service providers (ISPs) from tracking your browsing domains.</li>
            </ul>
            <h4>What a VPN DOES NOT Do:</h4>
            <ul>
              <li><strong>It does NOT make you anonymous:</strong> If you log into your Google or social media accounts, you are identified regardless of your VPN.</li>
              <li><strong>It does NOT protect against phishing:</strong> If you enter your password on a fake website, a VPN will not save you.</li>
              <li><strong>It does NOT prevent malware:</strong> Downloading an infected file over a VPN will still infect your computer.</li>
            </ul>
          `,
          followUps: [
            { label: "Is public Wi-Fi safe?", query: "Is public Wi-Fi safe?" },
            { label: "How do I spot phishing?", query: "How do I identify a phishing email?" }
          ]
        };
      }

      return {
        type: "assistant",
        title: "Public Wi-Fi Risks & Safety Protocols",
        html: `
          <p>Unsecured public Wi-Fi networks in coffee shops, airports, and hotels present distinct cybersecurity vulnerabilities.</p>

          <h4>Key Public Wi-Fi Risks:</h4>
          <ul>
            <li><strong>Evil Twin Hotspots:</strong> Attackers set up a rogue Wi-Fi access point with a name like <em>"Airport_Free_WiFi"</em> to inspect all unencrypted traffic.</li>
            <li><strong>Packet Sniffing:</strong> Other devices on the same unmanaged network may monitor broadcast traffic.</li>
            <li><strong>Network Worms:</strong> If file sharing and network discovery are enabled, infected computers can attempt connections to your device.</li>
          </ul>

          <h4>How to Stay Safe on Public Networks:</h4>
          <ol>
            <li><strong>Prefer Mobile Cellular Data:</strong> For banking, shopping, or entering passwords, switch to 4G/5G mobile data.</li>
            <li><strong>Use a Reputable VPN:</strong> Encrypt all communications so local network eavesdroppers see only unreadable ciphertext.</li>
            <li><strong>Verify the Network Name:</strong> Ask the venue staff for the exact official SSID before connecting.</li>
            <li><strong>Turn Off Auto-Connect:</strong> Disable "Connect automatically to open networks" in your phone's Wi-Fi settings.</li>
            <li><strong>Ensure HTTPS:</strong> Look for the secure connection padlock on every website you browse.</li>
          </ol>
        `,
        followUps: [
          { label: "What does a VPN actually do?", query: "What does a VPN do?" },
          { label: "How to secure my mobile phone", query: "How do I improve my digital privacy?" }
        ]
      };
    }
  },

  // Module 5: Social Engineering & Privacy
  {
    topic: "social-engineering",
    keywords: [
      "social engineering", "manipulation", "pretexting", "urgency",
      "fake customer care", "qr code scam", "quishing", "oversharing",
      "identity theft", "impersonation", "fake call", "police scam", "digital arrest"
    ],
    generate: (input) => {
      const lower = input.toLowerCase();

      if (lower.includes("digital arrest") || lower.includes("police") || lower.includes("customs")) {
        return {
          type: "assistant",
          title: "Beware of 'Digital Arrest' & Law Enforcement Impersonation",
          html: `
            <p><strong>'Digital Arrest' is a complete fabrication used by scammers.</strong> No law enforcement agency or court conducts arrests or trials over Skype or WhatsApp video calls.</p>
            <h4>How this Scam Operates:</h4>
            <ul>
              <li>Scammers pose as CBI, Police, Narcotics Bureau, or Customs officers claiming a parcel containing contraband has your passport or Aadhaar attached.</li>
              <li>They put you under "virtual surveillance" and demand you transfer money to "RBI verification accounts" to clear your name.</li>
            </ul>
            <div class="tip-box">
              <strong>Official Reality:</strong> Real police and judicial bodies summon citizens via physical legal notices, never through WhatsApp video calls. Immediately disconnect and report to <span class="highlight-code">1930</span> or <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a>.
            </div>
          `,
          followUps: [
            { label: "Report Financial Cyber Fraud", query: "How do I report financial cyber fraud?" },
            { label: "What is social engineering?", query: "What is social engineering?" }
          ]
        };
      }

      if (lower.includes("qr") || lower.includes("quishing")) {
        return {
          type: "assistant",
          title: "QR Code Scams ('Quishing')",
          html: `
            <p>Scammers exploit QR codes to bypass email spam filters and deceive users on online marketplaces like OLX.</p>
            <h4>The Classic QR Scam:</h4>
            <ul>
              <li>A buyer on a marketplace says: <em>"Scan this QR code on GPay/PhonePe to receive the money."</em></li>
              <li><strong>The Truth:</strong> You scan a QR code only to <strong>PAY</strong>, NEVER to receive funds!</li>
              <li>Scanning the code and entering your UPI PIN authorizes a withdrawal from your bank account.</li>
            </ul>
            <div class="tip-box">
              <strong>Remember:</strong> Receiving money via UPI NEVER requires entering your UPI PIN or scanning a code.
            </div>
          `,
          followUps: [
            { label: "Someone asked for my OTP", query: "Someone asked for my OTP. What should I do?" },
            { label: "How to spot social engineering", query: "What is social engineering?" }
          ]
        };
      }

      return {
        type: "assistant",
        title: "Understanding Social Engineering",
        html: `
          <p><strong>Social Engineering</strong> is the psychological manipulation of people into performing actions or divulging confidential information. Hackers target human emotions rather than software bugs.</p>

          <h4>Common Psychological Triggers:</h4>
          <ul>
            <li><strong>Urgency & Panic:</strong> <em>"Your electricity will be cut off tonight unless you click here."</em></li>
            <li><strong>Authority Impersonation:</strong> Posing as high-ranking executives, bank managers, tax authorities, or police officers.</li>
            <li><strong>Greed & Opportunity:</strong> Fake lottery prizes, crypto doubling schemes, and effortless work-from-home tasks.</li>
            <li><strong>Helpfulness / Sympathy:</strong> Fraudulent charities or impersonators claiming a friend is stranded without money.</li>
          </ul>

          <h4>How to Protect Yourself:</h4>
          <ol>
            <li><strong>Slow Down:</strong> Any request demanding immediate financial action is designed to trigger emotional panic.</li>
            <li><strong>Verify Out-of-Band:</strong> Call the supposed sender using a known, verified number.</li>
            <li><strong>Keep Personal Data Private:</strong> Do not publicly share boarding passes, vacation dates, or family details on open social media.</li>
          </ol>
        `,
        followUps: [
          { label: "QR code scam warning", query: "How do QR code scams work?" },
          { label: "What is a 'Digital Arrest' scam?", query: "What is a digital arrest scam?" },
          { label: "How to secure my accounts", query: "How can I secure my account?" }
        ]
      };
    }
  },

  // Module 6: Account Security & Hygiene
  {
    topic: "account-security",
    keywords: [
      "account security", "secure account", "protect account", "google security",
      "session", "sessions", "login alert", "haveibeenpwned", "data breach"
    ],
    generate: () => ({
      type: "assistant",
      title: "Comprehensive Account Security Checklist",
      html: `
        <p>Proactive account hygiene prevents credential theft before unauthorized access occurs.</p>

        <h4>Perform a 5-Minute Security Audit:</h4>
        <ol>
          <li><strong>Check Data Breaches:</strong> Visit <a href="https://haveibeenpwned.com" target="_blank" rel="noopener noreferrer">HaveIBeenPwned.com</a> to see if your email or phone number appeared in public breaches.</li>
          <li><strong>Review Active Devices:</strong> Go to your Google, Apple, or Meta account settings &rarr; <em>Security</em> &rarr; <em>Active Sessions</em>. Terminate any session you do not recognize.</li>
          <li><strong>Audit Connected Apps:</strong> Revoke permissions for old third-party apps, games, or quiz services that still have access to your Google/Apple accounts.</li>
          <li><strong>Verify Recovery Details:</strong> Confirm your recovery phone number and backup email are up-to-date and accessible.</li>
          <li><strong>Enable 2FA Everywhere:</strong> Turn on two-factor authentication, prioritizing authenticator apps or passkeys.</li>
        </ol>
      `,
      followUps: [
        { label: "How to set up a password manager", query: "Tell me about password managers" },
        { label: "My account was hacked", query: "My account was hacked. What should I do?" }
      ]
    })
  },

  // Module 7: Safe Browsing
  {
    topic: "safe-browsing",
    keywords: [
      "safe browsing", "browser security", "https", "ssl", "lock icon",
      "fake website", "typosquatting", "malicious ads", "adblocker", "redirect"
    ],
    generate: () => ({
      type: "assistant",
      title: "Safe Web Browsing Essentials",
      html: `
        <p>Browsing safely requires understanding the boundaries of browser security mechanisms.</p>

        <h4>HTTPS Padlock Limitation:</h4>
        <p>The padlock / HTTPS symbol only means your connection to that specific server is encrypted. <strong>It does NOT mean the website is legitimate.</strong> Phishing websites also obtain free SSL certificates.</p>

        <h4>Key Browsing Safeguards:</h4>
        <ul>
          <li><strong>Watch for Typosquatting:</strong> Phishers register look-alike domains like <code>rnicrosoft.com</code> (rn looks like m) or <code>g00gle.com</code>.</li>
          <li><strong>Use an Ad Blocker:</strong> Reputable open-source ad blockers (like uBlock Origin) prevent malicious advertisements ('malvertising') that inject fake software download buttons.</li>
          <li><strong>Beware of Notification Popups:</strong> Never click "Allow" on sites asking for notification permissions just to prove you are "not a robot".</li>
          <li><strong>Keep Browsers Updated:</strong> Enable automatic browser updates to ensure zero-day web engine patches are applied immediately.</li>
        </ul>
      `,
      followUps: [
        { label: "How to identify a phishing email?", query: "How do I identify a phishing email?" },
        { label: "How to safely download files?", query: "How can I download software safely?" }
      ]
    })
  },

  // Module 8: Digital Privacy & Tracking
  {
    topic: "privacy",
    keywords: [
      "privacy", "digital privacy", "app permissions", "location tracking",
      "cookies", "tracking", "social media privacy", "metadata", "fingerprinting"
    ],
    generate: () => ({
      type: "assistant",
      title: "Protecting Your Digital Privacy",
      html: `
        <p>Online privacy is about controlling what personal data companies, advertisers, and data brokers collect about you.</p>

        <h4>Practical Steps to Reclaim Your Privacy:</h4>
        <ul>
          <li><strong>Audit App Permissions:</strong> On iOS and Android, review which apps have access to your Location, Microphone, Camera, and Contacts. Revoke background location access unless necessary.</li>
          <li><strong>Lock Down Social Media:</strong> Set profiles to private, disable search engine indexing, and avoid posting real-time location tags while away from home.</li>
          <li><strong>Use Privacy-First DNS:</strong> Use encrypted DNS (such as Quad9 <code>9.9.9.9</code> or Cloudflare <code>1.1.1.1</code>) to prevent internet service providers from cataloging every domain you visit.</li>
          <li><strong>Turn Off Targeted Ad Tracking:</strong> Reset your Advertising ID in your smartphone settings and opt out of cross-app tracking.</li>
        </ul>
      `,
      followUps: [
        { label: "What does a VPN do?", query: "What does a VPN do?" },
        { label: "Check if my data was leaked", query: "How do I check if my password was leaked in a breach?" }
      ]
    })
  }
];

/* ==========================================================================
   6. Fallback Response Generator
   ========================================================================== */
function generateFallbackResponse(userQuery) {
  const safeQuerySnippet = escapeHtml(userQuery.slice(0, 60));
  return {
    type: "assistant",
    title: "I'm not completely sure about that one yet",
    html: `
      <p>I am a focused, rule-based cybersecurity awareness assistant. I don't have a verified response for <em>"${safeQuerySnippet}"</em>.</p>
      
      <p>I can provide practical, beginner-friendly advice on these core security areas:</p>
      <ul>
        <li><strong>Phishing & Scams:</strong> Spotting fake emails, SMS, and fake job offers.</li>
        <li><strong>Passwords & 2FA:</strong> Creating strong passphrases, managers, and authenticators.</li>
        <li><strong>Malware & Downloads:</strong> Preventing ransomware, infostealers, and unsafe torrents.</li>
        <li><strong>Public Wi-Fi & VPN:</strong> Unsecured hotspot safety and encryption limits.</li>
        <li><strong>Social Engineering:</strong> OTP phone scams, fake support, and QR code traps.</li>
        <li><strong>Compromised Accounts:</strong> Emergency steps if your account was breached.</li>
      </ul>

      <div class="tip-box">
        <strong>Tip:</strong> Click any of the suggestions below or ask directly about a cybersecurity topic!
      </div>
    `,
    followUps: [
      { label: "How do I identify a phishing email?", query: "How do I identify a phishing email?" },
      { label: "Someone asked for my OTP", query: "Someone asked for my OTP. What should I do?" },
      { label: "How do I secure my account?", query: "How can I secure my account?" },
      { label: "Is public Wi-Fi safe?", query: "Is public Wi-Fi safe?" }
    ]
  };
}

/* ==========================================================================
   7. Core Reasoning & Intent Matching Pipeline
   ========================================================================== */
function processUserMessage(rawInput) {
  const trimmed = rawInput.trim();
  if (!trimmed) return null;

  // STEP 1: Sensitive Information Protection Filter (Strict Pre-Check)
  const sensitiveCheck = checkSensitiveInformation(trimmed);
  if (sensitiveCheck.detected) {
    return {
      type: "warning",
      title: "Privacy Safeguard Warning",
      html: `
        <div class="warning-header-strip">
          <i data-lucide="shield-alert"></i>
          <span>DO NOT SHARE SENSITIVE CREDENTIALS</span>
        </div>
        <p>⚠️ <strong>Please don't share passwords, OTPs, PINs, card details, or recovery codes here.</strong> CyberBuddy is an educational chatbot and will <em>never</em> ask for your private secrets.</p>
        
        <p>For your security:</p>
        <ul>
          <li>All message processing is performed purely in your local browser.</li>
          <li>No messages or credentials are stored or transmitted anywhere.</li>
          <li><strong>If you just pasted a real password, OTP, or secret token:</strong> Change or revoke it through the official service immediately to ensure nobody else has intercepted it.</li>
        </ul>
      `,
      followUps: [
        { label: "How do I create a strong password?", query: "How can I create a strong password?" },
        { label: "How to set up two-factor authentication?", query: "What is two-factor authentication?" }
      ]
    };
  }

  // STEP 2: Emergency Response Flows (Highest Priority Rule Evaluation)
  const emergencyIntent = classifyEmergencyIntent(trimmed);
  if (emergencyIntent) {
    const emergencyResp = generateEmergencyResponse(emergencyIntent);
    if (emergencyResp) return emergencyResp;
  }

  // STEP 3: Topic Modules Matching
  const normalized = trimmed.toLowerCase();
  for (const mod of TOPIC_MODULES) {
    for (const kw of mod.keywords) {
      if (normalized.includes(kw)) {
        return mod.generate(trimmed);
      }
    }
  }

  // STEP 4: Quiz Trigger
  if (normalized.includes("quiz") || normalized.includes("challenge") || normalized.includes("test my defense")) {
    openModal("quizModal");
    return {
      type: "assistant",
      title: "Launching Cyber Defense Quiz",
      html: `<p>I have launched the <strong>Cyber Defense Awareness Challenge</strong> modal for you! Test your reflexes across 5 real-world scenarios.</p>`,
      followUps: [
        { label: "How do I identify a phishing email?", query: "How do I identify a phishing email?" },
        { label: "How can I secure my account?", query: "How can I secure my account?" }
      ]
    };
  }

  // STEP 5: Fallback Response for Unknown Questions
  return generateFallbackResponse(trimmed);
}

/* ==========================================================================
   8. UI Rendering & DOM Management (Safe DOM APIs)
   ========================================================================== */

function getElements() {
  return {
    appLayout: document.getElementById("appLayout"),
    sidebar: document.getElementById("sidebar"),
    sidebarBackdrop: document.getElementById("sidebarBackdrop"),
    mobileMenuBtn: document.getElementById("mobileMenuBtn"),
    closeSidebarBtn: document.getElementById("closeSidebarBtn"),

    chatMessagesContainer: document.getElementById("chatMessagesContainer"),
    welcomeHero: document.getElementById("welcomeHero"),
    messagesList: document.getElementById("messagesList"),
    typingIndicator: document.getElementById("typingIndicator"),
    
    chatForm: document.getElementById("chatForm"),
    chatInput: document.getElementById("chatInput"),
    sendBtn: document.getElementById("sendBtn"),
    clearChatBtn: document.getElementById("clearChatBtn"),
    quickChipsBar: document.getElementById("quickChipsBar"),

    // Modals
    emergencyModal: document.getElementById("emergencyModal"),
    quizModal: document.getElementById("quizModal"),
    resourcesModal: document.getElementById("resourcesModal"),

    // Sidebar & Header Buttons
    sidebarEmergencyBtn: document.getElementById("sidebarEmergencyBtn"),
    headerEmergencyBtn: document.getElementById("headerEmergencyBtn"),
    openQuizBtn: document.getElementById("openQuizBtn"),
    headerQuizBtn: document.getElementById("headerQuizBtn"),
    sidebarResourcesBtn: document.getElementById("sidebarResourcesBtn"),
    headerResourcesBtn: document.getElementById("headerResourcesBtn"),
    nextTipBtn: document.getElementById("nextTipBtn"),
    dailyTipText: document.getElementById("dailyTipText")
  };
}

/**
 * Safely renders user or assistant message to the chat container.
 * Uses textContent for user messages to eliminate any XSS vulnerability.
 */
function appendMessage({ sender, content, type = "normal", followUps = [] }) {
  const el = getElements();
  if (el.welcomeHero && el.welcomeHero.style.display !== "none") {
    el.welcomeHero.style.display = "none";
  }

  state.messageCount++;
  const row = document.createElement("div");
  row.className = `message-row ${sender} ${type}`;

  const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  if (sender === "user") {
    const contentWrapper = document.createElement("div");
    contentWrapper.className = "message-content-wrapper";

    const meta = document.createElement("div");
    meta.className = "message-meta";
    meta.innerHTML = `<span>You</span> &bull; <span>${timestamp}</span>`;

    const bubble = document.createElement("div");
    bubble.className = "message-bubble";
    bubble.textContent = content; // 100% Safe DOM assignment

    contentWrapper.appendChild(meta);
    contentWrapper.appendChild(bubble);

    const avatar = document.createElement("div");
    avatar.className = "message-avatar user-avatar";
    avatar.title = "You";
    avatar.innerHTML = `<i data-lucide="user"></i>`;

    row.appendChild(contentWrapper);
    row.appendChild(avatar);
  } else {
    // Assistant / Emergency / Warning
    const avatar = document.createElement("div");
    avatar.className = "message-avatar";
    avatar.title = "CyberBuddy";
    avatar.innerHTML = `<img src="assets/favicon.svg" alt="CyberBuddy">`;

    const contentWrapper = document.createElement("div");
    contentWrapper.className = "message-content-wrapper";

    const meta = document.createElement("div");
    meta.className = "message-meta";
    meta.innerHTML = `<span>CyberBuddy</span> &bull; <span>${timestamp}</span>`;

    const bubble = document.createElement("div");
    bubble.className = "message-bubble";
    bubble.innerHTML = content; // Curated, trusted HTML from template generators

    contentWrapper.appendChild(meta);
    contentWrapper.appendChild(bubble);

    if (followUps && followUps.length > 0) {
      const followUpGroup = document.createElement("div");
      followUpGroup.className = "follow-up-group";

      followUps.forEach(f => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "follow-up-chip";
        btn.dataset.query = f.query;
        btn.innerHTML = `<i data-lucide="sparkles"></i> <span>${escapeHtml(f.label)}</span>`;
        followUpGroup.appendChild(btn);
      });

      contentWrapper.appendChild(followUpGroup);
    }

    row.appendChild(avatar);
    row.appendChild(contentWrapper);
  }

  el.messagesList.appendChild(row);
  scrollToBottom();
  renderIcons();
}

/**
 * Handles sending a message, showing typing indicator, and generating response.
 */
function handleSendMessage(userText) {
  const trimmed = userText.trim();
  if (!trimmed || state.isTyping) return;

  const el = getElements();

  // 1. Append user message safely
  appendMessage({
    sender: "user",
    content: trimmed
  });

  // Clear input
  el.chatInput.value = "";
  el.chatInput.style.height = "auto";
  el.sendBtn.disabled = true;

  // 2. Show typing indicator
  state.isTyping = true;
  el.typingIndicator.style.display = "flex";
  scrollToBottom();

  // 3. Simulate natural response latency (350ms - 450ms)
  setTimeout(() => {
    const result = processUserMessage(trimmed);

    el.typingIndicator.style.display = "none";
    state.isTyping = false;

    if (result) {
      appendMessage({
        sender: "assistant",
        content: result.html,
        type: result.type,
        followUps: result.followUps
      });
    }
  }, 400);
}

/**
 * Resets conversation to initial welcome state.
 */
function clearChat() {
  const el = getElements();
  el.messagesList.innerHTML = "";
  if (el.welcomeHero) {
    el.welcomeHero.style.display = "flex";
  }
  state.messageCount = 0;
  showToast("Chat history cleared. In-memory session reset.");
  scrollToBottom();
}

/**
 * Auto-scroll to latest message in chat container.
 */
function scrollToBottom() {
  const el = getElements();
  if (el.chatMessagesContainer) {
    el.chatMessagesContainer.scrollTop = el.chatMessagesContainer.scrollHeight;
  }
}

/**
 * Safe Icon Renderer with CDN / window.lucide detection
 */
function renderIcons() {
  if (window.lucide && typeof window.lucide.createIcons === "function") {
    window.lucide.createIcons();
  }
}

/* ==========================================================================
   9. Modal Controller (With Focus Trap & Restoration)
   ========================================================================== */
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    state.lastFocusedElement = document.activeElement;
    modal.classList.add("open");
    modal.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";

    // Focus close button or first interactive element
    const closeBtn = modal.querySelector(".close-modal-btn");
    if (closeBtn) closeBtn.focus();

    if (modalId === "quizModal") {
      renderQuizStep();
    }
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";

    // Restore focus
    if (state.lastFocusedElement && typeof state.lastFocusedElement.focus === "function") {
      state.lastFocusedElement.focus();
    }
  }
}

/* ==========================================================================
   10. Mini Cyber Quiz Controller
   ========================================================================== */
function renderQuizStep() {
  const qIndex = state.quiz.currentIndex;
  const total = QUIZ_QUESTIONS.length;

  const stepText = document.getElementById("quizStepText");
  const scoreText = document.getElementById("quizScoreText");
  const progressBar = document.getElementById("quizProgressBar");
  const content = document.getElementById("quizContent");
  const results = document.getElementById("quizResults");
  const nextBtn = document.getElementById("quizNextBtn");
  const explanationBox = document.getElementById("quizExplanation");

  if (qIndex >= total) {
    // Quiz finished
    content.style.display = "none";
    nextBtn.style.display = "none";
    explanationBox.style.display = "none";
    results.style.display = "flex";

    const scoreLine = document.getElementById("resultsScoreLine");
    const summary = document.getElementById("resultsSummary");
    scoreLine.textContent = `You scored ${state.quiz.score} out of ${total}`;

    if (state.quiz.score === total) {
      summary.textContent = "🏆 Outstanding! You possess top-tier cybersecurity awareness and vigilance.";
    } else if (state.quiz.score >= 3) {
      summary.textContent = "🛡️ Great job! You have solid security instincts. Review the explanations to stay fully fortified.";
    } else {
      summary.textContent = "⚠️ Good effort! Take a moment to explore CyberBuddy's topic modules to strengthen your defenses.";
    }
    return;
  }

  // Active Question
  content.style.display = "block";
  results.style.display = "none";
  nextBtn.style.display = "none";
  explanationBox.style.display = "none";
  state.quiz.answered = false;

  const currentQ = QUIZ_QUESTIONS[qIndex];
  stepText.textContent = `Question ${qIndex + 1} of ${total}`;
  scoreText.textContent = `Score: ${state.quiz.score}`;
  progressBar.style.width = `${((qIndex + 1) / total) * 100}%`;

  document.getElementById("quizCategory").textContent = currentQ.category;
  document.getElementById("quizQuestion").textContent = currentQ.question;

  const optionsList = document.getElementById("quizOptionsList");
  optionsList.innerHTML = "";

  currentQ.options.forEach((opt, idx) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "quiz-opt-btn";
    btn.dataset.index = idx;
    btn.innerHTML = `<span>${escapeHtml(opt.text)}</span>`;

    btn.addEventListener("click", () => handleQuizAnswer(idx, opt.correct, currentQ));
    optionsList.appendChild(btn);
  });
}

function handleQuizAnswer(selectedIdx, isCorrect, questionObj) {
  if (state.quiz.answered) return;
  state.quiz.answered = true;

  const optionsList = document.getElementById("quizOptionsList");
  const buttons = optionsList.querySelectorAll(".quiz-opt-btn");

  if (isCorrect) {
    state.quiz.score++;
    buttons[selectedIdx].classList.add("correct");
  } else {
    buttons[selectedIdx].classList.add("wrong");
    // Highlight correct answer
    questionObj.options.forEach((opt, idx) => {
      if (opt.correct) {
        buttons[idx].classList.add("correct");
      }
    });
  }

  // Prevent multiple selections
  buttons.forEach(b => b.disabled = true);

  // Update Score Counter
  document.getElementById("quizScoreText").textContent = `Score: ${state.quiz.score}`;

  // Show explanation
  const expBox = document.getElementById("quizExplanation");
  const expTitle = document.getElementById("explanationTitle");
  const expText = document.getElementById("explanationText");

  expTitle.textContent = isCorrect ? "Correct! Well done." : "Not quite.";
  expTitle.style.color = isCorrect ? "var(--accent-primary)" : "var(--color-danger)";
  expText.textContent = questionObj.explanation;
  expBox.style.display = "flex";

  const nextBtn = document.getElementById("quizNextBtn");
  nextBtn.style.display = "inline-flex";

  renderIcons();
}

function resetQuiz() {
  state.quiz.currentIndex = 0;
  state.quiz.score = 0;
  state.quiz.answered = false;
  state.quiz.userAnswers = [];
  renderQuizStep();
}

/* ==========================================================================
   11. Daily Safety Tips Controller
   ========================================================================== */
function cycleDailyTip() {
  state.currentTipIndex = (state.currentTipIndex + 1) % SAFETY_TIPS.length;
  const tipEl = document.getElementById("dailyTipText");
  if (tipEl) {
    tipEl.style.opacity = "0";
    setTimeout(() => {
      tipEl.textContent = SAFETY_TIPS[state.currentTipIndex];
      tipEl.style.opacity = "1";
    }, 150);
  }
}

/* ==========================================================================
   12. Toast Notification Helper
   ========================================================================== */
function showToast(message) {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `<i data-lucide="check-circle" style="color: var(--accent-primary); width: 16px; height: 16px;"></i> <span>${escapeHtml(message)}</span>`;

  container.appendChild(toast);
  renderIcons();

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px)";
    setTimeout(() => toast.remove(), 250);
  }, 2800);
}

/* ==========================================================================
   13. Utility Functions
   ========================================================================== */
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/* ==========================================================================
   14. Application Initialization & Event Listeners
   ========================================================================== */
document.addEventListener("DOMContentLoaded", () => {
  const el = getElements();
  renderIcons();

  // --- Input Validation & Auto-resize ---
  el.chatInput.addEventListener("input", () => {
    el.sendBtn.disabled = el.chatInput.value.trim().length === 0;
    el.chatInput.style.height = "auto";
    el.chatInput.style.height = Math.min(el.chatInput.scrollHeight, 120) + "px";
  });

  // Enter to send, Shift+Enter for new line
  el.chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (!el.sendBtn.disabled) {
        handleSendMessage(el.chatInput.value);
      }
    }
  });

  // Chat Form Submission
  el.chatForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (!el.sendBtn.disabled) {
      handleSendMessage(el.chatInput.value);
    }
  });

  // Clear Chat Button
  el.clearChatBtn.addEventListener("click", () => {
    clearChat();
  });

  // Suggested Prompts Chips (Delegated listener)
  document.addEventListener("click", (e) => {
    const chip = e.target.closest(".prompt-chip, .quick-chip, .follow-up-chip");
    if (chip && chip.dataset.query) {
      handleSendMessage(chip.dataset.query);
    }

    // Modal Send-to-Chat Buttons
    const sendToChatBtn = e.target.closest(".send-to-chat-btn");
    if (sendToChatBtn && sendToChatBtn.dataset.prompt) {
      const modal = sendToChatBtn.closest(".modal-backdrop");
      if (modal) {
        closeModal(modal.id);
      }
      handleSendMessage(sendToChatBtn.dataset.prompt);
    }
  });

  // Sidebar Topic Navigation Buttons
  document.querySelectorAll(".topic-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const topic = btn.dataset.topic;
      const topicTitles = {
        "phishing": "How do I identify a phishing email?",
        "passwords": "How can I create a strong password?",
        "malware": "What is malware and how can I stay safe?",
        "wifi": "Is public Wi-Fi safe?",
        "social-engineering": "What is social engineering?",
        "account-security": "How can I secure my accounts?",
        "safe-browsing": "How do I know if a website is safe?",
        "privacy": "How can I improve my digital privacy?"
      };
      const query = topicTitles[topic] || "Tell me about cybersecurity";

      // Close mobile sidebar if open
      el.sidebar.classList.remove("open");
      el.sidebarBackdrop.classList.remove("active");

      handleSendMessage(query);
    });
  });

  // Mobile Sidebar Drawer Toggle
  if (el.mobileMenuBtn) {
    el.mobileMenuBtn.addEventListener("click", () => {
      el.sidebar.classList.add("open");
      el.sidebarBackdrop.classList.add("active");
    });
  }

  if (el.closeSidebarBtn) {
    el.closeSidebarBtn.addEventListener("click", () => {
      el.sidebar.classList.remove("open");
      el.sidebarBackdrop.classList.remove("active");
    });
  }

  if (el.sidebarBackdrop) {
    el.sidebarBackdrop.addEventListener("click", () => {
      el.sidebar.classList.remove("open");
      el.sidebarBackdrop.classList.remove("active");
    });
  }

  // Modals Open Triggers
  el.sidebarEmergencyBtn.addEventListener("click", () => openModal("emergencyModal"));
  el.headerEmergencyBtn.addEventListener("click", () => openModal("emergencyModal"));

  el.openQuizBtn.addEventListener("click", () => openModal("quizModal"));
  el.headerQuizBtn.addEventListener("click", () => openModal("quizModal"));

  el.sidebarResourcesBtn.addEventListener("click", () => openModal("resourcesModal"));
  el.headerResourcesBtn.addEventListener("click", () => openModal("resourcesModal"));

  // Modals Close Triggers
  document.querySelectorAll(".close-modal-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const modalId = btn.dataset.close;
      closeModal(modalId);
    });
  });

  // Close modal when clicking backdrop
  document.querySelectorAll(".modal-backdrop").forEach(backdrop => {
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) {
        closeModal(backdrop.id);
      }
    });
  });

  // Close modals on ESC key
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      document.querySelectorAll(".modal-backdrop.open").forEach(modal => {
        closeModal(modal.id);
      });
      el.sidebar.classList.remove("open");
      el.sidebarBackdrop.classList.remove("active");
    }
  });

  // Emergency Modal Tabs
  const emergencyTabs = document.querySelectorAll(".emergency-tabs .tab-btn");
  emergencyTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      emergencyTabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");

      const targetTabId = tab.dataset.tab;
      document.querySelectorAll(".tab-panel").forEach(panel => {
        panel.classList.toggle("active", panel.id === targetTabId);
      });
    });
  });

  // Quiz Next & Restart Buttons
  const quizNextBtn = document.getElementById("quizNextBtn");
  if (quizNextBtn) {
    quizNextBtn.addEventListener("click", () => {
      state.quiz.currentIndex++;
      renderQuizStep();
    });
  }

  const restartQuizBtn = document.getElementById("restartQuizBtn");
  if (restartQuizBtn) {
    restartQuizBtn.addEventListener("click", () => resetQuiz());
  }

  const quizDiscussBtn = document.getElementById("quizDiscussBtn");
  if (quizDiscussBtn) {
    quizDiscussBtn.addEventListener("click", () => {
      closeModal("quizModal");
      handleSendMessage("How can I improve my cybersecurity awareness after the quiz?");
    });
  }

  // Daily Safety Tip Refresh
  if (el.nextTipBtn) {
    el.nextTipBtn.addEventListener("click", () => cycleDailyTip());
  }
});
