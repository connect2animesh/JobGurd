/* ===========================
   JOBGUARD — DETECTION ENGINE
   =========================== */

// ─── RED FLAG DATABASE ─────────────────────────────────────────────────────

const RED_FLAGS = {
  paymentScam: {
    label: 'Payment / Fee Request',
    weight: 30,
    patterns: [
      /registration fee/i, /joining fee/i, /training fee/i, /processing fee/i,
      /security deposit/i, /refundable deposit/i, /pay.*before.*joining/i,
      /send money/i, /western union/i, /wire transfer/i, /gift card/i,
      /advance payment/i, /upfront.*fee/i, /fee.*upfront/i,
      /invest.*get.*job/i, /buy.*kit/i, /purchase.*kit/i
    ],
    messages: {
      paymentScam: '💳 Requests money, fees, or deposits — legitimate jobs never ask you to pay.'
    }
  },
  unrealisticOffer: {
    label: 'Unrealistic Offer',
    weight: 20,
    patterns: [
      /earn.*per.*day/i, /₹\s*\d{4,}.*per day/i, /\$\s*\d{3,}.*per day/i,
      /unlimited earning/i, /unlimited income/i, /no experience needed/i,
      /no qualification/i, /anyone can/i, /guaranteed income/i, /guaranteed salary/i,
      /make.*money.*fast/i, /get rich/i, /passive income/i,
      /work.*2.*hours.*earn/i, /work from home.*earn.*\d{5}/i
    ],
    messages: {
      unrealisticOffer: '💰 Promises unrealistic pay or "guaranteed income" with no effort — classic scam bait.'
    }
  },
  vagueListing: {
    label: 'Vague / Missing Details',
    weight: 15,
    patterns: [
      /various tasks/i, /miscellaneous work/i, /data entry.*work from home/i,
      /simple online work/i, /easy online work/i, /home based.*part time/i,
      /just click/i, /just type/i, /form filling/i,
      /ad posting/i, /copy paste/i, /survey filling/i
    ],
    messages: {
      vagueListing: '📋 Extremely vague job description — real jobs describe specific responsibilities.'
    }
  },
  urgencyTactics: {
    label: 'Urgency / Pressure Tactics',
    weight: 15,
    patterns: [
      /limited seats/i, /only \d+ seats/i, /last \d+ seats/i, /hurry/i,
      /act now/i, /urgent hiring/i, /immediate joining/i, /join today/i,
      /limited time offer/i, /offer expires/i, /first come first/i,
      /don'?t miss/i, /last chance/i, /apply before/i, /closing soon/i
    ],
    messages: {
      urgencyTactics: '⏰ Uses urgency/pressure language to rush your decision — this is a manipulation tactic.'
    }
  },
  personalInfoRequest: {
    label: 'Suspicious Info Request',
    weight: 20,
    patterns: [
      /send.*aadhar/i, /aadhar.*number/i, /pan.*card.*apply/i,
      /bank.*account.*apply/i, /bank.*details.*application/i,
      /passport.*copy.*apply/i, /send.*photo.*apply/i, /whatsapp.*photo/i,
      /send.*resume.*whatsapp/i, /apply.*whatsapp/i
    ],
    messages: {
      personalInfoRequest: '🪪 Asks for Aadhar/PAN/bank details during application — never share these upfront.'
    }
  },
  mlmNetwork: {
    label: 'MLM / Network Scheme',
    weight: 25,
    patterns: [
      /refer.*earn/i, /referral.*bonus/i, /multi.?level/i, /network marketing/i,
      /downline/i, /upline/i, /pyramid/i, /chain business/i,
      /recruit.*friends/i, /bring.*members/i, /grow.*team.*earn/i
    ],
    messages: {
      mlmNetwork: '🔗 Mentions referral chains or "grow your team to earn" — likely MLM or pyramid scheme.'
    }
  }
};

// ─── POSITIVE SIGNALS ──────────────────────────────────────────────────────

const POSITIVE_SIGNALS = [
  { pattern: /cin\s*[::#]\s*[A-Z0-9]+/i, text: '✓ Company CIN / registration number mentioned', points: 10 },
  { pattern: /www\.[a-z]+\.(com|in|org|co\.in)/i, text: '✓ Official company website referenced', points: 8 },
  { pattern: /interview process/i, text: '✓ Mentions structured interview process', points: 7 },
  { pattern: /offer letter/i, text: '✓ Mentions formal offer letter', points: 7 },
  { pattern: /probation period/i, text: '✓ Mentions probation period (formal employment sign)', points: 5 },
  { pattern: /pf|esic|provident fund/i, text: '✓ Mentions PF / ESIC benefits (regulated employer)', points: 10 },
  { pattern: /glassdoor|linkedin\.com\/company/i, text: '✓ Links to Glassdoor or LinkedIn company page', points: 10 },
  { pattern: /naukri\.com|internshala\.com|linkedin\.com\/jobs/i, text: '✓ Posted on reputed job portal', points: 8 },
  { pattern: /\d+ employees|\d+\s*member team/i, text: '✓ Company size mentioned', points: 5 },
  { pattern: /background (check|verification)/i, text: '✓ Mentions background verification (formal process)', points: 6 }
];

// ─── SUSPICIOUS EMAIL DOMAINS ──────────────────────────────────────────────

const PERSONAL_EMAIL_DOMAINS = [
  'gmail.com', 'yahoo.com', 'yahoo.in', 'hotmail.com', 'outlook.com',
  'rediffmail.com', 'ymail.com', 'aol.com', 'mail.com', 'protonmail.com'
];

// ─── SALARY ANALYSIS ───────────────────────────────────────────────────────

function analyzeSalary(salaryText) {
  const flags = [];
  const signals = [];

  if (!salaryText.trim()) return { flags, signals, score: 0 };

  // Extract numbers
  const nums = salaryText.match(/[\d,]+/g);
  if (!nums) return { flags, signals, score: 0 };

  const values = nums.map(n => parseInt(n.replace(/,/g, '')));
  const maxVal = Math.max(...values);

  const perDay = /per day|\/day|a day/i.test(salaryText);
  const perMonth = /per month|\/month|a month|monthly|pm\b/i.test(salaryText);

  if (perDay && maxVal > 3000) {
    flags.push({ text: `💰 Salary of ₹${maxVal.toLocaleString()}/day is unrealistically high for most roles.`, severity: 'high', score: 25 });
  } else if (perMonth && maxVal > 300000) {
    flags.push({ text: `💰 Claimed salary of ₹${maxVal.toLocaleString()}/month is suspiciously high for unspecified roles.`, severity: 'medium', score: 15 });
  } else if (perMonth && maxVal < 500 && maxVal > 0) {
    flags.push({ text: `💸 Salary of ₹${maxVal.toLocaleString()}/month is below minimum wage — exploitation risk.`, severity: 'medium', score: 10 });
  } else if (perMonth) {
    signals.push(`✓ Salary range of ₹${maxVal.toLocaleString()}/month appears reasonable.`);
  }

  const totalScore = flags.reduce((sum, f) => sum + f.score, 0);
  return { flags, signals, score: totalScore };
}

// ─── EMAIL ANALYSIS ────────────────────────────────────────────────────────

function analyzeEmail(email) {
  const flags = [];
  const signals = [];

  if (!email.trim()) return { flags, signals, score: 0 };

  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) {
    flags.push({ text: '📧 Invalid email format provided.', severity: 'low', score: 5 });
    return { flags, signals, score: 5 };
  }

  if (PERSONAL_EMAIL_DOMAINS.includes(domain)) {
    flags.push({
      text: `📧 HR email uses personal domain "@${domain}" — legitimate companies use official domains (e.g. @company.com).`,
      severity: 'high',
      score: 22
    });
  } else {
    signals.push(`✓ Company email uses official domain "@${domain}".`);
  }

  const totalScore = flags.reduce((sum, f) => sum + f.score, 0);
  return { flags, signals, score: totalScore };
}

// ─── URL ANALYSIS ──────────────────────────────────────────────────────────

function analyzeUrl(url) {
  const flags = [];
  const signals = [];

  if (!url.trim()) return { flags, signals, score: 0 };

  const suspiciousUrlPatterns = [
    /bit\.ly|tinyurl|t\.co|ow\.ly|rb\.gy|cutt\.ly/i,
    /\.xyz$|\.tk$|\.ml$|\.ga$|\.cf$/i,
    /\d{4,}\.(com|in|net)/i,
    /free.*job|job.*free|earn.*now|click.*earn/i
  ];

  let score = 0;

  suspiciousUrlPatterns.forEach(p => {
    if (p.test(url)) {
      flags.push({ text: '🔗 Suspicious or shortened URL — may redirect to phishing site. Verify before clicking.', severity: 'high', score: 20 });
      score += 20;
    }
  });

  const trustedDomains = /naukri\.com|internshala\.com|linkedin\.com|indeed\.com|shine\.com|monster\.com|foundit\.in/i;
  if (trustedDomains.test(url)) {
    signals.push('✓ URL belongs to a reputable job portal.');
  } else if (!flags.length && url.startsWith('https://')) {
    signals.push('✓ URL uses secure HTTPS protocol.');
  }

  if (!url.startsWith('http')) {
    flags.push({ text: '🔗 URL does not start with http/https — may be a malformed or fake link.', severity: 'low', score: 5 });
    score += 5;
  }

  return { flags, signals, score };
}

// ─── DESCRIPTION ANALYSIS ──────────────────────────────────────────────────

function analyzeDescription(desc) {
  const flags = [];
  const signals = [];
  let score = 0;

  if (!desc.trim()) {
    flags.push({ text: '📋 No job description provided — real jobs always have detailed descriptions.', severity: 'high', score: 18 });
    return { flags, signals, score: 18 };
  }

  const wordCount = desc.trim().split(/\s+/).length;
  if (wordCount < 30) {
    flags.push({ text: `📋 Description is very short (${wordCount} words) — real job postings are detailed.`, severity: 'medium', score: 12 });
    score += 12;
  }

  // Check each category
  const categoryScores = {};

  Object.entries(RED_FLAGS).forEach(([key, category]) => {
    let catScore = 0;
    const matches = [];

    category.patterns.forEach(pattern => {
      if (pattern.test(desc)) {
        const matchText = desc.match(pattern)?.[0] || '';
        if (!matches.includes(matchText)) matches.push(matchText);
      }
    });

    if (matches.length > 0) {
      const severity = matches.length >= 2 ? 'high' : 'medium';
      const addScore = Math.min(category.weight, matches.length * (category.weight / 2));
      flags.push({
        text: Object.values(category.messages)[0],
        severity,
        score: addScore,
        category: category.label
      });
      catScore = addScore;
      score += addScore;
    }

    categoryScores[category.label] = catScore;
  });

  // Positive signals from description
  POSITIVE_SIGNALS.forEach(sig => {
    if (sig.pattern.test(desc)) {
      signals.push(sig.text);
      score = Math.max(0, score - sig.points);
    }
  });

  return { flags, signals, score, categoryScores };
}

// ─── JOB TITLE ANALYSIS ────────────────────────────────────────────────────

function analyzeTitle(title) {
  const flags = [];
  const signals = [];
  let score = 0;

  if (!title.trim()) return { flags, signals, score: 0 };

  const suspiciousTitlePatterns = [
    { pattern: /work from home|wfh/i,           text: '📌 Title emphasises "Work From Home" — often used to lure applicants.', s: 8 },
    { pattern: /data entry|typing work|copy paste/i, text: '📌 Data-entry / copy-paste titles are heavily associated with scam listings.', s: 12 },
    { pattern: /earn.*online|online.*earn/i,     text: '📌 "Earn Online" phrasing in the title is a classic scam signal.', s: 15 },
    { pattern: /part.?time.*home|home.*part.?time/i, text: '📌 Part-time home-based titles frequently belong to fake/MLM listings.', s: 10 },
    { pattern: /ad posting|form fill/i,          text: '📌 Ad-posting / form-filling jobs are almost universally fraudulent.', s: 18 },
    { pattern: /reseller|drop.?ship/i,           text: '📌 Reseller / dropshipping titles — often unpaid or deceptive schemes.', s: 10 },
    { pattern: /survey/i,                        text: '📌 Survey-based job titles rarely pay meaningful amounts.', s: 8 },
    { pattern: /no experience.*required|fresher.*any.*graduate/i, text: '📌 Extremely broad eligibility in the title is a vagueness red flag.', s: 6 },
  ];

  const goodTitlePatterns = [
    { pattern: /engineer|developer|analyst|designer|manager|coordinator|executive|associate|specialist/i,
      text: '✓ Job title matches a recognisable professional role.' },
    { pattern: /intern(ship)?/i, text: '✓ Internship title is specific and standard.' },
  ];

  suspiciousTitlePatterns.forEach(({ pattern, text, s }) => {
    if (pattern.test(title)) {
      flags.push({ text, severity: s >= 12 ? 'high' : 'medium', score: s });
      score += s;
    }
  });

  if (flags.length === 0) {
    goodTitlePatterns.forEach(({ pattern, text }) => {
      if (pattern.test(title)) signals.push(text);
    });
  }

  return { flags, signals, score };
}

// ─── COMPANY NAME ANALYSIS ─────────────────────────────────────────────────

function analyzeCompany(name) {
  const flags = [];
  const signals = [];
  let score = 0;

  if (!name.trim()) {
    flags.push({ text: '🏢 No company name provided — anonymous job postings are a major red flag.', severity: 'high', score: 20 });
    return { flags, signals, score: 20 };
  }

  const suspiciousNames = [/make money/i, /earn online/i, /work from home company/i, /home based company/i];
  suspiciousNames.forEach(p => {
    if (p.test(name)) {
      flags.push({ text: '🏢 Company name contains suspicious phrases.', severity: 'medium', score: 15 });
      score += 15;
    }
  });

  if (name.trim().length > 3) {
    signals.push(`✓ Company name "${name.trim()}" is provided.`);
  }

  return { flags, signals, score };
}

// ─── MAIN ANALYSIS FUNCTION ────────────────────────────────────────────────

async function analyzeJob() {
  const title   = document.getElementById('jobTitle').value;
  const company = document.getElementById('companyName').value;
  const email   = document.getElementById('contactEmail').value;
  const salary  = document.getElementById('salary').value;
  const url     = document.getElementById('jobUrl').value;
  const desc    = document.getElementById('jobDesc').value;

  if (!title.trim() && !company.trim() && !desc.trim()) {
    showToast('⚠️ Please fill in at least one field before analyzing.');
    return;
  }

  const btn = document.getElementById('analyzeBtn');
  btn.classList.add('loading');
  btn.querySelector('.btn-icon').textContent = '⏳';
  btn.disabled = true;

  // ── Rule-based analysis ───────────────────────────────────────────────────
  const allFlags   = [];
  const allSignals = [];
  let   totalScore = 0;

  const titleResult   = analyzeTitle(title);
  const descResult    = analyzeDescription(desc);
  const emailResult   = analyzeEmail(email);
  const salaryResult  = analyzeSalary(salary);
  const urlResult     = analyzeUrl(url);
  const companyResult = analyzeCompany(company);

  allFlags.push(...titleResult.flags, ...descResult.flags, ...emailResult.flags,
                ...salaryResult.flags, ...urlResult.flags, ...companyResult.flags);
  allSignals.push(...titleResult.signals, ...descResult.signals, ...emailResult.signals,
                  ...salaryResult.signals, ...urlResult.signals, ...companyResult.signals);

  totalScore += titleResult.score + descResult.score + emailResult.score +
                salaryResult.score + urlResult.score + companyResult.score;

  const ruleScore     = Math.min(100, Math.round(totalScore));
  const breakdownData = buildBreakdown(titleResult, descResult, emailResult, salaryResult, urlResult, companyResult);

  // ── ML prediction via Flask backend ──────────────────────────────────────
  let mlResult = null;
  try {
    const resp = await fetch('/api/analyze', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ title, company, desc }),
    });
    const json = await resp.json();
    if (json.ml_available) mlResult = json;
  } catch (_) { /* server not running or endpoint unavailable */ }

  // ── Combine scores (60% rule-based + 40% ML) ─────────────────────────────
  let finalScore = ruleScore;
  if (mlResult) {
    finalScore = Math.min(100, Math.round(0.6 * ruleScore + 0.4 * mlResult.fake_prob));
  }

  // ── Render ────────────────────────────────────────────────────────────────
  renderResults(finalScore, allFlags, allSignals, breakdownData,
                { title, company, email, salary, url, desc }, mlResult);
  saveToHistory(finalScore, allFlags, { title, company });

  // ── Persist to Flask DB and get permalink ────────────────────────────────
  try {
    const sortedFlags    = [...allFlags].sort((a, b) => b.score - a.score);
    const uniqueSignals  = [...new Set(allSignals)];
    const verdict        = finalScore <= 25 ? 'safe' : finalScore <= 55 ? 'suspicious' : 'danger';
    const verdictText    = finalScore <= 25 ? '✅ Likely Safe'
                         : finalScore <= 55 ? '⚠️ Suspicious'
                         : '🚨 High Risk / Likely Fake';

    const saveResp = await fetch('/api/save', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        title, company, email, salary, url, desc,
        risk_score:    finalScore,
        verdict,
        verdict_text:  verdictText,
        ml_label:      mlResult ? mlResult.label      : '',
        ml_confidence: mlResult ? mlResult.confidence : 0,
        flag_count:    sortedFlags.length,
        signal_count:  uniqueSignals.length,
        flags:         sortedFlags,
        signals:       uniqueSignals,
        breakdown:     breakdownData,
      }),
    });
    const saved = await saveResp.json();
    if (saved.scan_id) {
      const btn = document.getElementById('permalinkBtn');
      btn._scanId       = saved.scan_id;
      btn.style.display = 'inline-flex';
    }
  } catch (_) { /* DB save failed silently */ }

  btn.classList.remove('loading');
  btn.querySelector('.btn-icon').textContent = '🔍';
  btn.disabled = false;

  if (window.innerWidth < 900) {
    document.getElementById('resultsPanel').scrollIntoView({ behavior: 'smooth' });
  }
}

// ─── BUILD CATEGORY BREAKDOWN ──────────────────────────────────────────────

function buildBreakdown(title, desc, email, salary, url, company) {
  return [
    {
      label: 'Job Title',
      score: Math.min(100, Math.round((title.score / 20) * 100)),
      raw: title.score
    },
    {
      label: 'Job Description',
      score: Math.min(100, Math.round((desc.score / 60) * 100)),
      raw: desc.score
    },
    {
      label: 'Email Check',
      score: Math.min(100, Math.round((email.score / 25) * 100)),
      raw: email.score
    },
    {
      label: 'Salary Analysis',
      score: Math.min(100, Math.round((salary.score / 30) * 100)),
      raw: salary.score
    },
    {
      label: 'URL / Source',
      score: Math.min(100, Math.round((url.score / 25) * 100)),
      raw: url.score
    },
    {
      label: 'Company Info',
      score: Math.min(100, Math.round((company.score / 25) * 100)),
      raw: company.score
    }
  ];
}

// ─── RENDER RESULTS ────────────────────────────────────────────────────────

function renderResults(score, flags, signals, breakdown, rawData, mlResult) {
  document.getElementById('idleState').style.display = 'none';
  document.getElementById('resultsContent').style.display = 'block';

  // Score ring
  const ring = document.getElementById('ringFill');
  const circumference = 314;
  const offset = circumference - (score / 100) * circumference;

  // Color based on score
  let color, verdictClass, verdictText, verdictDesc;

  if (score <= 25) {
    color = '#22c55e';
    verdictClass = 'safe';
    verdictText = '✅ Likely Safe';
    verdictDesc = 'No major red flags detected. Still do basic verification before sharing personal details.';
  } else if (score <= 55) {
    color = '#f59e0b';
    verdictClass = 'suspicious';
    verdictText = '⚠️ Suspicious';
    verdictDesc = 'Several warning signs found. Proceed with caution — research the company independently.';
  } else {
    color = '#ef4444';
    verdictClass = 'danger';
    verdictText = '🚨 High Risk / Likely Fake';
    verdictDesc = 'Multiple serious red flags detected. This posting has strong indicators of being a scam.';
  }

  ring.style.stroke = color;
  ring.style.strokeDashoffset = offset;

  // Animate score number
  animateNumber(document.getElementById('scoreNumber'), 0, score, 900);

  // Verdict
  const badge = document.getElementById('verdictBadge');
  badge.textContent = verdictText;
  badge.className = `verdict-badge ${verdictClass}`;
  document.getElementById('verdictDesc').textContent = verdictDesc;

  // ML result badge
  const mlEl = document.getElementById('mlResult');
  if (mlEl) {
    if (mlResult) {
      const cls = mlResult.label === 'Fake' ? 'ml-danger' : 'ml-safe';
      mlEl.innerHTML = `<span class="ml-pill ${cls}">🤖 ML: ${mlResult.label} · ${mlResult.confidence}% confidence</span>`;
      mlEl.style.display = 'block';
    } else {
      mlEl.style.display = 'none';
    }
  }

  // Red flags
  const flagsList = document.getElementById('flagsList');
  const noFlags   = document.getElementById('noFlags');
  flagsList.innerHTML = '';

  const sortedFlags = [...flags].sort((a, b) => b.score - a.score);

  if (sortedFlags.length === 0) {
    noFlags.style.display = 'block';
  } else {
    noFlags.style.display = 'none';
    sortedFlags.forEach((flag, i) => {
      const li = document.createElement('li');
      li.className = 'flag-item';
      li.style.animationDelay = `${i * 0.06}s`;
      const tagClass = flag.severity === 'high' ? 'tag-high' : flag.severity === 'medium' ? 'tag-medium' : 'tag-low';
      li.innerHTML = `
        <span class="flag-icon">⚑</span>
        <span class="flag-text">${flag.text}</span>
        <span class="flag-tag ${tagClass}">${flag.severity}</span>
      `;
      flagsList.appendChild(li);
    });
  }

  // Positive signals
  const signalsList = document.getElementById('signalsList');
  signalsList.innerHTML = '';
  const uniqueSignals = [...new Set(signals)];

  if (uniqueSignals.length === 0) {
    document.getElementById('signalsSection').style.display = 'none';
  } else {
    document.getElementById('signalsSection').style.display = 'block';
    uniqueSignals.forEach((sig, i) => {
      const li = document.createElement('li');
      li.className = 'signal-item';
      li.style.animationDelay = `${i * 0.06}s`;
      li.textContent = sig;
      signalsList.appendChild(li);
    });
  }

  // Category breakdown
  const grid = document.getElementById('breakdownGrid');
  grid.innerHTML = '';
  breakdown.forEach(item => {
    const barColor = item.score >= 60 ? '#ef4444' : item.score >= 30 ? '#f59e0b' : '#22c55e';
    const div = document.createElement('div');
    div.className = 'breakdown-item';
    div.innerHTML = `
      <div class="cat-label">${item.label}</div>
      <div class="cat-bar-track">
        <div class="cat-bar-fill" style="width:0%; background:${barColor}"></div>
      </div>
      <div class="cat-score" style="color:${barColor}">${item.score}% risk</div>
    `;
    grid.appendChild(div);
    // Animate bar
    setTimeout(() => {
      div.querySelector('.cat-bar-fill').style.width = `${item.score}%`;
    }, 100);
  });

  // Safety tips
  renderTips(score, flags);

  // Store for download
  window._lastAnalysis = { score, flags: sortedFlags, signals: uniqueSignals, breakdown, rawData, verdictText, verdictDesc, mlResult };
}

// ─── SAFETY TIPS ───────────────────────────────────────────────────────────

function renderTips(score, flags) {
  const tipsList = document.getElementById('tipsList');
  tipsList.innerHTML = '';

  const tips = [
    'Search the company name on Google with keywords like "scam" or "fraud" before applying.',
    'Never pay any fee to get a job — this is illegal under Indian law.',
    'Verify the company exists on the MCA portal (mca.gov.in) using their CIN number.',
    'Check the company\'s presence on LinkedIn before sharing your resume.',
    'Do not share Aadhar, PAN, or bank details until you receive a formal offer letter.',
    'Video-call the HR before joining — fake recruiters avoid video calls.',
    'Cross-check the job on the company\'s official website career page.',
    'Ask for a signed offer letter on company letterhead before resigning from current job.'
  ];

  // Prioritize tips based on flags
  const hasFeeFlag = flags.some(f => f.text.includes('fee') || f.text.includes('money'));
  const hasEmailFlag = flags.some(f => f.text.includes('email'));
  const hasPersonalInfoFlag = flags.some(f => f.text.includes('Aadhar'));

  const selected = [];
  if (hasFeeFlag) selected.push(tips[1]);
  if (hasEmailFlag) selected.push(tips[3]);
  if (hasPersonalInfoFlag) selected.push(tips[4]);
  selected.push(tips[0], tips[2], tips[5], tips[6]);

  const finalTips = [...new Set(selected)].slice(0, 5);

  finalTips.forEach(tip => {
    const li = document.createElement('li');
    li.className = 'tip-item';
    li.textContent = tip;
    tipsList.appendChild(li);
  });
}

// ─── UTILITIES ─────────────────────────────────────────────────────────────

function animateNumber(el, from, to, duration) {
  const start = performance.now();
  function update(time) {
    const elapsed = time - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(from + (to - from) * eased);
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

function showToast(message, duration = 3000) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), duration);
}

function clearAll() {
  ['jobTitle', 'companyName', 'contactEmail', 'salary', 'jobUrl', 'jobDesc'].forEach(id => {
    document.getElementById(id).value = '';
  });
  document.getElementById('charCount').textContent = '0 characters';
  document.getElementById('idleState').style.display = 'block';
  document.getElementById('resultsContent').style.display = 'none';
  showToast('✓ Form cleared.');
}

function downloadReport() {
  if (!window._lastAnalysis) return;
  const { score, flags, signals, rawData, verdictText, verdictDesc } = window._lastAnalysis;

  const date = new Date().toLocaleString('en-IN');
  let report = `JOBGUARD — FAKE JOB DETECTION REPORT
Generated: ${date}
${'='.repeat(50)}

JOB DETAILS ANALYZED
Job Title   : ${rawData.title || 'N/A'}
Company     : ${rawData.company || 'N/A'}
Email       : ${rawData.email || 'N/A'}
Salary      : ${rawData.salary || 'N/A'}
URL         : ${rawData.url || 'N/A'}

${'='.repeat(50)}
RISK SCORE: ${score}/100
VERDICT   : ${verdictText}
${verdictDesc}

${'='.repeat(50)}
RED FLAGS DETECTED (${flags.length})
${'─'.repeat(40)}
${flags.length === 0 ? 'No red flags found.' : flags.map((f, i) => `${i + 1}. [${f.severity.toUpperCase()}] ${f.text.replace(/^[^\s]+ /, '')}`).join('\n')}

${'='.repeat(50)}
POSITIVE SIGNALS (${signals.length})
${'─'.repeat(40)}
${signals.length === 0 ? 'No positive signals detected.' : signals.map((s, i) => `${i + 1}. ${s}`).join('\n')}

${'='.repeat(50)}
DISCLAIMER: This report is generated by an automated tool for educational purposes.
Always independently verify before making job decisions.
${'='.repeat(50)}
`;

  const blob = new Blob([report], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `JobGuard_Report_${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('✓ Report downloaded!');
}

function copyReport() {
  if (!window._lastAnalysis) return;
  const { score, flags, verdictText } = window._lastAnalysis;
  const text = `JobGuard Analysis Result\nRisk Score: ${score}/100\nVerdict: ${verdictText}\nRed Flags: ${flags.length}\n\nTop Issues:\n${flags.slice(0, 3).map(f => '• ' + f.text.replace(/^[^\s]+ /, '')).join('\n')}`;
  navigator.clipboard.writeText(text).then(() => showToast('✓ Summary copied to clipboard!')).catch(() => showToast('❌ Could not copy — try manually.'));
}

// ─── SAMPLE PRESETS ────────────────────────────────────────────────────────

const PRESETS = {
  fake: {
    jobTitle:     'Online Data Entry Work From Home',
    companyName:  'EarnEasy Solutions',
    contactEmail: 'earn.easy.jobs@gmail.com',
    salary:       '₹5,000 per day guaranteed',
    jobUrl:       'http://bit.ly/earn-now-jobs',
    jobDesc: `URGENT HIRING! Limited seats available — ACT NOW!

We are hiring for simple online data entry and ad posting jobs. No experience needed, anyone can apply. Earn ₹5,000 per day working just 2–3 hours from home.

WHAT YOU WILL DO:
- Simple copy-paste and form filling tasks
- Ad posting on social media
- Survey filling for our clients

TO GET STARTED:
Pay a one-time refundable security deposit of ₹1,500 to activate your account and receive your work kit. Send your Aadhar card and bank details to this WhatsApp number to apply immediately.

Don't miss this last chance! Offer expires in 24 hours. Apply before it closes!`
  },

  suspicious: {
    jobTitle:     'Field Sales Executive — Freshers Welcome',
    companyName:  'NextGen Distributors',
    contactEmail: 'hr.nextgendist@yahoo.com',
    salary:       '₹15,000 – ₹25,000/month + incentives',
    jobUrl:       'https://nextgen-dist-jobs.xyz/apply',
    jobDesc: `We are looking for energetic Field Sales Executives to join our growing team. Immediate joining required.

Responsibilities:
- Visit customers and promote our range of products
- Refer and recruit new team members to grow your network
- Earn bonus for every new member you bring onboard

Requirements: Any graduate, own vehicle preferred, age below 28.

Limited vacancies — urgent hiring. Apply directly on WhatsApp with your photo and address proof.`
  },

  legit: {
    jobTitle:     'Frontend Developer Intern',
    companyName:  'Pixelcraft Technologies Pvt. Ltd.',
    contactEmail: 'careers@pixelcraft.co.in',
    salary:       '₹12,000/month stipend',
    jobUrl:       'https://www.linkedin.com/jobs/view/pixelcraft-frontend-intern',
    jobDesc: `Pixelcraft Technologies (CIN: U72200MH2018PTC301234) is hiring a Frontend Developer Intern for a 3-month paid internship.

About Us: We are a 50-person product company building SaaS tools for SMEs. Our office is in Pune. Find us on Glassdoor and LinkedIn.

Responsibilities:
- Build and maintain React.js components
- Collaborate with design team on UI/UX improvements
- Write unit tests and documentation

Requirements:
- Pursuing B.E. / B.Tech in CS, IT, or related field
- Knowledge of HTML, CSS, JavaScript, React
- Good communication skills

Selection Process:
1. Online aptitude test
2. Technical interview (video call)
3. HR round + offer letter issuance

Benefits: Completion certificate, LOR, PF-eligible conversion on PPO. Background verification will be conducted. Do NOT share financial details during the application process.`
  }
};

function loadPreset(type) {
  const p = PRESETS[type];
  if (!p) return;
  document.getElementById('jobTitle').value      = p.jobTitle;
  document.getElementById('companyName').value   = p.companyName;
  document.getElementById('contactEmail').value  = p.contactEmail;
  document.getElementById('salary').value        = p.salary;
  document.getElementById('jobUrl').value        = p.jobUrl;
  document.getElementById('jobDesc').value       = p.jobDesc;

  const len = p.jobDesc.length;
  document.getElementById('charCount').textContent = `${len} character${len !== 1 ? 's' : ''}`;

  const labels = { fake: '🚨 Fake Job', suspicious: '⚠️ Suspicious Post', legit: '✅ Legit Job' };
  showToast(`✓ Loaded: ${labels[type]} example`);
}

// ─── SCAN HISTORY ──────────────────────────────────────────────────────────

const HISTORY_KEY = 'jobguard_history';
const MAX_HISTORY = 5;

function saveToHistory(score, flags, rawData) {
  const entry = {
    id: Date.now(),
    date: new Date().toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' }),
    title:   rawData.title   || 'Untitled Job',
    company: rawData.company || 'Unknown Company',
    score,
    verdict: score <= 25 ? 'safe' : score <= 55 ? 'suspicious' : 'danger',
    verdictText: score <= 25 ? 'Likely Safe' : score <= 55 ? 'Suspicious' : 'High Risk',
    flagCount: flags.length
  };

  let history = getHistory();
  history.unshift(entry);
  if (history.length > MAX_HISTORY) history = history.slice(0, MAX_HISTORY);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  renderHistory();
}

function getHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
  catch { return []; }
}

function clearHistory() {
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
  showToast('✓ Scan history cleared.');
}

function renderHistory() {
  const history = getHistory();
  const section = document.getElementById('historySection');
  const list    = document.getElementById('historyList');

  if (history.length === 0) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'block';
  list.innerHTML = '';

  history.forEach(entry => {
    const div = document.createElement('div');
    div.className = `history-item history-${entry.verdict}`;
    div.innerHTML = `
      <div class="hist-info">
        <span class="hist-title">${entry.title}</span>
        <span class="hist-company">${entry.company}</span>
      </div>
      <div class="hist-meta">
        <span class="hist-score" style="color:var(--${entry.verdict === 'safe' ? 'safe' : entry.verdict === 'suspicious' ? 'warn' : 'danger'})">${entry.score}/100</span>
        <span class="hist-verdict hist-v-${entry.verdict}">${entry.verdictText}</span>
        <span class="hist-date">${entry.date}</span>
      </div>
    `;
    list.appendChild(div);
  });
}

// ─── HOW IT WORKS TOGGLE ───────────────────────────────────────────────────

function toggleHow(btn) {
  const content = document.getElementById('howContent');
  const expanded = btn.getAttribute('aria-expanded') === 'true';
  btn.setAttribute('aria-expanded', String(!expanded));
  btn.querySelector('.how-chevron').style.transform = expanded ? 'rotate(0deg)' : 'rotate(90deg)';
  if (expanded) {
    content.hidden = true;
  } else {
    content.hidden = false;
  }
}

// ─── RESULT SIDE DRAWER ────────────────────────────────────────────────────

function openDrawer() {
  const a = window._lastAnalysis;
  if (!a) return;

  const { score, flags, signals, breakdown, rawData, verdictText, verdictDesc, mlResult } = a;

  // Title / sub
  document.getElementById('drawerTitle').textContent = rawData.title || 'Untitled Job';
  document.getElementById('drawerSub').textContent   = rawData.company || '';

  // Full-page link
  const fullLink = document.getElementById('drawerFullLink');
  const permBtn  = document.getElementById('permalinkBtn');
  if (permBtn && permBtn._scanId) fullLink.href = `/result/${permBtn._scanId}`;
  else fullLink.style.display = 'none';

  // Score ring
  const circ   = 314;
  const offset = circ - (score / 100) * circ;
  let color;
  if (score <= 25)      color = '#22c55e';
  else if (score <= 55) color = '#f59e0b';
  else                  color = '#ef4444';

  const ring = document.getElementById('drawerRingFill');
  ring.style.stroke = color;
  setTimeout(() => { ring.style.strokeDashoffset = offset; }, 30);
  animateNumber(document.getElementById('drawerScoreNum'), 0, score, 900);

  // Verdict
  const vcls = score <= 25 ? 'safe' : score <= 55 ? 'suspicious' : 'danger';
  const vBadge = document.getElementById('drawerVerdict');
  vBadge.textContent = verdictText;
  vBadge.className   = `verdict-badge ${vcls}`;
  document.getElementById('drawerVerdictDesc').textContent = verdictDesc;

  // ML pill
  const mlPill = document.getElementById('drawerMlPill');
  if (mlResult) {
    const cls = mlResult.label === 'Fake' ? 'ml-danger' : 'ml-safe';
    mlPill.innerHTML = `<span class="ml-pill ${cls}">🤖 ML: ${mlResult.label} · ${mlResult.confidence}% confidence</span>`;
  } else {
    mlPill.innerHTML = '';
  }

  // Red flags
  const flagsList = document.getElementById('drawerFlagsList');
  const noFlags   = document.getElementById('drawerNoFlags');
  flagsList.innerHTML = '';
  if (flags.length === 0) {
    noFlags.style.display = 'block';
  } else {
    noFlags.style.display = 'none';
    flags.forEach((flag, i) => {
      const li = document.createElement('li');
      li.className = 'flag-item';
      li.style.animationDelay = `${i * 0.05}s`;
      const tagClass = flag.severity === 'high' ? 'tag-high' : flag.severity === 'medium' ? 'tag-medium' : 'tag-low';
      li.innerHTML = `<span class="flag-icon">⚑</span><span class="flag-text">${flag.text}</span><span class="flag-tag ${tagClass}">${flag.severity}</span>`;
      flagsList.appendChild(li);
    });
  }

  // Signals
  const sigSec  = document.getElementById('drawerSignalsSection');
  const sigList = document.getElementById('drawerSignalsList');
  sigList.innerHTML = '';
  if (signals.length === 0) {
    sigSec.style.display = 'none';
  } else {
    sigSec.style.display = 'block';
    signals.forEach(sig => {
      const li = document.createElement('li');
      li.className = 'signal-item';
      li.textContent = sig;
      sigList.appendChild(li);
    });
  }

  // Breakdown bars
  const bdEl = document.getElementById('drawerBreakdown');
  bdEl.innerHTML = '';
  breakdown.forEach(item => {
    const barColor = item.score >= 60 ? '#ef4444' : item.score >= 30 ? '#f59e0b' : '#22c55e';
    const div = document.createElement('div');
    div.className = 'breakdown-item';
    div.innerHTML = `
      <div class="cat-label">${item.label}</div>
      <div class="cat-bar-track"><div class="cat-bar-fill" style="width:0%;background:${barColor}"></div></div>
      <div class="cat-score" style="color:${barColor}">${item.score}% risk</div>
    `;
    bdEl.appendChild(div);
    setTimeout(() => { div.querySelector('.cat-bar-fill').style.width = `${item.score}%`; }, 80);
  });

  // Safety tips
  const tipsList = document.getElementById('drawerTips');
  tipsList.innerHTML = '';
  document.querySelectorAll('#tipsList li').forEach(li => {
    const clone = li.cloneNode(true);
    tipsList.appendChild(clone);
  });

  // Show drawer
  document.getElementById('resultDrawer').classList.add('open');
  document.getElementById('resultDrawer').setAttribute('aria-hidden', 'false');
  document.getElementById('drawerBackdrop').classList.add('show');
  document.body.classList.add('drawer-open');
}

function closeDrawer() {
  document.getElementById('resultDrawer').classList.remove('open');
  document.getElementById('resultDrawer').setAttribute('aria-hidden', 'true');
  document.getElementById('drawerBackdrop').classList.remove('show');
  document.body.classList.remove('drawer-open');
}

// ─── CHAR COUNTER & ENTER KEY ──────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  renderHistory();

  const descEl = document.getElementById('jobDesc');
  const countEl = document.getElementById('charCount');

  descEl.addEventListener('input', () => {
    const len = descEl.value.length;
    countEl.textContent = `${len} character${len !== 1 ? 's' : ''}`;
  });

  // Allow Enter key in any input to trigger analyze
  document.querySelectorAll('input').forEach(input => {
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') analyzeJob();
    });
  });
});
