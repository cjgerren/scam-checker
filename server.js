const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { simpleParser } = require('mailparser');
const Tesseract = require('tesseract.js');
const { runRegressionSuite } = require('./regression-suite');

const app = express();
const PORT = process.env.PORT || 3000;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 8 * 1024 * 1024
  }
});

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static('public'));

const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'click',
  'shop',
  'icu',
  'cyou',
  'buzz',
  'monster',
  'work',
  'country',
  'stream',
  'gq',
  'tk',
  'ml',
  'ga',
  'cf',
  'rest',
  'fit',
  'cam',
  'cfd'
]);

const COMMON_TLDS = new Set([
  'com',
  'org',
  'net',
  'edu',
  'gov',
  'mil',
  'us',
  'co',
  'io',
  'app',
  'dev',
  'info',
  'biz',
  'me',
  'ai',
  'uk',
  'ca',
  'au'
]);

const SAFE_DOMAINS = new Set([
  'apple.com',
  'icloud.com',
  'microsoft.com',
  'account.microsoft.com',
  'office.com',
  'live.com',
  'outlook.com',
  'paypal.com',
  'amazon.com',
  'netflix.com',
  'chase.com',
  'bankofamerica.com',
  'wellsfargo.com',
  'usps.com',
  'fedex.com',
  'ups.com',
  'dhl.com',
  'google.com'
]);

const BRAND_RULES = [
  { name: 'Apple / iCloud', variants: ['icloud', 'appleid', 'apple id', 'apple account', 'apple'] },
  { name: 'Microsoft', variants: ['microsoft', 'outlook', 'office365', 'office 365', 'hotmail', 'live.com'] },
  { name: 'PayPal', variants: ['paypal'] },
  { name: 'Amazon', variants: ['amazon'] },
  { name: 'Netflix', variants: ['netflix'] },
  { name: 'Chase', variants: ['chase', 'jpmorgan', 'jp morgan'] },
  { name: 'Bank of America', variants: ['bankofamerica', 'bank of america', 'bofa'] },
  { name: 'Wells Fargo', variants: ['wellsfargo', 'wells fargo'] },
  { name: 'USPS', variants: ['usps', 'postal service', 'post office'] },
  { name: 'FedEx', variants: ['fedex'] },
  { name: 'UPS', variants: ['ups', 'parcel service'] },
  { name: 'DHL', variants: ['dhl'] }
];

function uniq(items) {
  return [...new Set((items || []).filter(Boolean))];
}

function normalizeText(value) {
  return String(value || '')
    .normalize('NFKC')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/\r/g, ' ')
    .replace(/\t/g, ' ')
    .replace(/\n/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function looksLikeIp(value) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(value || ''));
}

function normalizeLeetspeak(value) {
  return String(value || '')
    .replace(/0/g, 'o')
    .replace(/1/g, 'i')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/8/g, 'b')
    .replace(/9/g, 'g');
}

function collapseLetterSpacing(text) {
  return normalizeText(text)
    .replace(/\b(?:[a-zA-Z]\s+){2,}[a-zA-Z]\b/g, (match) => match.replace(/\s+/g, ''))
    .replace(/\b(?:[a-zA-Z]\.?){3,}\b/g, (match) => match.replace(/\./g, ''));
}

function deobfuscateCommon(text) {
  return normalizeText(text)
    .replace(/hxxps?/gi, (m) => (m.toLowerCase() === 'hxxps' ? 'https' : 'http'))
    .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}/gi, '.')
    .replace(/\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}/gi, '.')
    .replace(/\[\s*slash\s*\]|\(\s*slash\s*\)|\{\s*slash\s*\}/gi, '/')
    .replace(/\[\s*colon\s*\]|\(\s*colon\s*\)|\{\s*colon\s*\}/gi, ':')
    .replace(/\bdot\b/gi, '.')
    .replace(/\bslash\b/gi, '/')
    .replace(/\bcolon\b/gi, ':');
}

function preprocessText(text) {
  const original = normalizeText(text);
  const deobfuscated = deobfuscateCommon(original);
  const leet = normalizeLeetspeak(deobfuscated);
  const deSpaced = collapseLetterSpacing(leet);

  const punctuationCollapsed = deSpaced
    .replace(/\s*([.:/@_-])\s*/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();

  const squashed = punctuationCollapsed.toLowerCase().replace(/[^a-z0-9]+/g, ' ');
  const compact = punctuationCollapsed.toLowerCase().replace(/[^a-z0-9]+/g, '');

  return {
    original,
    deobfuscated,
    leet,
    deSpaced,
    punctuationCollapsed,
    squashed,
    compact,
    combined: uniq([
      original,
      deobfuscated,
      leet,
      deSpaced,
      punctuationCollapsed
    ]).join('\n')
  };
}

function extractUrls(text) {
  const matches = String(text || '').match(/\bhttps?:\/\/[^\s<>"')]+/gi) || [];
  return uniq(
    matches.filter((url) => {
      const domain = getDomainFromUrl(url);
      return isValidExtractedDomain(domain);
    })
  );
}

function getDomainFromEmail(email) {
  if (!email || !String(email).includes('@')) return '';
  return String(email).split('@').pop().toLowerCase().replace(/[>),.;]+$/g, '');
}

function getDomainFromUrl(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function isAllowedTld(tld) {
  return COMMON_TLDS.has(tld) || SUSPICIOUS_TLDS.has(tld);
}

function isValidExtractedDomain(domain) {
  const value = String(domain || '').toLowerCase();
  if (!value || value.includes('@') || looksLikeIp(value)) return false;
  const parts = value.split('.');
  const tld = parts[parts.length - 1] || '';
  return parts.length >= 2 && isAllowedTld(tld);
}

function extractDomains(text) {
  const matches =
    String(text || '').toLowerCase().match(/\b(?:[a-z0-9-]{1,63}\.)+[a-z]{2,10}\b/g) || [];
  return uniq(matches.filter(isValidExtractedDomain));
}

function extractObfuscatedUrls(text) {
  const processed = preprocessText(text);
  const candidateText = [
    processed.deobfuscated,
    processed.leet,
    processed.deSpaced,
    processed.punctuationCollapsed
  ].join(' ');

  const urls = extractUrls(candidateText);
  const candidates =
    candidateText.match(/\b(?:https?:\/\/)?(?:www\.)?(?:[a-z0-9-]{1,63}\.)+[a-z]{2,10}(?:\/[^\s<>"')]*)?/gi) || [];

  for (const item of candidates) {
    const trimmed = item.trim();
    if (!trimmed) continue;

    if (/^https?:\/\//i.test(trimmed)) {
      const domain = getDomainFromUrl(trimmed);
      if (isValidExtractedDomain(domain)) {
        urls.push(trimmed);
      }
      continue;
    }

    if (trimmed.includes('.') && isValidExtractedDomain(trimmed)) {
      urls.push(`http://${trimmed}`);
    }
  }

  return uniq(urls);
}

function isSafeDomain(domain) {
  const value = String(domain || '').toLowerCase();
  if (!value) return false;
  if (SAFE_DOMAINS.has(value)) return true;

  return [...SAFE_DOMAINS].some((safe) => value === safe || value.endsWith(`.${safe}`));
}

function analyzeDomain(domain) {
  const value = String(domain || '').toLowerCase();
  const reasons = [];

  if (!value) {
    return { domain: '', isSuspicious: false, reasons };
  }

  const parts = value.split('.');
  const tld = parts[parts.length - 1] || '';
  const host = parts.slice(0, -1).join('.');

  if (isSafeDomain(value)) {
    return { domain: value, isSuspicious: false, reasons: [] };
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    reasons.push(`uses a higher-risk top-level domain (.${tld})`);
  }

  if ((host.match(/-/g) || []).length >= 2) {
    reasons.push('uses multiple hyphens often seen in phishing domains');
  }

  if (/(secure|login|verify|update|account|billing|payment|wallet|support|unlock|confirm)/.test(host)) {
    reasons.push('contains phishing-style words in the domain');
  }

  if (host.length >= 22) {
    reasons.push('has an unusually long host name');
  }

  if (/\d/.test(host) && /[a-z]/.test(host)) {
    reasons.push('mixes letters and digits in the host name');
  }

  return {
    domain: value,
    isSuspicious: reasons.length > 0,
    reasons
  };
}

function multiHas(variants, phrases) {
  return phrases.some((phrase) => variants.some((variant) => variant.includes(phrase)));
}

function detectBrands(processed) {
  const variants = [
    processed.original.toLowerCase(),
    processed.deobfuscated.toLowerCase(),
    processed.leet.toLowerCase(),
    processed.deSpaced.toLowerCase(),
    processed.punctuationCollapsed.toLowerCase(),
    processed.squashed,
    processed.compact
  ];

  const matches = [];

  for (const brand of BRAND_RULES) {
    const hit = brand.variants.some((variant) => {
      const lowerVariant = variant.toLowerCase();
      const compactVariant = lowerVariant.replace(/[^a-z0-9]+/g, '');
      return variants.some(
        (text) => text.includes(lowerVariant) || text.includes(compactVariant)
      );
    });

    if (hit) {
      matches.push(brand.name);
    }
  }

  return uniq(matches);
}

function isLikelyOfficialBrandSecurityNotice({ brands, urls, safeDomains, suspiciousDomains, signals }) {
  const hasOfficialUrl = urls.length > 0 && safeDomains.length === urls.length;
  const officialMicrosoft = brands.includes('Microsoft');
  const officialGeneric = hasOfficialUrl && brands.length > 0;

  if ((!officialMicrosoft && !officialGeneric) || suspiciousDomains.length > 0) {
    return false;
  }

  if (signals.giftCard || signals.crypto || signals.job || signals.moneyMethod || signals.refund) {
    return false;
  }

  if (signals.payment && !officialMicrosoft) {
    return false;
  }

  return signals.credential || signals.threat || signals.cta;
}

function detectScamType({ brands, urls, suspiciousDomains, signals, safeDomains }) {
  if (signals.giftCard) {
    return 'Gift card scam';
  }

  if (signals.job) {
    return 'Job scam';
  }

  if (signals.crypto && (signals.credential || signals.threat || signals.payment)) {
    return 'Crypto extortion / account scam';
  }

  if (signals.credential && signals.threat && (urls.length > 0 || suspiciousDomains.length > 0)) {
    return 'Phishing / account scam';
  }

  if (brands.length > 0 && signals.payment && (signals.threat || signals.credential)) {
    return 'Brand impersonation / payment phishing';
  }

  if (signals.payment && (signals.moneyMethod || signals.refund || suspiciousDomains.length > 0)) {
    return 'Payment scam';
  }

  if (signals.crypto) {
    return 'Crypto scam';
  }

  if (signals.delivery && suspiciousDomains.length > 0) {
    return 'Delivery scam';
  }

  if (signals.government) {
    return 'Government impersonation scam';
  }

  if (signals.prize) {
    return 'Prize scam';
  }

  if (urls.length > 0 && safeDomains.length === urls.length && suspiciousDomains.length === 0) {
    return 'General message with official link';
  }

  if (urls.length > 0 || suspiciousDomains.length > 0) {
    return 'Suspicious link / domain message';
  }

  return 'General suspicious message';
}

function buildAnalysis({
  text,
  sourceType = 'text',
  fileName = '',
  emailMeta = null
}) {
  const processed = preprocessText(text);
  const cleanText = processed.original;

  if (!cleanText) {
    return {
      risk: 'Low',
      riskScore: 0,
      scamType: 'No content detected',
      summary: 'No readable content was found.',
      redFlags: [],
      nextSteps: ['Try a clearer screenshot or paste the message text directly.'],
      urls: [],
      looseDomains: [],
      suspiciousDomains: [],
      safeDomains: [],
      brands: [],
      sourceType,
      fileName,
      emailMeta,
      extractedText: '',
      normalizedText: '',
      matchedRules: []
    };
  }

  const variants = [
    processed.original.toLowerCase(),
    processed.deobfuscated.toLowerCase(),
    processed.leet.toLowerCase(),
    processed.deSpaced.toLowerCase(),
    processed.punctuationCollapsed.toLowerCase(),
    processed.squashed,
    processed.compact
  ];

  const urls = uniq([
    ...extractUrls(processed.original),
    ...extractUrls(processed.deobfuscated),
    ...extractUrls(processed.punctuationCollapsed),
    ...extractObfuscatedUrls(processed.original)
  ]);

  const looseDomains = uniq([
    ...extractDomains(processed.original),
    ...extractDomains(processed.deobfuscated),
    ...extractDomains(processed.punctuationCollapsed),
    ...urls.map(getDomainFromUrl).filter(Boolean)
  ]);

  const safeDomains = uniq(looseDomains.filter(isSafeDomain));

  const suspiciousDomainDetails = looseDomains
    .map(analyzeDomain)
    .filter((item) => item.isSuspicious);

  const suspiciousDomains = suspiciousDomainDetails.map((item) => item.domain);
  const brands = detectBrands(processed);

  const redFlags = [];
  const matchedRules = [];
  const fired = new Set();
  let riskScore = 0;

  function addFlag(points, label, rule, extra = {}) {
    if (fired.has(rule)) return;
    fired.add(rule);
    redFlags.push(label);
    matchedRules.push({ rule, points, label, ...extra });
    riskScore += points;
  }

  const signals = {
    urgency: multiHas(variants, [
      'urgent',
      'immediately',
      'right now',
      'within24hours',
      'within 24 hours',
      'final warning',
      'act now',
      'last chance',
      'expires today',
      'asap',
      'failure to act',
      'limited time',
      'urgentactionrequired'
    ]),
    payment: multiHas(variants, [
      'payment method has expired',
      'update your payment information',
      'update payment information',
      'payment details',
      'billing',
      'billing details',
      'billing issue',
      'billing information',
      're-enter your billing details',
      'reenter your billing details',
      'failed to renew',
      'renew',
      'subscription expired',
      'payment failed',
      'could not process your recent payment',
      'could not process payment',
      'invoice',
      'charge',
      'card declined',
      'payment method',
      'billing problem',
      'outstanding balance',
      'confirm payment details'
    ]),
    threat: multiHas(variants, [
      'will be deleted',
      'deleted',
      'lose all your data',
      'account suspended',
      'temporarily restricted',
      'restricted',
      'suspended',
      'locked',
      'disabled',
      'terminated',
      'deactivated',
      'blocked',
      'limited access',
      'unusual sign in attempt',
      'security alert',
      'avoid account suspension',
      'to avoid suspension',
      'unlock your account',
      'restore access'
    ]),
    credential: multiHas(variants, [
      'verify your account',
      'verify your identity',
      'confirm your identity',
      'confirm your information',
      'confirm your info',
      'update your information',
      'update your info',
      'password',
      'security check',
      'credential',
      'validate your account',
      'restore access',
      'sign in',
      'login',
      'log in',
      'review recent sign in activity',
      'review sign in activity'
    ]),
    cta: multiHas(variants, [
      'click here',
      'update now',
      'confirm now',
      'verify now',
      'pay now',
      'log in now',
      'signinnow',
      'review now',
      'open attachment',
      'open document'
    ]),
    delivery: multiHas(variants, [
      'package',
      'delivery',
      'shipment',
      'parcel',
      'mail hold',
      'customs fee',
      'track your package'
    ]),
    government: multiHas(variants, [
      'irs',
      'tax',
      'warrant',
      'law enforcement',
      'government notice',
      'social security'
    ]),
    job: multiHas(variants, [
      'job offer',
      'remote job opportunity',
      'remote position',
      'you will receive a check',
      'receive a check',
      'deposit the check',
      'check to deposit',
      'send part of the funds back',
      'send part of the money back',
      'kindly send',
      'hiring process',
      'employment offer',
      'interview process',
      'equipment vendor',
      'purchase equipment',
      'training check'
    ]),
    prize: multiHas(variants, [
      'you have won',
      'congratulations',
      'lottery',
      'claim your reward',
      'claim your prize',
      'free iphone',
      'winner'
    ]),
    refund: multiHas(variants, [
      'refund',
      'rebate',
      'compensation'
    ]),
    moneyMethod: multiHas(variants, [
      'gift card',
      'gift cards',
      'bitcoin',
      'crypto',
      'wire transfer',
      'zelle',
      'cash app',
      'venmo',
      'paypal friends and family',
      'western union',
      'moneygram'
    ]),
    giftCard: multiHas(variants, [
      'gift card',
      'gift cards',
      'send me the codes',
      'send the codes',
      'card codes',
      'apple gift cards',
      'steam cards',
      'gift card codes',
      'buy gift cards',
      'amazon gift cards',
      'amazon gift card',
      'target gift card',
      'google play card',
      'ebay gift card',
      'razor gold'
    ]),
    crypto: multiHas(variants, [
  'bitcoin',
  'crypto',
  'wallet address',
  'transfer funds via crypto',
  'btc',
  'ethereum',
  'usdt',
  'seed phrase',
  'recovery phrase'
]) || /\beth\b/.test(processed.original.toLowerCase()) || /\beth\b/.test(processed.deobfuscated.toLowerCase()),
    secrecy: multiHas(variants, [
      'do not tell anyone',
      'keep this between us',
      'i am in a meeting',
      'quietly',
      'discreetly'
    ]),
    reimbursement: multiHas(variants, [
      'i will reimburse you',
      'i’ll reimburse you',
      'reimburse you later',
      'pay you back later'
    ])
  };

  const onlyOfficialUrls =
    urls.length > 0 &&
    urls.every((url) => {
      const domain = getDomainFromUrl(url);
      return isSafeDomain(domain);
    });

  if (urls.length > 0) {
    if (onlyOfficialUrls && suspiciousDomains.length === 0) {
      addFlag(1, 'Contains official-looking links', 'official-links', { urls });
    } else {
      addFlag(3, 'Contains one or more links or deobfuscated web addresses', 'links', { urls });
    }
  }

  if (looseDomains.length > 0 && urls.length === 0) {
    addFlag(2, 'Contains domain names or web addresses even without a full clickable URL', 'domains', {
      domains: looseDomains
    });
  }

  if (signals.urgency) {
    addFlag(3, 'Uses urgency or pressure language', 'urgency');
  }

  if (signals.payment) {
    addFlag(4, 'Pushes billing, payment, renewal, or charge-related action', 'payment');
  }

  if (signals.threat) {
    addFlag(4, 'Threatens restriction, suspension, loss, or account harm', 'threat');
  }

  if (brands.length > 0) {
    addFlag(2, `Uses major brand names commonly targeted by scammers (${brands.join(', ')})`, 'brand', {
      brands
    });
  }

  if (signals.credential) {
    addFlag(4, 'May be trying to steal credentials or force account verification', 'credential');
  }

  if (signals.cta) {
    addFlag(3, 'Strong call-to-action pushing immediate action', 'cta');
  }

  if (signals.moneyMethod) {
    addFlag(4, 'Requests hard-to-recover payment methods commonly used by scammers', 'hard-payment');
  }

  if (signals.giftCard) {
    addFlag(5, 'Requests gift cards or asks for gift card codes', 'gift-card');
  }

  if (signals.crypto) {
    addFlag(4, 'Uses crypto-related payment or wallet language', 'crypto');
  }

  if (signals.job) {
    addFlag(5, 'Matches common fake job or fake-check scam language', 'job');
  }

  if (signals.refund) {
    addFlag(3, 'Uses refund or compensation language often seen in scams', 'refund');
  }

  if (signals.prize) {
    addFlag(4, 'Uses prize, winner, or reward bait language', 'prize');
  }

  if (signals.secrecy) {
    addFlag(4, 'Uses secrecy or isolation language to control the victim', 'secrecy');
  }

  if (signals.reimbursement) {
    addFlag(3, 'Promises reimbursement later, which is common in gift card scams', 'reimbursement');
  }

  const exclamations = (cleanText.match(/!/g) || []).length;
  if (exclamations >= 2) {
    addFlag(2, 'Uses exaggerated punctuation to create panic', 'punctuation');
  }

  if (suspiciousDomainDetails.length > 0) {
    addFlag(4, `Contains suspicious domain patterns (${suspiciousDomainDetails[0].domain})`, 'suspicious-domain', {
      suspiciousDomainDetails
    });
  }

  if (signals.delivery && suspiciousDomains.length > 0) {
    addFlag(5, 'Combines delivery language with a suspicious link or domain', 'combo-delivery-link');
  }

  if (signals.credential && signals.threat && (urls.length > 0 || suspiciousDomains.length > 0)) {
    addFlag(7, 'Combines account threat, credential request, and link or domain bait', 'combo-phishing');
  }

  if (brands.length > 0 && signals.payment && (signals.threat || signals.credential)) {
    addFlag(6, 'Combines brand impersonation with payment or account pressure', 'combo-brand-phishing');
  }

  if (brands.length > 0 && suspiciousDomains.length > 0) {
    addFlag(5, 'Combines a trusted brand name with a suspicious domain', 'combo-brand-domain');
  }

  if (signals.payment && signals.threat && suspiciousDomains.length > 0) {
    addFlag(6, 'Combines payment pressure, account threat, and a suspicious domain', 'combo-payment-threat-domain');
  }

  if (signals.payment && suspiciousDomains.length > 0) {
    addFlag(5, 'Combines payment language with a suspicious domain', 'combo-payment-domain');
  }

  if (signals.giftCard && (signals.urgency || signals.secrecy || signals.reimbursement)) {
    addFlag(6, 'Combines gift card request with urgency, secrecy, or reimbursement pressure', 'combo-giftcard');
  }

  if (signals.crypto && (signals.threat || signals.credential)) {
    addFlag(6, 'Combines crypto payment language with account access pressure', 'combo-crypto-account');
  }

  if (signals.crypto && (signals.urgency || signals.payment || suspiciousDomains.length > 0)) {
    addFlag(5, 'Combines crypto language with urgency, payment pressure, or suspicious domains', 'combo-crypto-pressure');
  }

  if (signals.job && (signals.moneyMethod || multiHas(variants, ['send part of the funds back', 'send part of the money back']))) {
    addFlag(6, 'Matches classic fake-check job scam flow', 'combo-job-fakecheck');
  }

  if (signals.job && multiHas(variants, ['receive a check', 'deposit the check', 'purchase equipment', 'equipment vendor'])) {
    addFlag(6, 'Matches fake job onboarding or fake-check equipment scam behavior', 'combo-job-equipment-check');
  }

  if (signals.urgency && (signals.payment || signals.credential || signals.threat)) {
    addFlag(3, 'Combines urgency with other social-engineering pressure signals', 'combo-urgency');
  }

  if (sourceType === 'image') {
    addFlag(1, 'Image-based message requires extra caution because OCR can miss details', 'image');
  }

  if (emailMeta && emailMeta.from) {
    const fromDomain = getDomainFromEmail(emailMeta.from);
    const urlDomains = urls.map(getDomainFromUrl).filter(Boolean);

    if (fromDomain && urlDomains.length > 0) {
      const mismatch = urlDomains.some(
        (domain) => !domain.endsWith(fromDomain) && !fromDomain.endsWith(domain)
      );

      if (mismatch) {
        addFlag(3, 'Sender domain does not match linked website domain', 'domain-mismatch', {
          fromDomain,
          urlDomains
        });
      }
    }
  }

  if (
    onlyOfficialUrls &&
    suspiciousDomains.length === 0 &&
    !signals.moneyMethod &&
    !signals.giftCard &&
    !signals.crypto &&
    !signals.job &&
    !signals.refund &&
    !signals.payment
  ) {
    addFlag(-4, 'Official trusted domain lowered the score', 'safe-domain-softener');
  }

  if (
    isLikelyOfficialBrandSecurityNotice({
      brands,
      urls,
      safeDomains,
      suspiciousDomains,
      signals
    })
  ) {
    addFlag(-6, 'Official brand security notice lowered the score', 'official-brand-security-softener');
  }

  if (riskScore < 0) {
    riskScore = 0;
  }

  let risk = 'Low';
  if (riskScore >= 12) {
    risk = 'High';
  } else if (riskScore >= 6) {
    risk = 'Medium';
  }

  const scamType = detectScamType({
    brands,
    urls,
    suspiciousDomains,
    signals,
    safeDomains
  });

  let summary = 'This message appears mostly safe, but you should still verify it carefully.';
  if (risk === 'Medium') {
    summary = 'This message has multiple suspicious signals and should be treated carefully.';
  }
  if (risk === 'High') {
    summary = 'This message strongly matches phishing or scam behavior.';
  }

  return {
    risk,
    riskScore,
    scamType,
    summary,
    redFlags: uniq(redFlags),
    nextSteps: [
      'Do not click links or open unexpected attachments',
      'Do not send money, passwords, verification codes, or personal information',
      'Go directly to the official website or app instead of using message links',
      'If the message claims to be from a company, contact that company using its official contact info'
    ],
    urls,
    looseDomains,
    suspiciousDomains,
    safeDomains,
    brands,
    sourceType,
    fileName,
    emailMeta,
    extractedText: cleanText,
    normalizedText: processed.punctuationCollapsed,
    matchedRules
  };
}

async function parseEmlFile(buffer) {
  const parsed = await simpleParser(buffer);

  const bodyText = [
    parsed.subject,
    parsed.text,
    parsed.html ? parsed.html.replace(/<[^>]+>/g, ' ') : ''
  ]
    .filter(Boolean)
    .join(' ');

  return {
    text: bodyText,
    emailMeta: {
      from: parsed.from?.text || '',
      to: parsed.to?.text || '',
      subject: parsed.subject || '',
      date: parsed.date ? parsed.date.toString() : ''
    }
  };
}

async function extractTextFromImage(buffer) {
  const result = await Tesseract.recognize(buffer, 'eng', {
    logger: () => {}
  });

  return normalizeText(result?.data?.text || '');
}

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    message: 'Scam Checker server is running',
    time: new Date().toISOString()
  });
});

app.post('/analyze-text', (req, res) => {
  try {
    const text = normalizeText(req.body?.text);

    if (!text) {
      return res.status(400).json({ error: 'No text provided.' });
    }

    const result = buildAnalysis({
      text,
      sourceType: 'text'
    });

    console.log('TEXT ANALYSIS RESULT:', JSON.stringify(result, null, 2));
    res.json(result);
  } catch (error) {
    console.error('analyze-text error:', error);
    res.status(500).json({ error: 'Failed to analyze text.' });
  }
});

app.post('/analyze-file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    const fileName = req.file.originalname || '';
    const mimeType = req.file.mimetype || '';
    const lowerName = fileName.toLowerCase();

    let text = '';
    let emailMeta = null;
    let sourceType = 'file';

    if (lowerName.endsWith('.eml')) {
      const parsed = await parseEmlFile(req.file.buffer);
      text = parsed.text;
      emailMeta = parsed.emailMeta;
      sourceType = 'email';
    } else if (
      mimeType.startsWith('image/') ||
      lowerName.endsWith('.png') ||
      lowerName.endsWith('.jpg') ||
      lowerName.endsWith('.jpeg') ||
      lowerName.endsWith('.webp')
    ) {
      text = await extractTextFromImage(req.file.buffer);
      sourceType = 'image';
    } else {
      text = req.file.buffer.toString('utf8');
      sourceType = 'file';
    }

    const result = buildAnalysis({
      text,
      sourceType,
      fileName,
      emailMeta
    });

    console.log('FILE ANALYSIS RESULT:', JSON.stringify(result, null, 2));
    res.json(result);
  } catch (error) {
    console.error('analyze-file error:', error);
    res.status(500).json({ error: 'Failed to analyze uploaded file.' });
  }
});

app.get('/test-results', async (req, res) => {
  try {
    const report = await runRegressionSuite({
      analyze: async (text) =>
        buildAnalysis({
          text: normalizeText(text),
          sourceType: 'text'
        })
    });

    res.json(report);
  } catch (error) {
    console.error('test-results error:', error);
    res.status(500).json({ error: 'Failed to run regression tests.' });
  }
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
}

module.exports = {
  app,
  buildAnalysis,
  normalizeText,
  preprocessText,
  detectBrands,
  extractUrls,
  extractDomains,
  extractObfuscatedUrls,
  analyzeDomain,
  isSafeDomain
};