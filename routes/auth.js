const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');
const { memStore }    = require('../models');
const { signToken, setAuthCookie, clearAuthCookie, requireAuth } = require('../middleware/auth');
const { generateOTP, sendOTPEmail, sendWelcomeEmail } = require('../services/emailService');
const { logAction } = require('../services/actionLogger');

function getDB() {
  if (global.dbConnected) {
    const { getModels } = require('../config/db');
    return getModels();
  }
  return {};
}

// ── POST /api/auth/register ────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { email, password, username } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const em = email.toLowerCase().trim();
    const { UserModel } = getDB();
    const exists = UserModel ? await UserModel.findOne({ email: em }) : await memStore.findUser(em);
    if (exists) return res.status(409).json({ error: 'Email already registered' });

    let user;
    if (UserModel) {
      const bcrypt = require('bcryptjs');
      const hash   = await bcrypt.hash(password, 12);
      const shareToken = crypto.randomBytes(12).toString('hex');
      user = await UserModel.create({ email: em, password: hash, username: username || em.split('@')[0], shareToken });
    } else {
      user = await memStore.createUser({ email: em, password, username: username || em.split('@')[0] });
    }

    const otp = generateOTP();
    if (UserModel) {
      await UserModel.updateOne({ _id: user._id }, { otp, otpExpiry: new Date(Date.now() + 5*60*1000) });
    } else {
      await memStore.setOTP(em, otp, 'register');
    }
    await sendOTPEmail(em, otp, 'register');
    logAction({ actor: 'system', action: 'register', target: em, success: true });

    return res.status(201).json({
      message: 'Account created. Check your email for verification code.',
      email: em,
      needsVerification: true
    });
  } catch(e) {
    console.error('[register]', e);
    return res.status(500).json({ error: 'Registration failed' });
  }
});

// ── POST /api/auth/verify-otp ─────────────────────────
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });
    const em = email.toLowerCase().trim();

    const { UserModel } = getDB();
    let user, valid = false;

    if (UserModel) {
      user = await UserModel.findOne({ email: em });
      if (!user) return res.status(404).json({ error: 'User not found' });
      if (!user.otp || user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });
      if (new Date() > user.otpExpiry) return res.status(400).json({ error: 'OTP expired. Request a new one.' });
      await UserModel.updateOne({ _id: user._id }, { isVerified: true, otp: null, otpExpiry: null });
      user = await UserModel.findById(user._id).lean();
      valid = true;
    } else {
      valid = await memStore.verifyOTP(em, otp, 'register');
      user  = await memStore.findUser(em);
    }

    if (!valid || !user) return res.status(400).json({ error: 'Invalid or expired OTP' });

    sendWelcomeEmail(em, user.username || em.split('@')[0]).catch(() => {});
    logAction({ actor: String(user._id), action: 'verify_email', success: true });

    const token = signToken({ id: user._id, email: user.email, role: user.role, isAdmin: user.isAdmin });
    setAuthCookie(res, token);

    return res.json({
      message: 'Email verified! Welcome to Raiplus.',
      token,
      user: {
        id: user._id, email: user.email, username: user.username,
        role: user.role, dailyQuota: user.dailyQuota,
        waitlistPosition: user.waitlistPosition, shareToken: user.shareToken,
        isAdmin: user.isAdmin || false
      }
    });
  } catch(e) {
    console.error('[verify-otp]', e);
    return res.status(500).json({ error: 'Verification failed' });
  }
});

// ── POST /api/auth/resend-otp ─────────────────────────
router.post('/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    const em  = email.toLowerCase().trim();
    const otp = generateOTP();
    const { UserModel } = getDB();
    if (UserModel) {
      await UserModel.updateOne({ email: em }, { otp, otpExpiry: new Date(Date.now() + 5*60*1000) });
    } else {
      await memStore.setOTP(em, otp, 'register');
    }
    await sendOTPEmail(em, otp, 'register');
    return res.json({ message: 'OTP resent' });
  } catch(e) {
    return res.status(500).json({ error: 'Failed to resend OTP' });
  }
});

// ── POST /api/auth/login ──────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const em = email.toLowerCase().trim();

    const { UserModel } = getDB();
    let user, valid;
    const bcrypt = require('bcryptjs');

    if (UserModel) {
      user = await UserModel.findOne({ email: em }).lean();
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });
      valid = await bcrypt.compare(password, user.password);
    } else {
      user  = await memStore.findUser(em);
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });
      valid = await memStore.comparePassword(user, password);
    }

    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.isBanned) return res.status(403).json({ error: 'account_banned', reason: user.banReason || 'Contact support.' });

    if (UserModel) {
      await UserModel.updateOne({ _id: user._id }, { lastLogin: new Date() });
    } else {
      await memStore.updateUser(String(user._id), { lastLogin: new Date() });
    }

    logAction({ actor: String(user._id), action: 'login_success', success: true });

    const token = signToken({ id: user._id, email: user.email, role: user.role, isAdmin: user.isAdmin });
    setAuthCookie(res, token);

    return res.json({
      message:     'Login successful',
      token,
      accessToken: token,   // SDK TokenManager reads `accessToken` or `token`
      expiresIn:   3600,    // seconds — SDK uses this to schedule token refresh
      user: {
        id: user._id, email: user.email, username: user.username,
        role: user.role, dailyQuota: user.dailyQuota,
        isAdmin: user.isAdmin || false, shareToken: user.shareToken
      }
    });
  } catch(e) {
    console.error('[login]', e);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// ── POST /api/auth/logout ─────────────────────────────
router.post('/logout', (req, res) => {
  clearAuthCookie(res);
  logAction({ actor: 'user', action: 'logout', success: true });
  return res.json({ message: 'Logged out' });
});

// ── GET /api/auth/me ──────────────────────────────────
router.get('/me', requireAuth, (req, res) => {
  const u     = req.user;
  const dbU   = memStore.users?.find(x => String(x._id) === String(u._id || u.id)) || u;
  const quota = memStore.getEffectiveQuota ? memStore.getEffectiveQuota(dbU) : (u.dailyQuota || 50);
  res.json({
    id: u._id || u.id, email: u.email, username: u.username,
    role: u.role, isAdmin: u.isAdmin || false,
    dailyQuota: quota, baseQuota: u.dailyQuota,
    shareToken: u.shareToken, shareBonus: u.shareBonus,
    shareBonusExpiry: u.shareBonusExpiry, createdAt: u.createdAt
  });
});

// ─────────────────────────────────────────────────────────────
// SDK TOKEN EXCHANGE
//
// The SDK's TokenManager (sdk/auth.js) calls these endpoints to
// get/refresh JWTs automatically. Developers only supply apiKey
// once — the SDK handles everything else invisibly.
//
//   POST /api/auth/validate-key
//     Header:   x-api-key: rp_<hex>
//     Response: { accessToken, expiresIn, tokenType }
//     Used by:  TokenManager._fetchViaApiKey()
//
//   POST /api/auth/refresh-token
//     Body:     { refreshToken: "<jwt>" }
//     Response: { accessToken, refreshToken, expiresIn, tokenType }
//     Used by:  TokenManager._refreshViaRefreshToken()
//     Note:     Falls back to validate-key if this fails.
//
// Security:
//   - Only SHA-256(plaintext) is stored — raw key never touches DB.
//   - prevApiKey accepts old hashes for 24h after rotation (grace period).
//   - Ban check on every exchange — revoked accounts can't get tokens.
// ─────────────────────────────────────────────────────────────

// ── POST /api/auth/validate-key ───────────────────────
router.post('/validate-key', async (req, res) => {
  try {
    const rawKey = (req.headers['x-api-key'] || '').trim();

    if (!rawKey || !rawKey.startsWith('rp_')) {
      return res.status(401).json({
        error:   'invalid_api_key',
        message: 'Provide your API key in the x-api-key header. Keys begin with rp_.'
      });
    }

    const hashed = crypto.createHash('sha256').update(rawKey).digest('hex');
    const { UserModel } = getDB();
    let user = null;

    if (UserModel) {
      user = await UserModel.findOne({
        $or: [
          { apiKey: hashed },
          { prevApiKey: hashed, prevApiKeyExpiry: { $gt: new Date() } },
        ],
      }).lean();

      // Audit trail — stamp last JWT issuance time
      if (user) {
        UserModel.updateOne(
          { _id: user._id },
          { $set: { jwtIssuedAt: new Date() } }
        ).catch(() => {});
      }
    }

    // In-memory fallback (dev / no-DB mode)
    if (!user) {
      try {
        user = (memStore.users || []).find(u =>
          u.apiKey === hashed ||
          (u.prevApiKey === hashed && u.prevApiKeyExpiry && new Date(u.prevApiKeyExpiry) > new Date())
        ) || null;
      } catch (_) {}
    }

    if (!user) {
      logAction({ actor: 'unknown', action: 'validate_key_failed', success: false });
      return res.status(401).json({
        error:   'invalid_api_key',
        message: 'API key not found or revoked. Visit https://raiplus.in/dashboard to manage keys.'
      });
    }

    if (user.isBanned) {
      return res.status(403).json({ error: 'account_banned', message: 'Account suspended.' });
    }

    const payload = {
      id:      String(user._id),
      email:   user.email,
      role:    user.role    || 'user',
      isAdmin: user.isAdmin || false,
    };

    const accessToken = signToken(payload);
    logAction({ actor: String(user._id), action: 'validate_key_success', success: true });

    return res.json({
      accessToken,
      expiresIn: 3600,   // 1 hour — matches JWT_EXPIRES in middleware/auth.js
      tokenType: 'Bearer',
    });
  } catch (e) {
    console.error('[validate-key]', e);
    return res.status(500).json({ error: 'Token exchange failed' });
  }
});

// ── POST /api/auth/refresh-token ──────────────────────
router.post('/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken || typeof refreshToken !== 'string') {
      return res.status(400).json({ error: 'refresh_token_required' });
    }

    const jwt    = require('jsonwebtoken');
    const secret = process.env.JWT_SECRET || 'raiplus_secret';
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, secret);
    } catch (err) {
      return res.status(401).json({
        error:   'refresh_token_invalid',
        message: err.name === 'TokenExpiredError'
          ? 'Refresh token expired. Re-authenticate using your API key.'
          : 'Invalid refresh token.'
      });
    }

    const { UserModel } = getDB();
    let user = null;

    if (UserModel) {
      user = await UserModel.findById(decoded.id || decoded._id).lean();
    } else {
      user = (memStore.users || []).find(
        u => String(u._id) === String(decoded.id || decoded._id)
      ) || null;
    }

    if (!user)        return res.status(401).json({ error: 'user_not_found' });
    if (user.isBanned) return res.status(403).json({ error: 'account_banned' });

    const payload = {
      id:      String(user.id),
      email:   user.email,
      role:    user.role    || 'user',
      isAdmin: user.isAdmin || false,
    };

    const newAccessToken  = signToken(payload);
    const newRefreshToken = jwt.sign(payload, secret, { expiresIn: '7d' });

    logAction({ actor: String(user._id), action: 'token_refreshed', success: true });

    return res.json({
      accessToken:  newAccessToken,
      refreshToken: newRefreshToken,  // rotated on every use
      expiresIn:    3600,
      tokenType:    'Bearer',
    });
  } catch (e) {
    console.error('[refresh-token]', e);
    return res.status(500).json({ error: 'Token refresh failed' });
  }
});

// ─────────────────────────────────────────────────────────────
// API KEY MANAGEMENT
//
// GET  /api/auth/apikey          → show masked preview or generate first key
// POST /api/auth/apikey/rotate   → rotate key, old key valid 24h (grace period)
//
// Storage: SHA-256(plaintext) only — plaintext shown ONCE and never stored.
// The "regenerate on every page load" bug was caused by apiKey missing from
// the Mongoose schema. Add the fields from models/userSchema.patch.js.
// ─────────────────────────────────────────────────────────────

// ── GET /api/auth/apikey ──────────────────────────────
router.get('/apikey', requireAuth, async (req, res) => {
  try {
    const uid = req.user._id || req.user.id;
    const { UserModel } = getDB();

    // Always re-fetch — JWT payload was signed at login and never carries apiKey state
    let user = null;
    if (UserModel) {
      user = await UserModel.findById(uid).select('apiKey').lean();
    } else {
      user = memStore.users?.find(u => String(u._id) === String(uid)) || null;
    }
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Key already exists → return masked preview, never the hash or plaintext
    if (user.apiKey) {
      return res.json({
        hasKey:  true,
        preview: 'rp_' + user.apiKey.slice(0, 8) + '••••••••••••••••••••••••',
        message: 'Key exists. Use rotate to generate a new one.'
      });
    }

    // No key yet → generate plaintext, store hash, return plaintext ONCE
    const plaintext = 'rp_' + crypto.randomBytes(24).toString('hex');
    const hashed    = crypto.createHash('sha256').update(plaintext).digest('hex');

    if (UserModel) {
      const result = await UserModel.findByIdAndUpdate(
        uid,
        { $set: { apiKey: hashed } },
        { new: true, select: 'apiKey' }
      );
      if (!result || !result.apiKey) {
        console.error('[apikey/get] DB write failed for user', uid);
        return res.status(500).json({ error: 'Key generation failed — check your User schema has apiKey field' });
      }
    } else {
      const u = memStore.users?.find(u => String(u._id) === String(uid));
      if (u) u.apiKey = hashed;
    }

    logAction({ actor: String(uid), action: 'apikey_created', success: true });

    return res.json({
      hasKey:   true,
      plaintext,                 // shown ONCE — not stored, cannot be recovered
      preview:  'rp_' + hashed.slice(0, 8) + '••••••••••••••••••••••••',
      message:  'API key created. Copy it now — it will not be shown again.',
      showOnce: true
    });
  } catch(e) {
    console.error('[apikey/get]', e);
    return res.status(500).json({ error: 'Failed to fetch API key' });
  }
});

// ── POST /api/auth/apikey/rotate ──────────────────────
router.post('/apikey/rotate', requireAuth, async (req, res) => {
  try {
    const uid = req.user._id || req.user.id;
    const { UserModel } = getDB();

    const plaintext = 'rp_' + crypto.randomBytes(24).toString('hex');
    const hashed    = crypto.createHash('sha256').update(plaintext).digest('hex');

    if (UserModel) {
      const current = await UserModel.findById(uid).select('apiKey').lean();
    const updated = await UserModel.findByIdAndUpdate(uid, {
  $set: {
    apiKey:           hashed,
    prevApiKey:       current?.apiKey || null,
    prevApiKeyExpiry: new Date(Date.now() + 24 * 60 * 60 * 1000),
  }
}, { new: true, select: 'apiKey' });

if (!updated || !updated.apiKey) {
  console.error('[apikey/rotate] DB write failed for user', uid);
  return res.status(500).json({ error: 'Key rotation failed — check your User schema has apiKey, prevApiKey, prevApiKeyExpiry fields' });
}
    } else {
      const u = memStore.users?.find(u => String(u._id) === String(uid));
      if (u) {
        u.prevApiKey       = u.apiKey || null;
        u.prevApiKeyExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
        u.apiKey           = hashed;
      }
    }

    logAction({ actor: String(uid), action: 'apikey_rotated', success: true });

    return res.json({
      hasKey:   true,
      plaintext,
      preview:  'rp_' + hashed.slice(0, 8) + '••••••••••••••••••••••••',
      message:  'New API key generated. Old key valid for 24h. Copy the new key now.',
      showOnce: true
    });
  } catch(e) {
    console.error('[apikey/rotate]', e);
    return res.status(500).json({ error: 'Failed to rotate API key' });
  }
});

module.exports = router;