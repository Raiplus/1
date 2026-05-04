"use strict";

/**
 * middleware/auth.js
 *
 * Auth resolution order (stops at first match):
 *   1. httpOnly cookie "token"       — browser clients
 *   2. Authorization: Bearer <jwt>   — SDK clients (no DB call)
 *   3. X-API-Key: <plaintext>        — SDK clients (DB lookup)
 *
 * JWT AUTO-REFRESH:
 *   - JWT expires in 1h
 *   - When an API-key auth succeeds, a fresh JWT is issued in X-Auth-Token
 *   - When a Bearer JWT is >23h old (iat), a refreshed JWT is issued in X-Auth-Token
 *     so SDK clients can cache the new token and avoid DB calls for another 24h
 *
 * req.user is ALWAYS the single source of truth. Never use req.userId / req.auth.
 */

const jwt    = require("jsonwebtoken");
const crypto = require("crypto");

const JWT_SECRET    = process.env.JWT_SECRET  || "raiplus_secret";
const JWT_EXPIRES   = process.env.JWT_EXPIRES || "1h";
const COOKIE_NAME   = "token";
const REFRESH_AFTER = 23 * 60 * 60 * 1000; // reissue JWT after 23h (before 24h expiry)

// ─────────────────────────────────────────────────────────────
// Token signing — always stamps iat so refresh logic can check age
// ─────────────────────────────────────────────────────────────
function signToken(payload) {
  // Strip old iat/exp so jwt.sign stamps fresh ones
  const { iat, exp, ...clean } = payload;
  return jwt.sign(clean, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}
// ─────────────────────────────────────────────────────────────
// Cookie helpers
// ─────────────────────────────────────────────────────────────
function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge:   60 * 60 * 1000, // 1 hour
  });
}


function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME);
}

// ─────────────────────────────────────────────────────────────
// Internal: safely verify a JWT — never throws
// ─────────────────────────────────────────────────────────────
function _verifyJwt(raw) {
  try {
    return { decoded: jwt.verify(raw, JWT_SECRET), expired: false };
  } catch (err) {
    return { decoded: null, expired: err.name === "TokenExpiredError" };
  }
}

// ─────────────────────────────────────────────────────────────
// Internal: verify X-API-Key against DB / memStore
// Compares SHA-256 hashes — plaintext is NEVER stored.
// Also accepts prevApiKey during the 24-hour rotation grace period.
// ─────────────────────────────────────────────────────────────
async function _verifyApiKey(rawKey) {
  if (!rawKey || typeof rawKey !== "string") return null;

  const hashed = crypto.createHash("sha256").update(rawKey).digest("hex");

  if (global.dbConnected) {
    try {
      const { getModels } = require("../config/db");
      const { UserModel } = getModels();
      if (UserModel) {
        return await UserModel.findOne({
          $or: [
            { apiKey: hashed },
            { prevApiKey: hashed, prevApiKeyExpiry: { $gt: new Date() } },
          ],
        }).lean() || null;
      }
    } catch (err) {
      console.error("[auth/_verifyApiKey] DB error:", err.message);
    }
  }

  // In-memory fallback (dev / no-DB mode)
  try {
    const { memStore } = require("../models");
    if (memStore && Array.isArray(memStore.users)) {
      return memStore.users.find(
        (u) =>
          u.apiKey === hashed ||
          (u.prevApiKey === hashed &&
            u.prevApiKeyExpiry &&
            new Date(u.prevApiKeyExpiry) > new Date())
      ) || null;
    }
  } catch (_) {}

  return null;
}

// ─────────────────────────────────────────────────────────────
// Internal: check if JWT needs a refresh (> 23h since issued)
// Returns a fresh token string if refresh needed, else null.
// ─────────────────────────────────────────────────────────────
function _maybeRefreshJwt(decoded) {
  if (!decoded || !decoded.iat) return null;
  const age = Date.now() - decoded.iat * 1000;
  if (age < REFRESH_AFTER) return null;
  // Issue a fresh token with the same payload
  return signToken(decoded);
}

// ─────────────────────────────────────────────────────────────
// optionalAuth
//
// Populates req.user if valid credentials exist; leaves null (guest)
// otherwise. Never sends 401 — that is requireAuth's job.
// ─────────────────────────────────────────────────────────────
async function optionalAuth(req, res, next) {
  try {
    // ── 1. httpOnly cookie (browser) ────────────────────
    const cookieToken = req.cookies && req.cookies[COOKIE_NAME];
    if (cookieToken) {
      const { decoded } = _verifyJwt(cookieToken);
      if (decoded) {
        req.user       = decoded;
        req.authMethod = "cookie";
        // Silently refresh cookie if token is getting old
        const refreshed = _maybeRefreshJwt(decoded);
        if (refreshed) setAuthCookie(res, refreshed);
        return next();
      }
    }

    // ── 2. Authorization: Bearer <token> (SDK) ──────────
const authHeader = req.headers["authorization"] || "";
if (authHeader.startsWith("Bearer ")) {
  const raw = authHeader.slice(7).trim();
  if (raw) {
    const { decoded, expired } = _verifyJwt(raw);
    
        if (decoded) {
          req.user       = decoded;
          req.authMethod = "bearer";
          // If token is >23h old, issue a fresh one in X-Auth-Token
          // SDK client should cache this and use it for the next 24h
          const refreshed = _maybeRefreshJwt(decoded);
          if (refreshed) res.set("X-Auth-Token", refreshed);
          return next();
        }
        if (expired) req.tokenExpired = true;
      }
    }

    // ── 3. X-API-Key header (DB lookup) ─────────────────
    const rawApiKey = req.headers["x-api-key"] || "";
    if (rawApiKey) {
      const user = await _verifyApiKey(rawApiKey);
      if (user) {
        const payload = {
          id:      String(user._id),
          email:   user.email,
          role:    user.role    || "user",
          isAdmin: user.isAdmin || false,
        };
        req.user       = payload;
        req.authMethod = "api_key";

        // Always issue a fresh JWT on API-key auth — client caches this
        // for up to 24h before needing to use the API key again
        const freshToken = signToken(payload);
        res.set("X-Auth-Token", freshToken);

        // Update jwtIssuedAt in DB so we have an audit trail
        if (global.dbConnected) {
          try {
            const { getModels } = require("../config/db");
            const { UserModel } = getModels();
            if (UserModel) {
              UserModel.updateOne(
                { _id: user._id },
                { jwtIssuedAt: new Date() }
              ).catch(() => {});
            }
          } catch (_) {}
        }

        return next();
      }
    }
    

    // ── 4. No credentials → guest ────────────────────────
    req.user       = null;
    req.authMethod = "none";
    return next();

  } catch (err) {
    console.error("[optionalAuth] Unexpected error:", err.message);
    req.user       = null;
    req.authMethod = "none";
    return next();
  }
}

// ─────────────────────────────────────────────────────────────
// requireAuth — must run AFTER optionalAuth. Returns 401 if no user.
// ─────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      error:   "unauthorized",
      message: req.tokenExpired
        ? "Token expired. POST /api/auth/validate-key with your x-api-key header to get a fresh JWT."
        : "Authentication required.",
    });
  }
  return next();
}

// ─────────────────────────────────────────────────────────────
// requireAdmin
// ─────────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (!req.user)         return res.status(401).json({ error: "unauthorized" });
  if (!req.user.isAdmin) return res.status(403).json({ error: "forbidden", message: "Admin only." });
  return next();
}

module.exports = {
  signToken,
  setAuthCookie,
  clearAuthCookie,
  optionalAuth,
  requireAuth,
  requireAdmin,
  verifyApiKey: _verifyApiKey,
};