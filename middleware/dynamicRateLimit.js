/**
 * dynamicRateLimit.js — Mode-Aware Rate Limiter for Raiplus Engine
 *
 * Three conditions, resolved in order:
 *
 *   A. Guest / Unauthenticated
 *      → Key: IP address
 *      → Limit: 20 req / 1 min
 *
 *   B. Authenticated + mode: "full"  (Node-1/Node-2 compute — expensive)
 *      → Key: User ID
 *      → Limit: 30 req / 1 min
 *
 *   C. Authenticated + mode: "detect_only"  (Node-3 only — cheap + fast)
 *      → Key: User ID
 *      → Limit: 300 req / 1 min
 *
 * Design notes
 * ─────────────
 * • We cannot use a single express-rate-limit instance because the limit,
 *   key, and window all vary per request.  We maintain THREE separate
 *   instances keyed by their store key prefix, and select the right one
 *   inside a single middleware function.
 *
 * • express-rate-limit's default MemoryStore is per-instance, so the three
 *   stores are fully isolated from each other — no cross-contamination.
 *
 * • `req.body.mode` is read here.  Express's json() middleware must run
 *   before this middleware.  The existing app.use(express.json()) in
 *   index.js already satisfies this.
 *
 * • `req.user` is populated by optionalAuth.  That middleware MUST be
 *   declared before dynamicRateLimit in the route chain.
 *
 * • On a 429, we attach the correct tier label to the response so the
 *   client can render helpful UI ("upgrade to alpha", "reduce burst", etc.)
 *
 * • All three limiters expose standard X-RateLimit-* headers so the SDK
 *   and docs stay accurate without any extra work.
 */

"use strict";

const rateLimit = require("express-rate-limit");

// ─────────────────────────────────────────────────────────────
// Helper — resolve the real client IP, respecting proxies.
// Mirrors the logic in your existing ratelimit middleware so
// hashes in logs stay consistent.
// ─────────────────────────────────────────────────────────────
function resolveIp(req) {
  return (
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

// ─────────────────────────────────────────────────────────────
// Shared 429 handler — injects tier label into error body
// ─────────────────────────────────────────────────────────────
function make429Handler(tier) {
  return (req, res /*, next, options */) => {
    res.status(429).json({
      success:     false,
      error:       "rate_limit_exceeded",
      tier,
      retry_after: Math.ceil((res.getHeader("X-RateLimit-Reset") - Date.now()) / 1000) || 60,
      message:     tier === "guest"
        ? "Guest limit reached (20/min). Register for higher limits."
        : tier === "full"
          ? "Authenticated full-mode limit reached (30/min). Switch to detect_only for bulk work."
          : "Bulk scan limit reached (300/min). Contact support for enterprise quotas.",
    });
  };
}

// ─────────────────────────────────────────────────────────────
// CONDITION A — Guest / Unauthenticated
//   Key  : IP address
//   Limit: 20 / min
// ─────────────────────────────────────────────────────────────
const guestLimiter = rateLimit({
  windowMs:          60 * 1000,   // 1 minute
  max:               20,
  standardHeaders:   true,
  legacyHeaders:     false,
  keyGenerator:      (req) => `guest:${resolveIp(req)}`,
  handler:           make429Handler("guest"),
  skip:              (req) => !!req.user,   // skip for authenticated users
});

// ─────────────────────────────────────────────────────────────
// CONDITION B — Authenticated + mode: "full"
//   Key  : User ID
//   Limit: 30 / min
// ─────────────────────────────────────────────────────────────
const authFullLimiter = rateLimit({
  windowMs:          60 * 1000,
  max:               30,
  standardHeaders:   true,
  legacyHeaders:     false,
  keyGenerator:      (req) => {
    const uid = String(req.user?._id || req.user?.id || resolveIp(req));
    return `auth_full:${uid}`;
  },
  handler:           make429Handler("full"),
  // Only active for authenticated users in full mode
  skip: (req) => {
    if (!req.user) return true;                           // guest path handles it
    const mode = (req.body?.mode || "full").trim().toLowerCase();
    return mode !== "full";                               // detect_only handled separately
  },
});

// ─────────────────────────────────────────────────────────────
// CONDITION C — Authenticated + mode: "detect_only"
//   Key  : User ID
//   Limit: 300 / min
// ─────────────────────────────────────────────────────────────
const authDetectLimiter = rateLimit({
  windowMs:          60 * 1000,
  max:               300,
  standardHeaders:   true,
  legacyHeaders:     false,
  keyGenerator:      (req) => {
    const uid = String(req.user?._id || req.user?.id || resolveIp(req));
    return `auth_detect:${uid}`;
  },
  handler:           make429Handler("detect_only"),
  skip: (req) => {
    if (!req.user) return true;
    const mode = (req.body?.mode || "full").trim().toLowerCase();
    return mode !== "detect_only";
  },
});

// ─────────────────────────────────────────────────────────────
// COMPOSED MIDDLEWARE
// Runs all three limiters in sequence.  Each limiter's `skip`
// function guarantees only one will actually count the request.
//
// Execution order:
//   1. guestLimiter    — counts if unauthenticated, skips otherwise
//   2. authFullLimiter — counts if authenticated + mode=full, skips otherwise
//   3. authDetectLimiter — counts if authenticated + mode=detect_only, skips otherwise
//
// If any limiter fires a 429, the chain stops (res.json was called).
// ─────────────────────────────────────────────────────────────
function dynamicRateLimit(req, res, next) {
  if (req.user) {
    const mode = (req.body?.mode || "full").trim().toLowerCase();
    res.setHeader("X-RateLimit-Tier", mode === "detect_only" ? "alpha_detect" : "alpha");
  } else {
    res.setHeader("X-RateLimit-Tier", "guest");
  }

  guestLimiter(req, res, (err) => {
    if (err || res.headersSent) return next(err);
    authFullLimiter(req, res, (err2) => {
      if (err2 || res.headersSent) return next(err2);
      authDetectLimiter(req, res, next);
    });
  });
}

// ─────────────────────────────────────────────────────────────
// Expose the individual limiters for unit testing + the composed
// middleware for use in the route.
// ─────────────────────────────────────────────────────────────
module.exports = {
  dynamicRateLimit,
  // Exposed for tests / admin inspection
  _limiters: { guestLimiter, authFullLimiter, authDetectLimiter, dynamicRateLimit},
};