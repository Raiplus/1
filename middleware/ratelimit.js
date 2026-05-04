const { memStore } = require('../models');
const store = new Map();


function getIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket.remoteAddress
    || 'unknown';
}

function rateLimit(req, res, next) {
  const ip = getIp(req);
  req.clientIp = ip;

  // ── Logged-in alpha user: daily quota ─────────────────
  if (req.user) {
    const uid          = String(req.user._id || req.user.id);
    const u          = memStore.users?.find(u => u._id === uid) || req.user;
    const effectiveQ = memStore.getEffectiveQuota ? memStore.getEffectiveQuota(u) : (u.dailyQuota || 50);
    const dailyCount   = memStore.getDailyCount(uid);
    const remaining    = Math.max(0, effectiveQ - dailyCount);
    const resetTs      = Math.floor(new Date().setHours(24,0,0,0) / 1000);

    res.setHeader('X-RateLimit-Remaining', String(remaining));
    res.setHeader('X-RateLimit-Reset', String(resetTs));
    res.setHeader('X-RateLimit-Tier', u.role || 'alpha');

    if (dailyCount >= effectiveQ) {
      return res.status(429).json({
        error:       'rate_limit_exceeded',
        retry_after: resetTs - Math.floor(Date.now() / 1000),
        message:     'Daily quota khatam. Resets at midnight. Share your link for +100 bonus!'
      });
    }
    req.rateRemaining = remaining;
    return next();
  }

  // ── Guest: 20 req/min per IP ───────────────────────────
  // Raised from 5 → 20 to handle NAT/shared IPs (offices, colleges, hostels)
  const GUEST_LIMIT = 20;
  const key   = 'rl:' + ip + ':' + Math.floor(Date.now() / 60000);
  const count = store.get(key) || 0;

  if (count >= GUEST_LIMIT) {
    const resetTs    = (Math.floor(Date.now() / 60000) + 1) * 60;
    const retryAfter = resetTs - Math.floor(Date.now() / 1000);
    res.setHeader('X-RateLimit-Remaining', '0');
    res.setHeader('X-RateLimit-Reset',     String(resetTs));
    res.setHeader('X-RateLimit-Tier',      'guest');
    return res.status(429).json({
      error:       'rate_limit_exceeded',
      retry_after: retryAfter,
      // Nudge guest to sign up instead of just blocking
      message:     `Shared IP limit reached (${GUEST_LIMIT}/min). Sign up free for 50 requests/day — no sharing limit.`,
      signup_url:  '/login'
    });
  }

  store.set(key, count + 1);
  setTimeout(() => store.delete(key), 61000);

  const remaining = Math.max(0, GUEST_LIMIT - 1 - count);
  const resetTs   = (Math.floor(Date.now() / 60000) + 1) * 60;
  res.setHeader('X-RateLimit-Remaining', String(remaining));
  res.setHeader('X-RateLimit-Reset',     String(resetTs));
  res.setHeader('X-RateLimit-Tier',      'guest');
  req.rateRemaining = remaining;
  next();
}

module.exports = { rateLimit, getIp,};
