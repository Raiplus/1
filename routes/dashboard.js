const mongoose = require('mongoose');

// Safe ObjectId conversion — works with both old and new mongoose
function toObjectId(id) {
  try {
    return mongoose.Types.ObjectId.createFromHexString
      ? mongoose.Types.ObjectId.createFromHexString(String(id))
      : new mongoose.Types.ObjectId(String(id));
  } catch(e) {
    return id; // fallback — let mongoose handle it
  }
}

const express = require('express');
const router  = express.Router();
const { requireAuth } = require('../middleware/auth');
const { memStore }    = require('../models');

function db() {
  if (global.dbConnected) {
    const { getModels } = require('../config/db');
    return getModels();
  }
  return {};
}

// ── GET /api/dashboard/stats ───────────────────────────
router.get('/stats', requireAuth, async (req, res) => {
  try {
    const uid = String(req.user._id || req.user.id);
    const { RequestModel, UserModel } = db();

    let total = 0, toxic = 0, clean = 0, avgLatency = 0, dailyUsed = 0;

    if (RequestModel) {
      const today = new Date(); today.setHours(0,0,0,0);

      // FIX: Query both as ObjectId AND as string to catch documents written
      // either way (in case of mixed legacy data). Use $or for robustness.
      const userIdObj = toObjectId(uid);
      const [allStats, todayCount] = await Promise.all([
        RequestModel.aggregate([
          { $match: { $or: [{ userId: userIdObj }, { userId: uid }] } },
          { $group: {
            _id:   null,
            total: { $sum: 1 },
            toxic: { $sum: { $cond: ['$isToxic', 1, 0] } },
            avgLat: { $avg: '$latencyMs' }
          }}
        ]).catch(() => []),
        RequestModel.countDocuments({
          $or: [{ userId: userIdObj }, { userId: uid }],
          createdAt: { $gte: today }
        })
      ]);

      if (allStats && allStats[0]) {
        total      = allStats[0].total   || 0;
        toxic      = allStats[0].toxic   || 0;
        clean      = total - toxic;
        avgLatency = Math.round(allStats[0].avgLat || 0);
      }
      dailyUsed = todayCount;

      if (UserModel) {
        await UserModel.updateOne({ _id: uid }, { totalRequests: total }).catch(() => {});
      }
    } else {
      const s = await memStore.getStats(uid);
      total      = s.total;
      toxic      = s.toxic;
      clean      = s.clean;
      avgLatency = s.avgLatency;
      dailyUsed  = memStore.getDailyCount(uid);
    }

    // Get effective quota
    const userObj = (UserModel ? await UserModel.findById(uid).lean().catch(() => null) : null) || req.user;
    const effectiveQuota = userObj
      ? (userObj.dailyQuota || 50) +
        (userObj.shareBonus && userObj.shareBonusExpiry && new Date() < new Date(userObj.shareBonusExpiry)
          ? (userObj.shareBonusQuota || 100) : 0)
      : 50;
    const bonusActive = userObj && userObj.shareBonus && userObj.shareBonusExpiry && new Date() < new Date(userObj.shareBonusExpiry);

    res.json({
      total, toxic, clean, avgLatency,
      dailyUsed, dailyQuota: effectiveQuota,
      baseQuota:   userObj ? (userObj.dailyQuota || 50) : 50,
      bonusActive: !!bonusActive,
      bonusExpiry: bonusActive ? userObj.shareBonusExpiry : null,
      bonusQuota:  bonusActive ? (userObj.shareBonusQuota || 100) : 0,
    });
  } catch(e) { console.error('[dashboard/stats]', e); res.status(500).json({ error: 'stats_error' }); }
});

// ── GET /api/dashboard/history ─────────────────────────
router.get('/history', requireAuth, async (req, res) => {
  try {
    const uid   = String(req.user._id || req.user.id);
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const { RequestModel } = db();
    let history;

    if (RequestModel) {
      const userIdObj = toObjectId(uid);
      // FIX: Query both ObjectId and string userId to catch all documents
      history = await RequestModel.find({
        $or: [{ userId: userIdObj }, { userId: uid }]
      })
        .sort({ createdAt: -1 })
        .limit(limit)
        .lean();
    } else {
      history = await memStore.getUserRequests(uid, limit);
    }

    // FIX: Ensure all fields the frontend needs are present, with safe defaults.
    // The frontend reads r.mode, r.originalText, r.cleanText, r.isToxic, etc.
    const sanitized = (history || []).map(r => ({
      ...r,
      // mode is set to actionTaken in buildLogData — map known values to
      // display-friendly labels for the mode badge coloring
      mode:         r.mode || r.actionTaken || 'clean',
      originalText: r.originalText || '',
      cleanText:    r.cleanText    || null,
      isToxic:      !!r.isToxic,
      confidence:   r.confidence   ?? 0,
    }));

    res.json({ history: sanitized });
  } catch(e) { console.error('[dashboard/history]', e); res.status(500).json({ error: 'history_error' }); }
});

// ── GET /api/dashboard/feed (public, anonymized) ───────
router.get('/feed', async (req, res) => {
  try {
    const { RequestModel } = db();
    let all;

    if (RequestModel) {
      all = await RequestModel.find().sort({ createdAt: -1 }).limit(30).lean();
    } else {
      all = await memStore.getAllRequests(20);
    }

    const safe = (all || []).map(r => {
      // BUG FIX: read both camelCase (new) and snake_case (legacy) field names
      // because moderate.js stores both but older documents may only have one.
      const origText  = r.originalText  || r.original_text  || '';
      const cleanTxt  = r.cleanText     || r.clean_text     || origText;
      const latMs     = r.latencyMs     ?? r.latency_ms     ?? null;
      const isToxic   = !!(r.isToxic    || r.is_toxic);
      const actionRaw = r.actionTaken   || r.action_taken   || r.mode || 'clean';

      return {
        id:             r._id,
        // BUG FIX: truncate AFTER resolving the dual-key field
        originalText:   origText.length > 60 ? origText.slice(0, 60) + '…' : origText,
        cleanText:      cleanTxt.length > 80 ? cleanTxt.slice(0, 80) + '…' : cleanTxt,
        isToxic,
        confidence:     r.confidence   ?? 0,
        // FIX: normalise actionTaken — never expose raw provider strings
        actionTaken:    stealthMaskAction(actionRaw),
        // BUG FIX: use ?? not || so a genuine 0ms latency is preserved, not replaced
        latencyMs:      latMs !== null && isFinite(latMs) ? latMs : null,
        node1LatencyMs: r.node1LatencyMs ?? null,
        node2LatencyMs: r.node2LatencyMs ?? null,
        nodesHit:       r.nodesHit       || [],
        // BUG FIX: delayedBy was never written to DB before — now it is, so pass it through
        delayedBy:      r.delayedBy      || null,
        createdAt:      r.createdAt,
      };
    });

    res.json({ feed: safe });
  } catch(e) { res.status(500).json({ error: 'feed_error' }); }
});

// ─────────────────────────────────────────────────────────────
// SERVER-SIDE stealth mask — ensures nothing leaks from DB
// into API responses even if old documents exist with provider names
// ─────────────────────────────────────────────────────────────
function stealthMaskAction(str) {
  if (!str) return 'clean';
  return str
    .replace(/sanitized_via_\w+/gi, 'sanitized_by_node')
    .replace(/groq/gi,               'node-1')
    .replace(/together/gi,           'node-2')
    .replace(/hugging\s*face/gi,     'node-3')
    .replace(/roberta/gi,            'node-3');
}

module.exports = router;