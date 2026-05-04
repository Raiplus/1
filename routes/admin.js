const express  = require('express');
const router   = express.Router();
const { memStore }     = require('../models');
const { requireAdmin } = require('../middleware/auth');
const { logAction, queryLogs } = require('../services/actionLogger');

router.use(requireAdmin);

function db() {
  if (global.dbConnected) {
    const { getModels } = require('../config/db');
    return getModels();
  }
  return {};
}

// ── GET /api/admin/stats ───────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const { UserModel, RequestModel, ReportModel, ShareModel } = db();
    let stats;
    if (UserModel) {
      const today   = new Date(); today.setHours(0,0,0,0);
      const weekAgo = new Date(Date.now() - 7*24*60*60*1000);
      const [totalUsers, verifiedUsers, bannedUsers, adminUsers,
             totalRequests, requestsToday, requestsWeek, toxicDetected,
             openReports, totalReports, sharesUsed] = await Promise.all([
        UserModel.countDocuments(),
        UserModel.countDocuments({ isVerified: true }),
        UserModel.countDocuments({ isBanned: true }),
        UserModel.countDocuments({ isAdmin: true }),
        RequestModel.countDocuments(),
        RequestModel.countDocuments({ createdAt: { $gte: today } }),
        RequestModel.countDocuments({ createdAt: { $gte: weekAgo } }),
        RequestModel.countDocuments({ isToxic: true }),
        ReportModel.countDocuments({ status: 'open' }),
        ReportModel.countDocuments(),
        ShareModel.countDocuments({ usedBy: { $ne: null } }),
      ]);
      stats = { totalUsers, verifiedUsers, bannedUsers, adminUsers,
                totalRequests, requestsToday, requestsThisWeek: requestsWeek,
                toxicDetected, openReports, totalReports, shareLinksUsed: sharesUsed };
    } else {
      stats = await memStore.getAdminStats();
    }
    res.json(stats);
  } catch(e) { console.error('[admin/stats]', e); res.status(500).json({ error: 'stats_error' }); }
});

// ── GET /api/admin/users ───────────────────────────────
router.get('/users', async (req, res) => {
  try {
    const { search = '', role = '', limit = 50 } = req.query;
    const { UserModel } = db();
    let users;
    if (UserModel) {
      const q = {};
      if (role)   q.role = role;
      if (search) q.$or = [
        { email:    { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } }
      ];
      users = await UserModel.find(q)
        .select('-password -otp -otpExpiry')
        .limit(parseInt(limit))
        .sort({ createdAt: -1 })
        .lean();
    } else {
      users = await memStore.findAllUsers(parseInt(limit));
      if (search) users = users.filter(u => u.email.includes(search) || (u.username||'').includes(search));
      if (role)   users = users.filter(u => u.role === role);
    }
    res.json({
      users: users.map(u => ({
        id: u._id, email: u.email, username: u.username,
        role: u.role, isAdmin: u.isAdmin, isVerified: u.isVerified,
        isBanned: u.isBanned, banReason: u.banReason,
        dailyQuota: u.dailyQuota, totalRequests: u.totalRequests || 0,
        shareBonus: u.shareBonus, shareUsed: u.shareUsed,
        createdAt: u.createdAt, lastLogin: u.lastLogin || null
      })),
      total: users.length
    });
  } catch(e) { console.error('[admin/users]', e); res.status(500).json({ error: 'users_error' }); }
});

// ── GET /api/admin/reports ─────────────────────────────
router.get('/reports', async (req, res) => {
  try {
    const { status, category, limit = 100 } = req.query;
    const { ReportModel } = db();
    let reports;
    if (ReportModel) {
      const q = {};
      if (status)   q.status   = status;
      if (category) q.category = category;
      reports = await ReportModel.find(q).sort({ createdAt: -1 }).limit(parseInt(limit)).lean();
    } else {
      reports = await memStore.getAllReports({ status, category, limit: parseInt(limit) });
    }
    res.json({ reports, total: reports.length });
  } catch(e) { res.status(500).json({ error: 'reports_error' }); }
});

// ── PATCH /api/admin/reports/:id ──────────────────────
router.patch('/reports/:id', async (req, res) => {
  try {
    const { status, adminNote } = req.body;
    const { ReportModel } = db();
    const update = {};
    if (status)            update.status    = status;
    if (adminNote != null) update.adminNote = adminNote;
    if (status === 'resolved') update.resolvedAt = new Date();
    let report;
    if (ReportModel) {
      report = await ReportModel.findByIdAndUpdate(req.params.id, update, { new: true }).lean();
    } else {
      report = await memStore.updateReport(req.params.id, update);
    }
    if (!report) return res.status(404).json({ error: 'not_found' });
    logAction({ actor: String(req.user._id || req.user.id), action: 'update_report', target: req.params.id, meta: update });
    res.json({ message: 'Report updated', report });
  } catch(e) { res.status(500).json({ error: 'update_error' }); }
});

// ── PATCH /api/admin/users/:id/ban ────────────────────
router.patch('/users/:id/ban', async (req, res) => {
  try {
    const { reason = 'Violated terms of service' } = req.body;
    const { UserModel } = db();
    if (UserModel) await UserModel.findByIdAndUpdate(req.params.id, { isBanned: true, banReason: reason });
    else await memStore.updateUser(req.params.id, { isBanned: true, banReason: reason });
    logAction({ actor: String(req.user._id || req.user.id), action: 'ban_user', target: req.params.id, meta: { reason } });
    res.json({ message: 'User banned' });
  } catch(e) { res.status(500).json({ error: 'ban_error' }); }
});

// ── PATCH /api/admin/users/:id/unban ──────────────────
router.patch('/users/:id/unban', async (req, res) => {
  try {
    const { UserModel } = db();
    if (UserModel) await UserModel.findByIdAndUpdate(req.params.id, { isBanned: false, banReason: null });
    else await memStore.updateUser(req.params.id, { isBanned: false, banReason: null });
    logAction({ actor: String(req.user._id || req.user.id), action: 'unban_user', target: req.params.id });
    res.json({ message: 'User unbanned' });
  } catch(e) { res.status(500).json({ error: 'unban_error' }); }
});

// ── PATCH /api/admin/users/:id/quota ──────────────────
router.patch('/users/:id/quota', async (req, res) => {
  try {
    const { quota } = req.body;
    if (!quota || quota < 1) return res.status(400).json({ error: 'Invalid quota' });
    const { UserModel } = db();
    if (UserModel) await UserModel.findByIdAndUpdate(req.params.id, { dailyQuota: parseInt(quota) });
    else await memStore.updateUser(req.params.id, { dailyQuota: parseInt(quota) });
    logAction({ actor: String(req.user._id || req.user.id), action: 'adjust_quota', target: req.params.id, meta: { quota } });
    res.json({ message: 'Quota updated', quota });
  } catch(e) { res.status(500).json({ error: 'quota_error' }); }
});

// ── PATCH /api/admin/users/:id/role ───────────────────
router.patch('/users/:id/role', async (req, res) => {
  try {
    const { role, isAdmin } = req.body;
    const update = {};
    if (role)            update.role    = role;
    if (isAdmin != null) update.isAdmin = isAdmin;
    const { UserModel } = db();
    if (UserModel) await UserModel.findByIdAndUpdate(req.params.id, update);
    else await memStore.updateUser(req.params.id, update);
    logAction({ actor: String(req.user._id || req.user.id), action: 'change_role', target: req.params.id, meta: update });
    res.json({ message: 'Role updated' });
  } catch(e) { res.status(500).json({ error: 'role_error' }); }
});

// ── GET /api/admin/requests — FULL input/output for all users ──
router.get('/requests', async (req, res) => {
  try {
    const { limit = 50, userId, isToxic, actionTaken } = req.query;
    const { RequestModel, UserModel } = db();
    let requests;

    if (RequestModel) {
      const q = {};
      if (userId)      q.userId     = userId;
      if (isToxic !== undefined) q.isToxic = isToxic === 'true';
      if (actionTaken) q.actionTaken = actionTaken;

      // Join with user email for display
      requests = await RequestModel.find(q)
        .sort({ createdAt: -1 })
        .limit(parseInt(limit))
        .lean();

      // Attach user emails
      if (UserModel && requests.length) {
        const userIds = [...new Set(requests.filter(r => r.userId).map(r => String(r.userId)))];
        const users   = await UserModel.find({ _id: { $in: userIds } }).select('email username').lean();
        const uMap    = {};
        users.forEach(u => { uMap[String(u._id)] = { email: u.email, username: u.username }; });
        requests = requests.map(r => ({
          ...r,
          userEmail:    r.userId ? (uMap[String(r.userId)]?.email    || 'guest') : 'guest',
          userUsername: r.userId ? (uMap[String(r.userId)]?.username || '—')     : '—',
        }));
      }
    } else {
      requests = await memStore.getAllRequests(parseInt(limit));
      if (isToxic !== undefined) requests = requests.filter(r => r.isToxic === (isToxic === 'true'));
    }

    res.json({ requests, total: requests.length });
  } catch(e) { console.error('[admin/requests]', e); res.status(500).json({ error: 'requests_error' }); }
});

// ── GET /api/admin/requests/:id — single request detail ──
router.get('/requests/:id', async (req, res) => {
  try {
    const { RequestModel, UserModel } = db();
    let request;
    if (RequestModel) {
      request = await RequestModel.findById(req.params.id).lean();
      if (request && request.userId && UserModel) {
        const user = await UserModel.findById(request.userId).select('email username').lean();
        if (user) { request.userEmail = user.email; request.userUsername = user.username; }
      }
    } else {
      request = memStore.requests.find(r => r._id === req.params.id);
    }
    if (!request) return res.status(404).json({ error: 'not_found' });
    res.json(request);
  } catch(e) { res.status(500).json({ error: 'request_detail_error' }); }
});

// ── GET /api/admin/logs ────────────────────────────────
router.get('/logs', async (req, res) => {
  try {
    const { action, actor, limit = 100 } = req.query;
    const logs = await queryLogs({ action, actor }, parseInt(limit));
    res.json({ logs, total: logs.length, source: global.dbConnected ? 'mongodb' : 'unavailable' });
  } catch(e) { res.status(500).json({ error: 'logs_error' }); }
});

// ── GET /api/admin/http-logs ───────────────────────────
router.get('/http-logs', async (req, res) => {
  try {
    const { getHttpLogs, getLogStats } = require('../services/morganLogger');
    const limit      = Math.min(parseInt(req.query.limit) || 100, 500);
    const onlyErrors = req.query.errors === 'true';
    const logs       = getHttpLogs(limit, onlyErrors);
    const stats      = getLogStats();
    res.json({ logs, stats, total: logs.length, source: 'logfile' });
  } catch(e) { res.status(500).json({ error: 'http_logs_error' }); }
});

//system health
router.get("/system-health", requireAdmin, async (req, res) => {
  const t0 = Date.now();
  const { RequestModel } = global.dbConnected ? require("../config/db").getModels() : {};

  // ── Last 100 requests from memStore or DB ──────────────────
  let recentRequests = [];
  try {
    if (global.dbConnected && RequestModel) {
      recentRequests = await RequestModel.find({})
        .sort({ createdAt: -1 })
        .limit(100)
        .lean();
    } else {
      recentRequests = (memStore.requests || []).slice(-100).reverse();
    }
  } catch (_) {}

  const total = recentRequests.length;

  // ── Per-layer counters ─────────────────────────────────────
  const counts = {
    front_door:     0,
    layer1_groq:    0,
    layer2_together:0,
    layer3_hf:      0,
    cb_bypass:      0,
    clean:          0,
  };
  let totalLatency = 0;
  let toxicCount   = 0;

for (const r of recentRequests) {
    if (r.isToxic) toxicCount++;
    totalLatency += r.latencyMs || 0;
    
    const action = r.actionTaken || r.mode || "";
    
    // 1. Check Circuit Breaker Bypass First
    if (action === "fallback_detection_only" || action === "circuit_breaker_active") {
      counts.cb_bypass++;
    } 
    // 2. Check Front Door
    else if (action === "front_door_blocked") {
      counts.front_door++;
    } 
    // 3. Check Hugging Face (Layer 3)
    else if (action === "hf_detected_only" || action === "hf_polite_template") {
      counts.layer3_hf++;
    } 
    // 4. Check LLMs (Layer 1 & 2)
    else if (action === "sanitized_via_llama" || action === "clean") {
       if (r.isToxic) {
           // We only count LLMs if they processed a toxic comment
           // Checking the new engineSource if you saved it, otherwise fallback to delayedBy heuristic
           const source = r.engineSource || r.source || "";
           if (source === "together" || r.delayedBy === "groq") {
               counts.layer2_together++;
           } else {
               counts.layer1_groq++;
           }
       } else {
           counts.clean++;
       }
    } 
    else {
      counts.clean++; // Safety catch-all
    }
  }
  // ── Probe each layer (non-blocking, 3s timeout) ────────────
const probeLayer = async (url, headers, body, reqMethod = "POST") => { // 👈 Method parameter add kiya
    const t = Date.now();
    try {
      const fetchOpts = {
        method:  reqMethod,
        headers: { "Content-Type": "application/json", ...headers },
      };
      if (reqMethod === "POST") fetchOpts.body = JSON.stringify(body);

      const res = await Promise.race([
        fetch(url, fetchOpts),
        new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 3000)),
      ]);
      return { ok: res.ok, latency: Date.now() - t, status: res.status };
    } catch (e) {
      return { ok: false, latency: Date.now() - t, error: e.message };
    }
  };

const GROQ_KEY = [
    process.env.GROQ_API_KEY_1,
    process.env.GROQ_API_KEY_2,
    process.env.GROQ_API_KEY_3,
  ].find(k => k && !k.includes("your"));

  const [groqProbe, togetherProbe, hfProbe] = await Promise.all([
    GROQ_KEY
      ? probeLayer(
          "https://api.groq.com/openai/v1/chat/completions",
          { Authorization: `Bearer ${GROQ_KEY}` },
          { model: "llama-3.1-8b-instant", max_tokens: 1, messages: [{ role: "user", content: "hi" }] }
        )
      : { ok: false, latency: 0, error: "no_key" },

    process.env.TOGETHER_API_KEY && !process.env.TOGETHER_API_KEY.includes("your")
      ? probeLayer(
          "https://api.together.xyz/v1/chat/completions",
          { Authorization: `Bearer ${process.env.TOGETHER_API_KEY}` },
          { model: "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo", max_tokens: 1, messages: [{ role: "user", content: "hi" }] }
        )
      : { ok: false, latency: 0, error: "no_key" },

    // 🔥 HF FIX: Change POST /health to GET / (Root path hamesha 200 OK deta hai)
    process.env.PYTHON_BOUNCER_URL && !process.env.PYTHON_BOUNCER_URL.includes("your-hf")
      ? probeLayer(process.env.PYTHON_BOUNCER_URL.replace(/\/+$/, "") + "/", {}, null, "GET")
      : { ok: false, latency: 0, error: "no_url" },
  ]);

  res.json({
    snapshot_latency_ms: Date.now() - t0,
    circuit_breaker: {
      open:      global.circuitOpen,
      failures:  0,
    },
    global_status: {
      llm_provider:   global.llmProvider,
      groq_status:    global.groqStatus,
      together_status:global.togetherStatus,
      hf_status:      global.hfStatus,
    },
    layers: {
      layer0_regex:    { status: "always_on", description: "Front-door keyword block" },
      layer1_groq:     { status: groqProbe.ok ? "healthy" : "degraded", latency_ms: groqProbe.latency, error: groqProbe.error || null, key_configured: !!GROQ_KEY },
      layer2_together: { status: togetherProbe.ok ? "healthy" : "degraded", latency_ms: togetherProbe.latency, error: togetherProbe.error || null, key_configured: !!(process.env.TOGETHER_API_KEY && !process.env.TOGETHER_API_KEY.includes("your")) },
      layer3_hf:       { status: hfProbe.ok ? "healthy" : "degraded", latency_ms: hfProbe.latency, error: hfProbe.error || null, url_configured: !!(process.env.PYTHON_BOUNCER_URL && !process.env.PYTHON_BOUNCER_URL.includes("your-hf")) },
      training_db:     { status: process.env.TRAINING_MONGO_URI ? "connected" : "not_configured" },
      main_db:         { status: global.dbConnected ? "connected" : "in_memory" },
    },
    traffic_breakdown: {
      sample_size:          total,
      front_door_blocked:   counts.front_door,
      layer1_handled:       counts.layer1_groq,
      layer2_fallback:      counts.layer2_together,
      layer3_last_resort:   counts.layer3_hf,
      circuit_breaker_bypass: counts.cb_bypass,
      clean_pass:           counts.clean,
      toxic_total:          toxicCount,
      avg_latency_ms:       total > 0 ? Math.round(totalLatency / total) : 0,
    },
  });
});


module.exports = router;
