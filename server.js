/**
 * KantoHub License System — Backend v3
 * Node.js + Express + Mongoose (MongoDB)
 *
 * Routes:
 *   POST /api/auth/login
 *   POST /api/auth/register
 *   POST /api/auth/logout
 *
 *   GET  /api/me
 *   GET  /api/keys          (own keys)
 *   POST /api/keys/generate
 *   DELETE /api/keys/:id
 *
 *   GET  /api/admin/keys    (all keys — admin only)
 *   GET  /api/admin/users   (all users — admin only)
 *   POST /api/admin/users/:id/edit
 *   POST /api/admin/users/:id/give-credits
 *   POST /api/admin/users/:id/kick-session
 *
 *   POST /api/verify        (called by the Roblox Lua script)
 */

const express  = require('express');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const cors     = require('cors');
const crypto   = require('crypto');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT              = process.env.PORT              || 3000;
const MONGO_URI         = process.env.MONGO_URI         || 'mongodb://collectorexalted_db_user:uQyvWxSF6VwmUBkP@ac-so0drys-shard-00-00.1rorwvh.mongodb.net:27017,ac-so0drys-shard-00-01.1rorwvh.mongodb.net:27017,ac-so0drys-shard-00-02.1rorwvh.mongodb.net:27017/?ssl=true&replicaSet=atlas-8xzedc-shard-0&authSource=admin&appName=Cluster0';
const DISCORD_CLIENT_ID     = process.env.DISCORD_CLIENT_ID     || '';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REDIRECT_URI  = process.env.DISCORD_REDIRECT_URI  || `http://localhost:${process.env.PORT || 3000}/api/auth/discord/callback`;
const FRONTEND_URL          = process.env.FRONTEND_URL          || `http://localhost:${process.env.PORT || 3000}`;

/* ─── MONGOOSE SCHEMAS ──────────────────── */

const userSchema = new mongoose.Schema({
  id:               { type: String, required: true, unique: true },
  username:         { type: String, required: true, unique: true },
  discord_id:       { type: String, required: true },
  discord_username: { type: String, default: '' },
  discord_avatar:   { type: String, default: '' },
  password:         { type: String, required: true },
  role:             { type: String, default: 'member' },
  credits:          { type: Number, default: 0 },
  key_prefix:       { type: String, default: null },
  created_at:       { type: Date,   default: Date.now }
});

const sessionSchema = new mongoose.Schema({
  user_id:    { type: String, required: true },
  token_hash: { type: String, required: true, unique: true },
  expires_at: { type: Date,   required: true },
  user_agent: { type: String, default: '' },
  created_at: { type: Date,   default: Date.now }
});

const creditHistorySchema = new mongoose.Schema({
  user_id: { type: String, required: true },
  action:  { type: String, required: true },
  amount:  { type: Number, required: true },
  by_user: { type: String, required: true },
  date:    { type: String, required: true }
});

const licenseKeySchema = new mongoose.Schema({
  id:           { type: String,  required: true, unique: true },
  system_name:  { type: String,  required: true },
  server_name:  { type: String,  default: '' },
  place_id:     { type: String,  required: true },
  key_value:    { type: String,  required: true, unique: true },
  assigned_to:  { type: String,  required: true },
  duration:     { type: String,  default: 'permanent' },
  activated:    { type: Boolean, default: false },
  activated_at: { type: Date,    default: null },
  expires_at:   { type: Date,    default: null },
  revoked:      { type: Boolean, default: false },
  job_id:       { type: String,  default: '' },
  created_by:   { type: String,  required: true },
  created_at:   { type: Date,    default: Date.now }
});

/* Activity log — every verify call from Roblox */
const keyUsageSchema = new mongoose.Schema({
  key_id:      { type: String, required: true },
  key_value:   { type: String, required: true },
  system_name: { type: String, default: '' },
  place_id:    { type: String, default: '' },
  job_id:      { type: String, default: '' },
  server_name: { type: String, default: '' },
  assigned_to: { type: String, default: '' },
  created_by:  { type: String, default: '' },  /* who generated the key */
  event:       { type: String, default: 'heartbeat' },
  message:     { type: String, default: '' },
  timestamp:   { type: Date,   default: Date.now }
});

/* Admin action log — who did what to whom */
const adminLogSchema = new mongoose.Schema({
  actor_id:       { type: String, required: true },   /* admin who performed the action */
  actor_username: { type: String, required: true },
  action:         { type: String, required: true },   /* e.g. 'revoke_key', 'edit_user' */
  target_type:    { type: String, default: '' },      /* 'key' | 'user' */
  target_id:      { type: String, default: '' },
  target_label:   { type: String, default: '' },      /* human-readable name/key */
  details:        { type: String, default: '' },      /* extra context */
  timestamp:      { type: Date,   default: Date.now }
});
adminLogSchema.index({ timestamp: -1 });
adminLogSchema.index({ actor_id: 1, timestamp: -1 });

/* Redeem code schema */
const redeemCodeSchema = new mongoose.Schema({
  id:         { type: String, required: true, unique: true },
  code:       { type: String, required: true, unique: true },
  prefix:     { type: String, required: true },
  credits:    { type: Number, required: true },
  maxUses:    { type: Number, default: 1 },   /* 0 = unlimited */
  usedCount:  { type: Number, default: 0 },
  usedBy:     [{ type: String }],             /* array of user ids who redeemed */
  created_by: { type: String, required: true },
  created_at: { type: Date,   default: Date.now }
});
redeemCodeSchema.index({ code: 1 });

/* Indexes for faster lookups */
sessionSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });
licenseKeySchema.index({ assigned_to: 1 });
creditHistorySchema.index({ user_id: 1 });
keyUsageSchema.index({ key_id: 1, timestamp: -1 });
keyUsageSchema.index({ timestamp: -1 });

const User          = mongoose.model('User',          userSchema);
const Session       = mongoose.model('Session',       sessionSchema);
const CreditHistory = mongoose.model('CreditHistory', creditHistorySchema);
const LicenseKey    = mongoose.model('LicenseKey',    licenseKeySchema);
const KeyUsage      = mongoose.model('KeyUsage',      keyUsageSchema);
const AdminLog      = mongoose.model('AdminLog',      adminLogSchema);
const RedeemCode    = mongoose.model('RedeemCode',    redeemCodeSchema);

/* ─── DB CONNECT ────────────────────────── */
async function connectDB() {
  try {
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000
    });
    console.log('✓ MongoDB connected');
    await seedAdmin();
  } catch (err) {
    console.error('\n✗ MongoDB connection failed:', err.message);
    if (err.message.includes('ECONNREFUSED') || err.message.includes('querySrv')) {
      console.error('\n  → Atlas fix: MongoDB Atlas → Network Access → Add IP Address');
      console.error('  → Add YOUR current IP, or 0.0.0.0/0 to allow all (testing only)');
      console.error('  → Local MongoDB: make sure mongod is running\n');
    }
    process.exit(1);
  }
}

/* ─── SEED OWNERS if empty ───────────────── */
async function seedAdmin() {
  const owners = [
    { id: "u1", username: "Void", discord_id: "1329294797755777047", key_prefix: "VOID" },
    { id: "u2", username: "Zie",  discord_id: "1378265291095543870", key_prefix: "ZIE"  },
  ];

  for (const o of owners) {
    const existing = await User.findOne({ $or: [{ id: o.id }, { discord_id: o.discord_id }] });
    if (!existing) {
      const pw = bcrypt.hashSync(crypto.randomBytes(24).toString("hex"), 10);
      await User.create({ id: o.id, username: o.username, discord_id: o.discord_id, password: pw, role: "Owner", credits: 999, key_prefix: o.key_prefix });
      await CreditHistory.create({ user_id: o.id, action: "Given", amount: 999, by_user: "system", date: today() });
      console.log("Seeded Owner: " + o.username);
    } else {
      const updates = { discord_id: o.discord_id, key_prefix: o.key_prefix };
      if (existing.role !== "Owner") { updates.role = "Owner"; console.log("Restored Owner role: " + o.username); }
      await User.updateOne({ _id: existing._id }, { $set: updates });
    }
  }
}

/* ─── HELPERS ───────────────────────────── */
function genId()  { return crypto.randomBytes(9).toString('hex'); }
function genKey(prefix) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let rand = '';
  for (let i = 0; i < 12; i++) rand += chars[Math.floor(Math.random() * chars.length)];
  return `${prefix}-${rand}`;
}
function today()    { return new Date().toISOString().split('T')[0]; }
function addDays(n) {
  const d = new Date();
  d.setDate(d.getDate() + n);
  return d;
}
function hashToken(t) {
  return crypto.createHash('sha256').update(t).digest('hex');
}
/* ─── ROLE HELPERS ──────────────────────────
   Hierarchy (highest → lowest):
     Owner        – full control, protected tier
     Developer    – same as Owner
     Admin        – manage roles/keys; cannot touch Owner/Developer accounts
     Staff        – give credits, remove users & keys only
     Credit Giver – see users, give prefix + credits only
     member       – regular user
─────────────────────────────────────────── */
function isOwnerOrDev(role)      { return role === 'Owner' || role === 'Developer'; }
function isAdminRole(role)       { return isOwnerOrDev(role) || role === 'Admin'; }
function isStaffOrAbove(role)    { return isAdminRole(role)  || role === 'Staff'; }
function canGiveCredits(role)    { return isStaffOrAbove(role) || role === 'Credit Giver'; }
function canSeeAllUsers(role)    { return canGiveCredits(role); }
function canManageRoles(role)    { return isAdminRole(role); }
/* Protected tier — Owner + Developer accounts cannot be edited/kicked by Admin or below */
function isProtectedTier(role)   { return isOwnerOrDev(role); }

/* Write an admin audit log entry — fire-and-forget (never throws) */
async function logAdmin(actor, action, targetType, targetId, targetLabel, details = '') {
  try {
    await AdminLog.create({
      actor_id:       actor.id,
      actor_username: actor.username,
      action,
      target_type:  targetType,
      target_id:    targetId,
      target_label: targetLabel,
      details
    });
  } catch (_) {}
}

/* auto-mark expired keys as revoked */
async function autoRevoke() {
  await LicenseKey.updateMany(
    { activated: true, expires_at: { $ne: null, $lt: new Date() }, revoked: false },
    { $set: { revoked: true } }
  );
}

/* ─── MIDDLEWARE ────────────────────────── */
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

/* serve the frontend — auto-detect folder location */
/* ── FRONTEND STATIC FILES ─────────────────────────────────────────
   All frontend files (index.html, style.css, landing.js, images/, files/)
   and the dashboard/ subfolder live in the same directory as server.js.
   express.static serves them all automatically.
──────────────────────────────────────────────────────────────────── */
const frontendDir = __dirname;
console.log(`✓ Serving frontend from: ${frontendDir}`);
app.use(express.static(frontendDir));

/* ─── DOWNLOAD ROUTE ────────────────────────── */
/* GET /api/download/license — authenticated users only */
app.get('/api/download/license', requireAuth, (req, res) => {
  const filePath = path.join(__dirname, 'downloads', 'KANTOHUB_KEY_SYSTEM.rbxm');
  res.download(filePath, 'KANTOHUB_KEY_SYSTEM.rbxm', (err) => {
    if (err) {
      console.error('Download error:', err);
      res.status(404).json({ error: 'File not found.' });
    }
  });
});

/* ─── DISCORD OAUTH ─────────────────────── */

/* GET /api/auth/discord — redirect user to Discord consent screen */
app.get('/api/auth/discord', (req, res) => {
  if (!DISCORD_CLIENT_ID) {
    return res.status(503).json({ error: 'Discord OAuth not configured.' });
  }
  const params = new URLSearchParams({
    client_id:     DISCORD_CLIENT_ID,
    redirect_uri:  DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope:         'identify',
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
});

/* GET /api/auth/discord/callback — Discord redirects here with ?code= */
app.get('/api/auth/discord/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect(`${FRONTEND_URL}/dashboard?discord_error=no_code`);

  try {
    /* 1. Exchange code for Discord access token */
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    new URLSearchParams({
        client_id:     DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  DISCORD_REDIRECT_URI,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      console.error('Discord token exchange failed:', tokenData);
      return res.redirect(`${FRONTEND_URL}/dashboard?discord_error=token_failed`);
    }

    /* 2. Fetch Discord user profile */
    const userRes    = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const dUser = await userRes.json();

    const discordId       = dUser.id;
    const discordUsername = dUser.global_name || dUser.username;
    const discordAvatar   = dUser.avatar
      ? `https://cdn.discordapp.com/avatars/${discordId}/${dUser.avatar}.png?size=128`
      : `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(discordId) >> 22n) % 6}.png`;

    /* 3. Find existing user by discord_id or create new one */
    let user = await User.findOne({ discord_id: discordId });

    if (!user) {
      /* Auto-register — use Discord username, deduplicate if needed */
      let username = discordUsername.replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 20);
      const clash  = await User.findOne({ username });
      if (clash) username = username + '_' + genId().slice(0, 4);

      const pw = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 10);
      user = await User.create({
        id:               genId(),
        username,
        discord_id:       discordId,
        discord_username: discordUsername,
        discord_avatar:   discordAvatar,
        password:         pw,
        role:             'member',
        credits:          0,
        key_prefix:       null,
      });
    } else {
      /* Update avatar / display name in case they changed on Discord */
      await User.updateOne({ id: user.id }, {
        $set: { discord_username: discordUsername, discord_avatar: discordAvatar }
      });
    }

    /* 4. Create a session and redirect to frontend with the token */
    await Session.deleteMany({ user_id: user.id });
    const token = crypto.randomBytes(32).toString('hex');
    await Session.create({
      user_id:    user.id,
      token_hash: hashToken(token),
      expires_at: addDays(1),
      user_agent: 'discord-oauth',
    });

    res.redirect(`${FRONTEND_URL}/dashboard?discord_token=${token}`);
  } catch (e) {
    console.error('Discord OAuth error:', e);
    res.redirect(`${FRONTEND_URL}/dashboard?discord_error=server_error`);
  }
});

/* auth middleware */
async function requireAuth(req, res, next) {
  try {
    const header = req.headers['authorization'] || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Not authenticated.' });

    const hash = hashToken(token);
    const sess = await Session.findOne({ token_hash: hash, expires_at: { $gt: new Date() } });
    if (!sess)  return res.status(401).json({ error: 'Session expired. Please log in again.' });

    const user = await User.findOne({ id: sess.user_id });
    if (!user)  return res.status(401).json({ error: 'User not found.' });

    req.user  = { id: user.id, username: user.username, role: user.role, credits: user.credits, key_prefix: user.key_prefix, discord_avatar: user.discord_avatar || '', discord_username: user.discord_username || '' };
    req.token = token;
    next();
  } catch (e) {
    res.status(500).json({ error: 'Auth error.' });
  }
}

function requireAdmin(req, res, next) {
  if (!isAdminRole(req.user.role))
    return res.status(403).json({ error: 'Admin only.' });
  next();
}

function requireStaff(req, res, next) {
  if (!isStaffOrAbove(req.user.role))
    return res.status(403).json({ error: 'Staff or above only.' });
  next();
}

function requireCreditGiver(req, res, next) {
  if (!canGiveCredits(req.user.role))
    return res.status(403).json({ error: 'No permission.' });
  next();
}

/* ─────────────────────────────────────────
   AUTH ROUTES
───────────────────────────────────────── */

/* POST /api/auth/login */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Fill in all fields.' });

    const user = await User.findOne({ username });
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Wrong username or password.' });

    /* one active session per user */
    await Session.deleteMany({ user_id: user.id });

    const token = crypto.randomBytes(32).toString('hex');
    const hash  = hashToken(token);
    const ua    = req.headers['user-agent'] || '';

    await Session.create({
      user_id:    user.id,
      token_hash: hash,
      expires_at: addDays(1),
      user_agent: ua.slice(0, 200)
    });

    res.json({
      token,
      user: {
        id:              user.id,
        username:        user.username,
        discordId:       user.discord_id,
        discordUsername: user.discord_username || '',
        discordAvatar:   user.discord_avatar   || '',
        role:            user.role,
        credits:         user.credits,
        keyprefix:       user.key_prefix
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed.' });
  }
});

/* POST /api/auth/register */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, discordId, password } = req.body;
    if (!username || !discordId || !password)
      return res.status(400).json({ error: 'Fill in all fields.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ error: 'Username already taken.' });

    const hash = bcrypt.hashSync(password, 10);
    const id   = genId();

    await User.create({
      id,
      username,
      discord_id: discordId,
      password:   hash,
      role:       'member',
      credits:    0,
      key_prefix: null
    });

    /* auto-login */
    await Session.deleteMany({ user_id: id });
    const token  = crypto.randomBytes(32).toString('hex');
    const tokenH = hashToken(token);
    const ua     = req.headers['user-agent'] || '';

    await Session.create({
      user_id:    id,
      token_hash: tokenH,
      expires_at: addDays(1),
      user_agent: ua.slice(0, 200)
    });

    res.status(201).json({
      token,
      user: { id, username, discordId, role: 'member', credits: 0, keyprefix: null }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Registration failed.' });
  }
});

/* POST /api/auth/logout */
app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    const hash = hashToken(req.token);
    await Session.deleteOne({ token_hash: hash });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Logout failed.' });
  }
});

/* ─────────────────────────────────────────
   USER ROUTES
───────────────────────────────────────── */

/* GET /api/me */
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const u       = await User.findOne({ id: req.user.id });
    const history = await CreditHistory.find({ user_id: req.user.id })
      .sort({ _id: -1 }).limit(50);

    res.json({
      id:              u.id,
      username:        u.username,
      discordId:       u.discord_id,
      discordUsername: u.discord_username || '',
      discordAvatar:   u.discord_avatar   || '',
      role:            u.role,
      credits:         u.credits,
      keyprefix:       u.key_prefix,
      creditHistory:   history.map(h => ({
        action: h.action,
        amount: h.amount,
        by:     h.by_user,
        date:   h.date
      }))
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch user.' });
  }
});

/* ─────────────────────────────────────────
   KEY ROUTES
───────────────────────────────────────── */

/* GET /api/keys — own keys */
app.get('/api/keys', requireAuth, async (req, res) => {
  try {
    await autoRevoke();
    const keys = await LicenseKey.find({ assigned_to: req.user.id }).sort({ created_at: -1 });
    res.json(keys.map(formatKey));
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch keys.' });
  }
});

/* POST /api/keys/generate */
app.post('/api/keys/generate', requireAuth, async (req, res) => {
  try {
    const { systemName, placeId, duration, prefix, assignTo } = req.body;
    if (!systemName || !placeId || !prefix)
      return res.status(400).json({ error: 'Fill in all fields.' });

    const u = await User.findOne({ id: req.user.id });

    if (!isAdminRole(u.role)) {
      if (u.credits <= 0)
        return res.status(402).json({ error: 'No credits left. Ask an admin.' });
      if (u.key_prefix && prefix.toUpperCase() !== u.key_prefix)
        return res.status(400).json({ error: `Use your assigned prefix: ${u.key_prefix}` });
    }

    const targetId = isAdminRole(u.role) && assignTo ? assignTo : req.user.id;
    const target   = await User.findOne({ id: targetId });
    if (!target)   return res.status(400).json({ error: 'Target user not found.' });

    const keyVal = genKey(prefix.toUpperCase());
    const id     = genId();

    const newKey = await LicenseKey.create({
      id,
      system_name: systemName,
      server_name: '',
      place_id:    String(placeId).trim(),
      key_value:   keyVal,
      assigned_to: targetId,
      duration:    duration || 'permanent',
      activated:   false,
      created_by:  req.user.id
    });

    /* deduct credit for non-admins */
    if (!isAdminRole(u.role)) {
      await User.updateOne({ id: req.user.id }, { $inc: { credits: -1 } });
      await CreditHistory.create({
        user_id: req.user.id,
        action:  'Used',
        amount:  1,
        by_user: u.username,
        date:    today()
      });
    }

    res.status(201).json(formatKey(newKey));

    /* Log key generation in activity — visible to admin + key owner */
    try {
      await KeyUsage.create({
        key_id:      id,
        key_value:   keyVal,
        system_name: systemName,
        place_id:    String(placeId).trim(),
        job_id:      '',
        server_name: '',
        assigned_to: targetId,
        created_by:  req.user.id,
        event:       'generated',
        message:     `Key generated by ${u.username}`
      });
    } catch (_) {}
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to generate key.' });
  }
});

/* DELETE /api/keys/:id */
app.delete('/api/keys/:id', requireAuth, async (req, res) => {
  try {
    const k = await LicenseKey.findOne({ id: req.params.id });
    if (!k) return res.status(404).json({ error: 'Key not found.' });

    const u = await User.findOne({ id: req.user.id });
    if (!isStaffOrAbove(u.role)) {
      const ownedByMe   = k.assigned_to === req.user.id;
      const matchPrefix = u.key_prefix && k.key_value.startsWith(u.key_prefix + '-');
      if (!ownedByMe && !matchPrefix)
        return res.status(403).json({ error: 'You can only revoke your own keys.' });
    }

    await LicenseKey.deleteOne({ id: req.params.id });
    /* Audit log — who revoked this key */
    await logAdmin(
      req.user, 'revoke_key', 'key', k.id,
      k.key_value,
      `System: ${k.system_name} | Assigned to: ${k.assigned_to}`
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to revoke key.' });
  }
});

/* ─────────────────────────────────────────
   ADMIN ROUTES
───────────────────────────────────────── */

/* GET /api/admin/keys */
app.get('/api/admin/keys', requireAuth, requireStaff, async (req, res) => {
  try {
    await autoRevoke();
    const keys = await LicenseKey.find().sort({ created_at: -1 });
    res.json(keys.map(formatKey));
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch keys.' });
  }
});

/* GET /api/admin/users */
app.get('/api/admin/users', requireAuth, requireCreditGiver, async (req, res) => {
  try {
    const users    = await User.find().sort({ created_at: 1 });
    const sessions = await Session.aggregate([
      { $match: { expires_at: { $gt: new Date() } } },
      { $group: { _id: '$user_id', cnt: { $sum: 1 } } }
    ]);

    const sessMap = {};
    sessions.forEach(s => { sessMap[s._id] = s.cnt; });

    res.json(users.map(u => ({
      id:             u.id,
      username:       u.username,
      discordId:      u.discord_id,
      role:           u.role,
      credits:        u.credits,
      keyprefix:      u.key_prefix,
      activeSessions: sessMap[u.id] || 0
    })));
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

/* POST /api/admin/users/:id/edit */
app.post('/api/admin/users/:id/edit', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { role, addCredits, keyPrefix } = req.body;
    const requester = await User.findOne({ id: req.user.id });
    const target    = await User.findOne({ id: req.params.id });
    if (!target) return res.status(404).json({ error: 'User not found.' });

    /* Owner/Developer accounts are protected — only Owner/Developer can edit them */
    if (isProtectedTier(target.role) && !isOwnerOrDev(requester.role))
      return res.status(403).json({ error: 'Only an Owner or Developer can edit this account.' });

    /* Only Owner/Developer can assign the Owner role */
    if (role === 'Owner' && !isOwnerOrDev(requester.role))
      return res.status(403).json({ error: 'Only an Owner or Developer can assign the Owner role.' });

    /* Only Owner/Developer can assign the Developer role */
    if (role === 'Developer' && !isOwnerOrDev(requester.role))
      return res.status(403).json({ error: 'Only an Owner or Developer can assign the Developer role.' });

    /* Admin cannot promote someone to a role equal to or above their own */
    const roleRank = { member: 0, 'Credit Giver': 1, Staff: 2, Admin: 3, Developer: 4, Owner: 4 };
    if (role && (roleRank[role] ?? 0) >= (roleRank[requester.role] ?? 0) && !isOwnerOrDev(requester.role))
      return res.status(403).json({ error: 'You cannot assign a role equal to or above your own.' });

    const $set = {};
    if (role)      $set.role       = role;
    if (keyPrefix) $set.key_prefix = keyPrefix.toUpperCase();

    const add      = parseInt(addCredits) || 0;
    const updateOp = {};
    if (Object.keys($set).length) updateOp.$set = $set;
    if (add > 0) {
      updateOp.$inc = { credits: add };
      await CreditHistory.create({
        user_id: target.id,
        action:  'Given',
        amount:  add,
        by_user: req.user.username,
        date:    today()
      });
    }

    if (Object.keys(updateOp).length) {
      await User.updateOne({ id: req.params.id }, updateOp);
    }

    const updated = await User.findOne({ id: req.params.id });
    /* Audit log */
    const changeDesc = [];
    if (role)      changeDesc.push(`role→${role}`);
    if (keyPrefix) changeDesc.push(`prefix→${keyPrefix.toUpperCase()}`);
    if (add > 0)   changeDesc.push(`+${add} credits`);
    await logAdmin(
      req.user, 'edit_user', 'user', target.id,
      target.username,
      changeDesc.join(', ')
    );
    res.json({
      ok: true,
      user: {
        id:        updated.id,
        username:  updated.username,
        role:      updated.role,
        credits:   updated.credits,
        keyprefix: updated.key_prefix
      }
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to edit user.' });
  }
});

/* POST /api/admin/users/:id/give-credits */
app.post('/api/admin/users/:id/give-credits', requireAuth, requireCreditGiver, async (req, res) => {
  try {
    const u = await User.findOne({ id: req.user.id });
    if (!canGiveCredits(u.role)) return res.status(403).json({ error: 'No permission.' });

    const target = await User.findOne({ id: req.params.id });
    if (!target) return res.status(404).json({ error: 'User not found.' });

    const { amount, keyPrefix } = req.body;
    const amt = parseInt(amount) || 0;
    if (amt <= 0)  return res.status(400).json({ error: 'Amount must be > 0.' });
    if (!keyPrefix) return res.status(400).json({ error: 'Key prefix required.' });

    await User.updateOne(
      { id: target.id },
      { $inc: { credits: amt }, $set: { key_prefix: keyPrefix.toUpperCase() } }
    );

    await CreditHistory.create({
      user_id: target.id,
      action:  'Given',
      amount:  amt,
      by_user: u.username,
      date:    today()
    });

    /* Audit log */
    await logAdmin(
      req.user, 'give_credits', 'user', target.id,
      target.username,
      `+${amt} credits | prefix: ${keyPrefix.toUpperCase()}`
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to give credits.' });
  }
});

/* ─────────────────────────────────────────
   REDEEM CODE ROUTES
───────────────────────────────────────── */

/* POST /api/admin/redeem-codes — create a redeem code (Admin+) */
app.post('/api/admin/redeem-codes', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { code, prefix, credits, maxUses } = req.body;
    if (!code)    return res.status(400).json({ error: 'Code is required.' });
    if (!prefix)  return res.status(400).json({ error: 'Prefix is required.' });
    if (!credits || credits < 1) return res.status(400).json({ error: 'Credits must be at least 1.' });

    const normalised = code.trim().toUpperCase();
    const exists = await RedeemCode.findOne({ code: normalised });
    if (exists)   return res.status(409).json({ error: 'A code with that name already exists.' });

    const rc = await RedeemCode.create({
      id:         genId(),
      code:       normalised,
      prefix:     prefix.trim().toUpperCase(),
      credits:    parseInt(credits),
      maxUses:    parseInt(maxUses) || 0,
      created_by: req.user.username
    });

    await logAdmin(req.user, 'create_redeem_code', 'redeem', rc.id, normalised,
      `+${credits} credits | prefix:${prefix.toUpperCase()} | max uses:${maxUses || '∞'}`);

    res.json({ ok: true, id: rc.id, code: rc.code });
  } catch (e) {
    res.status(500).json({ error: 'Failed to create redeem code.' });
  }
});

/* GET /api/admin/redeem-codes — list all codes (Admin+) */
app.get('/api/admin/redeem-codes', requireAuth, requireAdmin, async (req, res) => {
  try {
    const codes = await RedeemCode.find({}).sort({ created_at: -1 });
    res.json(codes.map(c => ({
      id:         c.id,
      code:       c.code,
      prefix:     c.prefix,
      credits:    c.credits,
      maxUses:    c.maxUses,
      usedCount:  c.usedCount,
      usesLeft:   c.maxUses === 0 ? Infinity : Math.max(0, c.maxUses - c.usedCount),
      createdAt:  c.created_at
    })));
  } catch (e) {
    res.status(500).json({ error: 'Failed to load redeem codes.' });
  }
});

/* DELETE /api/admin/redeem-codes/:id — delete a code (Admin+) */
app.delete('/api/admin/redeem-codes/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const rc = await RedeemCode.findOne({ id: req.params.id });
    if (!rc) return res.status(404).json({ error: 'Redeem code not found.' });
    await RedeemCode.deleteOne({ id: rc.id });
    await logAdmin(req.user, 'delete_redeem_code', 'redeem', rc.id, rc.code, '');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete redeem code.' });
  }
});

/* GET /api/redeem/preview?code=... — preview a code before redeeming (any auth user) */
app.get('/api/redeem/preview', requireAuth, async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).json({ error: 'Code required.' });

    const rc = await RedeemCode.findOne({ code: code.trim().toUpperCase() });
    if (!rc) return res.status(404).json({ error: 'Invalid or expired code.' });

    /* Already redeemed by this user? */
    if (rc.usedBy.includes(req.user.id))
      return res.status(409).json({ error: 'You have already redeemed this code.' });

    /* Maxed out? */
    if (rc.maxUses > 0 && rc.usedCount >= rc.maxUses)
      return res.status(410).json({ error: 'This code has been fully redeemed.' });

    res.json({
      code:     rc.code,
      credits:  rc.credits,
      prefix:   rc.prefix,
      maxUses:  rc.maxUses,
      usesLeft: rc.maxUses === 0 ? 0 : rc.maxUses - rc.usedCount
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to preview code.' });
  }
});

/* POST /api/redeem — redeem a code (any auth user) */
app.post('/api/redeem', requireAuth, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Code required.' });

    const rc = await RedeemCode.findOne({ code: code.trim().toUpperCase() });
    if (!rc) return res.status(404).json({ error: 'Invalid or expired code.' });

    if (rc.usedBy.includes(req.user.id))
      return res.status(409).json({ error: 'You have already redeemed this code.' });

    if (rc.maxUses > 0 && rc.usedCount >= rc.maxUses)
      return res.status(410).json({ error: 'This code has been fully redeemed.' });

    /* Apply credits + prefix */
    await User.updateOne(
      { id: req.user.id },
      { $inc: { credits: rc.credits }, $set: { key_prefix: rc.prefix } }
    );

    await CreditHistory.create({
      user_id: req.user.id,
      action:  'Redeemed',
      amount:  rc.credits,
      by_user: `Code: ${rc.code}`,
      date:    today()
    });

    /* Mark code as used */
    await RedeemCode.updateOne(
      { id: rc.id },
      { $inc: { usedCount: 1 }, $push: { usedBy: req.user.id } }
    );

    await logAdmin(
      { id: req.user.id, username: req.user.username },
      'redeem_code', 'redeem', rc.id, rc.code,
      `User ${req.user.username} redeemed +${rc.credits} credits | prefix:${rc.prefix}`
    );

    res.json({ ok: true, credits: rc.credits, prefix: rc.prefix });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to redeem code.' });
  }
});

/* POST /api/admin/users/:id/kick-session */
app.post('/api/admin/users/:id/kick-session', requireAuth, requireStaff, async (req, res) => {
  try {
    const target = await User.findOne({ id: req.params.id });
    if (!target) return res.status(404).json({ error: 'User not found.' });
    if (isProtectedTier(target.role) && !isOwnerOrDev(req.user.role))
      return res.status(403).json({ error: 'Only an Owner or Developer can kick this account\'s session.' });
    await Session.deleteMany({ user_id: req.params.id });
    /* Audit log */
    await logAdmin(req.user, 'kick_session', 'user', target.id, target.username, 'Force-logged out');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to kick session.' });
  }
});

/* DELETE /api/admin/users/:id — delete account + all their data */
app.delete('/api/admin/users/:id', requireAuth, requireStaff, async (req, res) => {
  try {
    const target = await User.findOne({ id: req.params.id });
    if (!target) return res.status(404).json({ error: 'User not found.' });

    /* Cannot delete yourself */
    if (target.id === req.user.id)
      return res.status(400).json({ error: 'You cannot delete your own account.' });
    /* Owner/Developer accounts are protected */
    if (isProtectedTier(target.role))
      return res.status(403).json({ error: 'Cannot delete an Owner or Developer account.' });
    /* Admin cannot delete another Admin (only Owner/Developer can) */
    if (target.role === 'Admin' && !isOwnerOrDev(req.user.role))
      return res.status(403).json({ error: 'Only an Owner or Developer can delete an Admin account.' });

    /* Wipe sessions, keys, credit history, then user */
    await Session.deleteMany({ user_id: target.id });
    await LicenseKey.deleteMany({ assigned_to: target.id });
    await CreditHistory.deleteMany({ user_id: target.id });
    await User.deleteOne({ id: target.id });

    /* Audit log */
    await logAdmin(req.user, 'delete_user', 'user', target.id, target.username, `Role was: ${target.role}`);

    res.json({ ok: true, deleted: target.username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to delete user.' });
  }
});

/* POST /api/admin/users/:id/set-password — force password reset */
app.post('/api/admin/users/:id/set-password', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    const target = await User.findOne({ id: req.params.id });
    if (!target) return res.status(404).json({ error: 'User not found.' });

    /* Cannot reset Owner/Developer password unless you ARE Owner/Developer */
    if (isProtectedTier(target.role) && !isOwnerOrDev(req.user.role))
      return res.status(403).json({ error: 'Cannot reset Owner/Developer password.' });

    const hash = bcrypt.hashSync(newPassword, 10);
    await User.updateOne({ id: target.id }, { $set: { password: hash } });

    /* Kick their active sessions so they must re-login with new password */
    await Session.deleteMany({ user_id: target.id });

    /* Audit log */
    await logAdmin(req.user, 'reset_password', 'user', target.id, target.username, 'Password force-reset');

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to reset password.' });
  }
});

/* ─────────────────────────────────────────
   ROBLOX VERIFY ENDPOINT
   Called by the Lua script inside Roblox game servers.
───────────────────────────────────────── */
app.post('/api/verify', async (req, res) => {
  try {
    const { key, placeId, serverName, jobId, systemName } = req.body;
    if (!key || !placeId) return res.status(400).json({ valid: false, message: 'missing_config' });

    const cleanKey        = String(key).trim();
    const cleanPlaceId    = String(placeId).trim();
    const cleanSystemName = systemName ? String(systemName).trim() : '';

    const k = await LicenseKey.findOne({ key_value: cleanKey });

    /* helper: log usage event — always includes created_by so the key creator sees it too */
    async function logUsage(event, message) {
      try {
        await KeyUsage.create({
          key_id:      k ? k.id : 'unknown',
          key_value:   cleanKey,
          system_name: k ? k.system_name : '',
          place_id:    cleanPlaceId,
          job_id:      (jobId || '').slice(0, 80),
          server_name: (serverName || '').slice(0, 100),
          assigned_to: k ? k.assigned_to : '',
          created_by:  k ? k.created_by  : '',
          event,
          message
        });
      } catch (_) {}
    }

    if (!k)        { await logUsage('denied', 'invalid_key');     return res.json({ valid: false, message: 'invalid_key' }); }
    if (k.revoked) { await logUsage('denied', 'revoked');         return res.json({ valid: false, message: 'revoked' }); }
    if (k.place_id.trim() !== cleanPlaceId) {
      /* include both expected and attempted place IDs so the UI can show the diff */
      await logUsage('denied', `invalid_place_id|expected:${k.place_id}|got:${cleanPlaceId}`);
      return res.json({ valid: false, message: 'invalid_place_id' });
    }

    /* A key is issued for ONE system. If the calling script sends its
       SYSTEM_NAME and it doesn't match what this key was generated for,
       reject it — this is what stops one key (meant for System A) from
       also authorizing System B just because both live in the same game. */
    if (cleanSystemName && k.system_name && k.system_name.trim() !== cleanSystemName) {
      await logUsage('denied', `system_mismatch|expected:${k.system_name}|got:${cleanSystemName}`);
      return res.json({ valid: false, message: 'system_mismatch' });
    }

    /* check expiry if already active */
    if (k.activated && k.expires_at && new Date(k.expires_at) < new Date()) {
      await LicenseKey.updateOne({ id: k.id }, { $set: { revoked: true } });
      await logUsage('denied', 'expired');
      return res.json({ valid: false, message: 'expired' });
    }

    /* first activation — start the countdown NOW */
    if (!k.activated) {
      let expiresAt = null;
      const dur = k.duration;
      if      (dur === '30d' || dur === '1month') expiresAt = addDays(30);
      else if (dur === '7d'  || dur === '1week')  expiresAt = addDays(7);
      else if (dur === '3d'  || dur === '3days')  expiresAt = addDays(3);
      else if (dur === '1d')                      expiresAt = addDays(1);

      const srvName = (serverName || 'Roblox Server').slice(0, 100);
      await LicenseKey.updateOne({ id: k.id }, {
        $set: {
          activated:    true,
          activated_at: new Date(),
          server_name:  srvName,
          job_id:       (jobId || '').slice(0, 80),
          expires_at:   expiresAt
        }
      });

      const updated = await LicenseKey.findOne({ id: k.id });
      await logUsage('activated', 'first_use');
      return res.json({ valid: true, message: 'activated', expiresAt: updated.expires_at });
    }

    /* already active — log heartbeat (throttle: once per 5 min per jobId) */
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
    const recentLog  = await KeyUsage.findOne({
      key_id: k.id,
      job_id: (jobId || '').slice(0, 80),
      event:  'heartbeat',
      timestamp: { $gt: fiveMinAgo }
    });
    if (!recentLog) await logUsage('heartbeat', `Server: ${(serverName || 'Unknown').slice(0, 60)}`);

    return res.json({ valid: true, message: 'ok', expiresAt: k.expires_at });
  } catch (e) {
    console.error(e);
    res.status(500).json({ valid: false, message: 'server_error' });
  }
});

/* GET /api/activity — current user's own key activity log */
app.get('/api/activity', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);

    /* Also fetch the user's own key values so we can catch
       denied attempts (invalid_place_id) that are logged with the
       correct key_value but maybe a blank assigned_to fallback */
    const myKeys = await LicenseKey.find({ assigned_to: req.user.id }).select('key_value');
    const myKeyValues = myKeys.map(k => k.key_value);

    const logs = await KeyUsage.find({
      $or: [
        { assigned_to: req.user.id },
        { created_by:  req.user.id },
        /* catch denied logs tied to their key values */
        { event: 'denied', key_value: { $in: myKeyValues } }
      ]
    })
      .sort({ timestamp: -1 })
      .limit(limit);

    res.json(logs.map(l => ({
      id:         l._id,
      keyId:      l.key_id,
      keyValue:   l.key_value,
      systemName: l.system_name,
      placeId:    l.place_id,
      jobId:      l.job_id,
      serverName: l.server_name,
      assignedTo: l.assigned_to,
      createdBy:  l.created_by,
      event:      l.event,
      message:    l.message,
      timestamp:  l.timestamp
    })));
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch activity.' });
  }
});

/* DELETE /api/activity — clear current user's own activity logs */
app.delete('/api/activity', requireAuth, async (req, res) => {
  try {
    await KeyUsage.deleteMany({ assigned_to: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to clear activity.' });
  }
});

/* GET /api/admin/audit-log — admin action history */
app.get('/api/admin/audit-log', requireAuth, requireAdmin, async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit) || 100, 500);
    const actor  = req.query.actor || null;
    const filter = actor ? { actor_id: actor } : {};
    const logs   = await AdminLog.find(filter).sort({ timestamp: -1 }).limit(limit);
    res.json(logs.map(l => ({
      id:           l._id,
      actorId:      l.actor_id,
      actorName:    l.actor_username,
      action:       l.action,
      targetType:   l.target_type,
      targetId:     l.target_id,
      targetLabel:  l.target_label,
      details:      l.details,
      timestamp:    l.timestamp
    })));
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch audit log.' });
  }
});

/* DELETE /api/admin/audit-log — clear audit log (Owner / Developer only) */
app.delete('/api/admin/audit-log', requireAuth, async (req, res) => {
  if (!isOwnerOrDev(req.user.role))
    return res.status(403).json({ error: 'Owner or Developer only.' });
  try {
    await AdminLog.deleteMany({});
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to clear audit log.' });
  }
});

/* GET /api/admin/activity — recent key usage log */
app.get('/api/admin/activity', requireAuth, requireStaff, async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit) || 50, 200);
    const keyId  = req.query.keyId || null;
    const filter = keyId ? { key_id: keyId } : {};
    const logs   = await KeyUsage.find(filter).sort({ timestamp: -1 }).limit(limit);
    res.json(logs.map(l => ({
      id:         l._id,
      keyId:      l.key_id,
      keyValue:   l.key_value,
      systemName: l.system_name,
      placeId:    l.place_id,
      jobId:      l.job_id,
      serverName: l.server_name,
      assignedTo: l.assigned_to,
      createdBy:  l.created_by,
      event:      l.event,
      message:    l.message,
      timestamp:  l.timestamp
    })));
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch activity.' });
  }
});

/* GET /api/admin/denied — all denied events including invalid_key (no user link) */
app.get('/api/admin/denied', requireAuth, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const logs  = await KeyUsage.find({ event: 'denied' }).sort({ timestamp: -1 }).limit(limit);
    res.json(logs.map(l => ({
      id:         l._id,
      keyId:      l.key_id,
      keyValue:   l.key_value,
      systemName: l.system_name,
      placeId:    l.place_id,
      jobId:      l.job_id,
      serverName: l.server_name,
      assignedTo: l.assigned_to,
      createdBy:  l.created_by,
      event:      l.event,
      message:    l.message,
      timestamp:  l.timestamp
    })));
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch denied events.' });
  }
});

/* DELETE /api/admin/activity — clear ALL activity logs (admin only) */
app.delete('/api/admin/activity', requireAuth, requireAdmin, async (req, res) => {
  try {
    await KeyUsage.deleteMany({});
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to clear activity.' });
  }
});

/* ─────────────────────────────────────────
   FORMAT HELPER
───────────────────────────────────────── */
function formatKey(k) {
  return {
    id:          k.id,
    systemName:  k.system_name,
    serverName:  k.server_name,
    placeid:     k.place_id,
    key:         k.key_value,
    assignedTo:  k.assigned_to,
    duration:    k.duration,
    activated:   !!k.activated,
    activatedAt: k.activated_at,
    expiresAt:   k.expires_at,
    revoked:     !!k.revoked,
    jobId:       k.job_id,
    createdBy:   k.created_by,
    createdAt:   k.created_at
  };
}

/* ─────────────────────────────────────────
   CATCH-ALL — serve index.html for any
   unmatched GET (handles Discord callback
   redirect and direct URL visits)
───────────────────────────────────────── */
/* ── CATCH-ALL ─────────────────────────────────────────────────────
   /dashboard  → dashboard/index.html  (the app shell with auth + sidebar)
   everything else → index.html        (landing page)
──────────────────────────────────────────────────────────────────── */
app.get('/dashboard', (req, res) => {
  const dashPath = path.join(frontendDir, 'dashboard', 'index.html');
  if (fs.existsSync(dashPath)) {
    res.sendFile(dashPath);
  } else {
    res.status(404).send('Dashboard not found. Make sure dashboard/index.html exists.');
  }
});

app.get('*', (req, res) => {
  const indexPath = path.join(frontendDir, 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send('Not found.');
  }
});

/* ─────────────────────────────────────────
   START
───────────────────────────────────────── */
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🛡️  KantoHub backend running on http://localhost:${PORT}`);
    console.log(`   MongoDB: ${MONGO_URI}`);
    console.log(`   Frontend served from: ${path.join(__dirname, '../frontend')}\n`);
  });
});
