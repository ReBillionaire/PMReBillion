// ══════════════════════════════════════════════════════════════
// ReBillion PM — Express Server (Vercel Deployment)
// ══════════════════════════════════════════════════════════════
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const passport = require('passport');
const XLSX = require('xlsx');
const multer = require('multer');
const db = require('./database');
const email = require('./email');

// Multer config for XLSX uploads (memory storage, 10MB limit)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy (required for Vercel/serverless - enables secure cookies behind reverse proxy)
app.set('trust proxy', 1);

// ══════════════════════════════════════════════════════════════
// PASSPORT GOOGLE OAUTH SETUP (only if credentials are configured)
// ══════════════════════════════════════════════════════════════
const googleAuthEnabled = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

if (googleAuthEnabled) {
  const GoogleStrategy = require('passport-google-oauth20').Strategy;

  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL ||
      `${process.env.VERCEL_URL ? 'https://' + process.env.VERCEL_URL : 'http://localhost:' + PORT}/auth/google/callback`
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
      if (!email) {
        return done(null, false, { message: 'No email found in Google profile' });
      }

      // Look up user by email in database
      const existingUser = await db.getUserByEmail(email);

      if (existingUser) {
        return done(null, existingUser);
      }

      // Check if email is from an internal domain
      const internalDomains = ['@rebillion.ai', '@garvik.ai', '@simplyclosed.com'];
      const isInternalEmail = internalDomains.some(d => email.endsWith(d));

      // Create new user
      const newUser = await db.findOrCreateGoogleUser({
        email: email,
        name: profile.displayName || email.split('@')[0],
        type: isInternalEmail ? 'member' : 'observer',
        role: isInternalEmail ? 'team member' : 'observer'
      });

      return done(null, newUser);
    } catch (error) {
      return done(error);
    }
  }));
}

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await db.getUser(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// ══════════════════════════════════════════════════════════════
// SECURITY MIDDLEWARE
// ══════════════════════════════════════════════════════════════

// C9: Helmet security headers (allow inline scripts/event handlers for login/app pages)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'self'"],
      upgradeInsecureRequests: []
    }
  }
}));

// Disable caching for HTML/JS responses (prevent stale CSP headers)
app.use((req, res, next) => {
  if (req.path.endsWith('.html') || req.path.endsWith('.js') || req.path.startsWith('/api/') || req.path.startsWith('/auth/')) {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
  }
  next();
});

// I4: Morgan HTTP access logging
app.use(morgan('combined'));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: false }));

// C3: Session configuration with PostgreSQL store for Vercel persistence
const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'rebillion-pm-dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  store: new pgSession({
    pool: db.getPool(),
    tableName: 'session',
    createTableIfMissing: true
  }),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' || !!process.env.VERCEL,
    sameSite: 'lax', // Changed to 'lax' for OAuth redirect compatibility
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  }
};

app.use(session(sessionConfig));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// C4: CSRF Protection - Double-submit cookie pattern with X-CSRF-Token header
function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = generateCSRFToken();
  }
  res.locals.csrfToken = req.session.csrfToken;
  // Set CSRF token as a readable cookie (double-submit pattern)
  res.cookie('csrfToken', req.session.csrfToken, {
    httpOnly: false, // Must be readable by JS
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production' || !!process.env.VERCEL
  });
  next();
});

// CSRF token validation for mutating requests (exempt login/logout and Google OAuth callback)
function validateCSRFToken(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  // Exempt auth endpoints and public onboarding form
  if (req.path === '/api/auth/login' ||
      req.path === '/api/auth/logout' ||
      req.path === '/auth/google/callback' ||
      req.path.startsWith('/api/onboarding/')) {
    return next();
  }
  const token = req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({ message: 'CSRF token validation failed' });
  }
  next();
}
app.use(validateCSRFToken);

// C6: Rate limiting on login (5 attempts per 15 minutes)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

// ══════════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ══════════════════════════════════════════════════════════════
function requireLogin(req, res, next) {
  if (!req.session || !req.session.userId) {
    // For browser HTML requests, redirect to login page instead of returning JSON
    const acceptsHTML = req.headers.accept && req.headers.accept.includes('text/html');
    if (acceptsHTML && !req.path.startsWith('/api/')) {
      return res.redirect('/login.html');
    }
    return res.status(401).json({ message: 'Not authenticated' });
  }
  next();
}

// I1: Admin check middleware
async function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ message: 'Not authenticated' });
  }
  try {
    const isAdmin = await db.isAdmin(req.session.userId);
    if (!isAdmin) {
      return res.status(403).json({ message: 'Admin access required' });
    }
    next();
  } catch (e) {
    return res.status(500).json({ message: 'Error checking admin status' });
  }
}

// I10: Safe error response helper
function safeError(res, statusCode, message) {
  res.status(statusCode).json({ message });
}

// I2: Input length validation helper
function validateInputLengths(data) {
  const limits = {
    company: 200,
    contactName: 100,
    notes: 5000,
    email: 120,
    contactEmail: 120,
    name: 100,
    role: 100
  };
  for (const [key, limit] of Object.entries(limits)) {
    if (data[key] && typeof data[key] === 'string' && data[key].length > limit) {
      return { valid: false, field: key, limit };
    }
  }
  return { valid: true };
}

// C5: Serve static files (except app.html, app.js, portal.html which need auth)
const publicDir = path.join(__dirname, 'public');
app.use((req, res, next) => {
  if (req.path === '/app.html' || req.path === '/app.js' || req.path === '/portal.html') {
    return next();
  }
  express.static(publicDir)(req, res, next);
});

// ══════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════

// Root redirect
app.get('/', (req, res) => {
  if (req.session && req.session.userId) {
    res.redirect('/app.html');
  } else {
    res.redirect('/login.html');
  }
});

// C5: Serve app.html through auth-gated route
app.get('/app.html', requireLogin, (req, res) => {
  res.sendFile(path.join(publicDir, 'app.html'));
});

// C5: Serve app.js through auth-gated route
app.get('/app.js', requireLogin, (req, res) => {
  res.set('Content-Type', 'application/javascript');
  res.sendFile(path.join(publicDir, 'app.js'));
});

// Serve portal.html through auth-gated route (client portal)
app.get('/portal.html', requireLogin, (req, res) => {
  res.sendFile(path.join(publicDir, 'portal.html'));
});

// Get CSRF token (for C4)
app.get('/api/csrf-token', requireLogin, (req, res) => {
  res.json({ token: res.locals.csrfToken });
});

// Auth config endpoint - tells frontend if Google OAuth is available
app.get('/api/auth/config', (req, res) => {
  res.json({ googleAuthEnabled });
});

// Google OAuth routes (only if configured)
if (googleAuthEnabled) {
  console.log('Google OAuth enabled. Callback URL:', process.env.GOOGLE_CALLBACK_URL || 'using VERCEL_URL fallback');
  console.log('Client ID starts with:', process.env.GOOGLE_CLIENT_ID?.substring(0, 15) + '...');

  app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

  app.get('/auth/google/callback', (req, res, next) => {
    passport.authenticate('google', async (err, user, info) => {
      if (err) {
        console.error('Google OAuth error:', err.message || err);
        console.error('Error details:', JSON.stringify({ name: err.name, code: err.code, oauthError: err.oauthError, statusCode: err.statusCode }));
        return res.redirect('/login.html?error=auth_failed&detail=' + encodeURIComponent(err.message || 'unknown'));
      }
      if (!user) {
        console.error('Google OAuth: no user returned. Info:', JSON.stringify(info));
        return res.redirect('/login.html?error=auth_failed&detail=no_user');
      }
      // Successful authentication
      req.session.userId = user.id;
      await new Promise((resolve, reject) => {
        req.session.save((saveErr) => {
          if (saveErr) reject(saveErr);
          else resolve();
        });
      });
      // Redirect client-type users to portal, internal users to app
      const isClientUser = user.type === 'client' || user.type === 'observer';
      // Check if this user's email matches a client contact_email — if so, send to portal
      const matchedClient = await db.getClientByContactEmail(user.email);
      if (matchedClient && !['member', 'admin'].includes(user.type)) {
        res.redirect('/portal.html');
      } else {
        res.redirect('/app.html');
      }
    })(req, res, next);
  });
} else {
  app.get('/auth/google', (req, res) => {
    res.redirect('/login.html?error=auth_failed');
  });
}

// Username/password login disabled — Google OAuth only
app.post('/api/auth/login', (req, res) => {
  res.status(403).json({ message: 'Username/password login is disabled. Please use Google sign-in.' });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Current user
app.get('/api/auth/me', requireLogin, async (req, res) => {
  try {
    const user = await db.getUser(req.session.userId);
    if (!user) {
      req.session.destroy(() => {});
      return res.status(401).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (e) {
    console.error('Get user error:', e);
    safeError(res, 500, 'Server error');
  }
});

// C1 + C7: Change password (8-char minimum, call db.updatePassword)
app.post('/api/auth/change-password', requireLogin, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Both passwords required' });
    }
    // C7: Enforce 8-character minimum
    if (newPassword.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters' });
    }
    const user = await db.getUser(req.session.userId);
    const userByName = await db.getUserByName(user.name);
    const valid = await bcrypt.compare(currentPassword, userByName.password_hash);
    if (!valid) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }
    // C1: Hash and call db.updatePassword
    const hash = await bcrypt.hash(newPassword, 10);
    await db.updatePassword(req.session.userId, hash);
    res.json({ success: true, message: 'Password changed' });
  } catch (e) {
    console.error('Change password error:', e);
    safeError(res, 500, 'Server error');
  }
});

// ══════════════════════════════════════════════════════════════
// CLIENT ROUTES
// ══════════════════════════════════════════════════════════════

// List all clients (I5: pagination support)
app.get('/api/clients', requireLogin, async (req, res) => {
  try {
    const limit = req.query.limit ? Math.min(parseInt(req.query.limit), 200) : undefined;
    const offset = req.query.offset ? parseInt(req.query.offset) : undefined;
    const clients = await db.getAllClients(limit, offset);
    res.json({ clients });
  } catch (e) {
    console.error('Get clients error:', e);
    safeError(res, 500, 'Failed to fetch clients');
  }
});

// Get single client
app.get('/api/clients/:id', requireLogin, async (req, res) => {
  try {
    const client = await db.getClient(req.params.id);
    if (!client) return res.status(404).json({ message: 'Client not found' });
    res.json(client);
  } catch (e) {
    safeError(res, 500, 'Failed to fetch client');
  }
});

// Create client
app.post('/api/clients', requireLogin, async (req, res) => {
  try {
    const { company, type, contactName } = req.body;
    if (!company || !contactName) {
      return res.status(400).json({ message: 'Company and contact name are required' });
    }
    // Validate email if provided
    if (req.body.contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(req.body.contactEmail)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    // I2: Input length validation
    const validation = validateInputLengths(req.body);
    if (!validation.valid) {
      return res.status(400).json({ message: `Field ${validation.field} exceeds ${validation.limit} characters` });
    }
    const client = await db.createClient(req.body);
    await db.createActivity({ clientId: client.id, userId: req.session.userId, action: 'created new client', details: company });
    res.json(client);
  } catch (e) {
    console.error('Create client error:', e);
    safeError(res, 500, 'Failed to create client');
  }
});

// Update client
app.put('/api/clients/:id', requireLogin, async (req, res) => {
  try {
    const existing = await db.getClient(req.params.id);
    if (!existing) return res.status(404).json({ message: 'Client not found' });
    if (req.body.contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(req.body.contactEmail)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    // I2: Input length validation
    const validation = validateInputLengths(req.body);
    if (!validation.valid) {
      return res.status(400).json({ message: `Field ${validation.field} exceeds ${validation.limit} characters` });
    }
    const client = await db.updateClient(req.params.id, req.body);
    await db.createActivity({ clientId: client.id, userId: req.session.userId, action: 'updated client details', details: '' });
    res.json(client);
  } catch (e) {
    console.error('Update client error:', e);
    safeError(res, 500, 'Failed to update client');
  }
});

// Delete client
app.delete('/api/clients/:id', requireLogin, async (req, res) => {
  try {
    const existing = await db.getClient(req.params.id);
    if (!existing) return res.status(404).json({ message: 'Client not found' });
    await db.createActivity({ clientId: null, userId: req.session.userId, action: `deleted client "${existing.company}"`, details: '' });
    await db.deleteClient(req.params.id);
    res.json({ success: true });
  } catch (e) {
    console.error('Delete client error:', e);
    safeError(res, 500, 'Failed to delete client');
  }
});

// ══════════════════════════════════════════════════════════════
// STEP NAME LOOKUP (maps step IDs like "p1s3" to readable names)
// ══════════════════════════════════════════════════════════════
const STEP_NAMES = {
  p1s1: 'Lead Qualification', p1s2: 'Discovery Call', p1s3: 'Follow-Up & Demo Scheduling',
  p1s4: 'Tailored Product Demo', p1s5: 'Proposal & Objection Handling', p1s6: 'Contract Signed & Deal Closed',
  g1: 'GATE 1: Sales → Onboarding',
  p2s1: 'Welcome Email & Info Packet', p2s2: 'Onboarding Kick-Off Call', p2s3: 'Technology Stack Inventory',
  p2s4: 'API Credentials & Access', p2s5: 'Workflow & Contract Docs', p2s6: 'Agent Roster Collection',
  p2s7: 'Data Migration Planning', p2s8: 'Data Package Assembly', p2s9: 'Pre-Config Internal Sync',
  p2s10: 'Data Package Handoff',
  g2: 'GATE 2: Onboarding → Technical',
  p3s1: 'Tenant Creation & Provisioning', p3s2: 'Workflow & Field Configuration', p3s3: 'Integration Setup',
  p3s4: 'Internal Testing & QA', g3: 'GATE 3: Config → UAT', p3s5: 'Client UAT',
  g4: 'GATE 4: UAT → Training', p3s6: 'Training Sessions', g5: 'GATE 5: Training → Go-Live',
  p3s7: 'GO-LIVE & Supported Launch', p3s8: 'Agent Adoption Tracking', p3s9: 'Post-Launch Support',
  p3s10: 'ROI & Success Metrics Review',
  g6: 'GATE 6: Go-Live → Steady-State'
};
function stepName(id) { return STEP_NAMES[id] || id; }

// ══════════════════════════════════════════════════════════════
// STEP ROUTES
// ══════════════════════════════════════════════════════════════

// Update step status
app.put('/api/clients/:clientId/steps/:stepId', requireLogin, async (req, res) => {
  try {
    const client = await db.getClient(req.params.clientId);
    if (!client) return res.status(404).json({ message: 'Client not found' });
    const { status, note } = req.body;
    if (status && !['pending', 'in_progress', 'completed', 'blocked'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }
    const result = await db.upsertStep(req.params.clientId, req.params.stepId, {
      status: status || 'pending',
      note: note !== undefined ? note : undefined,
      completedBy: req.session.userId
    });
    // Log activity
    await db.createActivity({
      clientId: req.params.clientId,
      userId: req.session.userId,
      action: `marked "${stepName(req.params.stepId)}" as ${status.replace('_', ' ')}`,
      details: ''
    });
    res.json(result);
  } catch (e) {
    console.error('Update step error:', e);
    safeError(res, 500, 'Failed to update step');
  }
});

// Save step note only
app.put('/api/clients/:clientId/steps/:stepId/note', requireLogin, async (req, res) => {
  try {
    const client = await db.getClient(req.params.clientId);
    if (!client) return res.status(404).json({ message: 'Client not found' });
    const { note } = req.body;
    // Get current step status
    const steps = await db.getClientSteps(req.params.clientId);
    const current = steps[req.params.stepId] || { status: 'pending' };
    const result = await db.upsertStep(req.params.clientId, req.params.stepId, {
      status: current.status,
      note: note || '',
      completedBy: current.completedBy || req.session.userId
    });
    if (note) {
      await db.createActivity({
        clientId: req.params.clientId,
        userId: req.session.userId,
        action: `added note to "${stepName(req.params.stepId)}"`,
        details: (note || '').substring(0, 80)
      });
    }
    res.json(result);
  } catch (e) {
    safeError(res, 500, 'Failed to save note');
  }
});

// Add link to step
app.post('/api/clients/:clientId/steps/:stepId/links', requireLogin, async (req, res) => {
  try {
    const client = await db.getClient(req.params.clientId);
    if (!client) return res.status(404).json({ message: 'Client not found' });
    const { url, label } = req.body;
    if (!url || typeof url !== 'string' || url.length > 2000) {
      return res.status(400).json({ message: 'Valid URL is required (max 2000 chars)' });
    }
    if (label && label.length > 200) {
      return res.status(400).json({ message: 'Label must be under 200 characters' });
    }
    const link = await db.addStepLink(req.params.clientId, req.params.stepId, {
      url: url.trim(),
      label: (label || '').trim(),
      addedBy: req.session.userId
    });
    await db.createActivity({
      clientId: req.params.clientId,
      userId: req.session.userId,
      action: `attached link to "${stepName(req.params.stepId)}"`,
      details: (label || url).substring(0, 80)
    });
    res.json(link);
  } catch (e) {
    console.error('Add link error:', e);
    safeError(res, 500, 'Failed to add link');
  }
});

// Set/clear client action note on a step
app.put('/api/clients/:clientId/steps/:stepId/client-action', requireLogin, async (req, res) => {
  try {
    const client = await db.getClient(req.params.clientId);
    if (!client) return res.status(404).json({ message: 'Client not found' });
    const { note } = req.body;
    if (note && typeof note === 'string' && note.length > 500) {
      return res.status(400).json({ message: 'Action note must be under 500 characters' });
    }
    const result = await db.setClientActionNote(req.params.clientId, req.params.stepId, note || '');
    // Log activity
    const actionText = note
      ? `requested client action on "${stepName(req.params.stepId)}"`
      : `cleared client action on "${stepName(req.params.stepId)}"`;
    await db.createActivity({
      clientId: req.params.clientId,
      userId: req.session.userId,
      action: actionText,
      details: (note || '').substring(0, 80)
    });
    // Fire-and-forget: send email notification to client if note is being set (not cleared)
    if (note && client.contactEmail) {
      const portalUrl = `${req.protocol}://${req.get('host')}/portal.html`;
      email.sendClientActionEmail({
        toEmail: client.contactEmail,
        toName: client.contactName,
        company: client.company,
        stepName: stepName(req.params.stepId),
        actionNote: note,
        portalUrl
      }).catch(err => console.error('Email notification failed:', err));
    }
    res.json(result);
  } catch (e) {
    console.error('Set client action error:', e);
    safeError(res, 500, 'Failed to set client action');
  }
});

// Remove link from step
app.delete('/api/clients/:clientId/steps/:stepId/links/:linkId', requireLogin, async (req, res) => {
  try {
    const client = await db.getClient(req.params.clientId);
    if (!client) return res.status(404).json({ message: 'Client not found' });
    await db.removeStepLink(req.params.clientId, req.params.stepId, req.params.linkId);
    res.json({ success: true });
  } catch (e) {
    safeError(res, 500, 'Failed to remove link');
  }
});

// ══════════════════════════════════════════════════════════════
// TEAM ROUTES
// ══════════════════════════════════════════════════════════════

app.get('/api/team', requireLogin, async (req, res) => {
  try {
    const team = await db.getAllUsers();
    res.json({ team });
  } catch (e) {
    safeError(res, 500, 'Failed to fetch team');
  }
});

app.post('/api/team', requireLogin, async (req, res) => {
  try {
    const { name, role } = req.body;
    if (!name) return res.status(400).json({ message: 'Name is required' });
    // I2: Input length validation
    const validation = validateInputLengths(req.body);
    if (!validation.valid) {
      return res.status(400).json({ message: `Field ${validation.field} exceeds ${validation.limit} characters` });
    }
    const member = await db.createUser(req.body);
    await db.createActivity({ clientId: null, userId: req.session.userId, action: `added ${req.body.type || 'member'} "${name}" (${role})`, details: '' });
    res.json(member);
  } catch (e) {
    console.error('Create team member error:', e);
    safeError(res, 500, 'Failed to add team member');
  }
});

// Delete team member
app.delete('/api/team/:id', requireLogin, async (req, res) => {
  try {
    const user = await db.getUser(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.isDefault) return res.status(400).json({ message: 'Cannot delete default team members' });
    await db.createActivity({ clientId: null, userId: req.session.userId, action: `removed team member "${user.name}"`, details: '' });
    await db.deleteUser(req.params.id);
    res.json({ success: true });
  } catch (e) {
    safeError(res, 500, 'Failed to remove team member');
  }
});

// ══════════════════════════════════════════════════════════════
// ACTIVITY ROUTES
// ══════════════════════════════════════════════════════════════

app.get('/api/activities', requireLogin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 60, 200);
    const offset = parseInt(req.query.offset) || 0;
    const activities = await db.getActivities(limit, offset);
    res.json({ activities });
  } catch (e) {
    safeError(res, 500, 'Failed to fetch activities');
  }
});

// Delete activities
app.delete('/api/activities', requireLogin, async (req, res) => {
  try {
    await db.clearActivities();
    res.json({ success: true });
  } catch (e) {
    safeError(res, 500, 'Failed to clear activities');
  }
});

// ══════════════════════════════════════════════════════════════
// ONBOARDING FORM ROUTES (public, token-based access)
// ══════════════════════════════════════════════════════════════

// Rate limit for form submissions
const onboardingLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: 'Too many requests' });

// Get client info + form state by token (public)
app.get('/api/onboarding/:token', onboardingLimiter, async (req, res) => {
  try {
    const client = await db.getClientByToken(req.params.token);
    if (!client) return res.status(404).json({ message: 'Invalid or expired onboarding link' });
    const submission = await db.getOnboardingSubmission(client.id);
    res.json({
      client: { id: client.id, company: client.company, contactName: client.contactName, contactEmail: client.contactEmail, googleDriveUrl: client.googleDriveUrl },
      submission: submission ? { formData: submission.formData, status: submission.status, submittedAt: submission.submittedAt } : null
    });
  } catch (e) {
    console.error('Get onboarding error:', e);
    safeError(res, 500, 'Failed to load form');
  }
});

// Save/submit onboarding form (public, token-based)
app.post('/api/onboarding/:token', onboardingLimiter, async (req, res) => {
  try {
    const client = await db.getClientByToken(req.params.token);
    if (!client) return res.status(404).json({ message: 'Invalid or expired onboarding link' });
    const { formData, status } = req.body;
    if (!formData || typeof formData !== 'object') return res.status(400).json({ message: 'Form data required' });
    const validStatuses = ['in_progress', 'submitted'];
    if (!validStatuses.includes(status)) return res.status(400).json({ message: 'Invalid status' });

    const submission = await db.saveOnboardingSubmission(client.id, formData, status);

    // If submitted, log activity and update relevant step
    if (status === 'submitted') {
      await db.createActivity({ clientId: client.id, userId: 'client', action: 'submitted onboarding form', details: client.company });
    }

    res.json({ success: true, submission });
  } catch (e) {
    console.error('Save onboarding error:', e);
    safeError(res, 500, 'Failed to save form');
  }
});

// Generate onboarding token for a client (internal, requires auth)
app.post('/api/clients/:id/onboarding-token', requireLogin, async (req, res) => {
  try {
    const client = await db.getClient(req.params.id);
    if (!client) return res.status(404).json({ message: 'Client not found' });
    const token = await db.generateOnboardingToken(req.params.id);
    await db.createActivity({ clientId: req.params.id, userId: req.session.userId, action: 'generated onboarding form link', details: client.company });
    res.json({ token, url: `${req.protocol}://${req.get('host')}/onboarding.html?token=${token}` });
  } catch (e) {
    console.error('Generate token error:', e);
    safeError(res, 500, 'Failed to generate link');
  }
});

// Get onboarding submission for a client (internal)
app.get('/api/clients/:id/onboarding', requireLogin, async (req, res) => {
  try {
    const submission = await db.getOnboardingSubmission(req.params.id);
    res.json({ submission });
  } catch (e) {
    safeError(res, 500, 'Failed to fetch submission');
  }
});

// ══════════════════════════════════════════════════════════════
// CLIENT PORTAL ROUTES (requires auth, scoped to client's own data)
// ══════════════════════════════════════════════════════════════

// Get portal data for logged-in client
app.get('/api/portal/me', requireLogin, async (req, res) => {
  try {
    const user = await db.getUser(req.session.userId);
    if (!user) return res.status(401).json({ message: 'User not found' });
    // Find client record matching this user's email
    const client = await db.getClientByContactEmail(user.email);
    if (!client) return res.status(404).json({ message: 'No client record found for your email' });
    const submission = await db.getOnboardingSubmission(client.id);
    res.json({
      user: { name: user.name, email: user.email },
      client: {
        id: client.id, company: client.company, type: client.type,
        contactName: client.contactName, contactEmail: client.contactEmail,
        status: client.status, onboardingStatus: client.onboardingStatus,
        googleDriveUrl: client.googleDriveUrl, targetGoLive: client.targetGoLive,
        onboardingToken: client.onboardingToken
      },
      steps: client.steps,
      submission: submission ? { formData: submission.formData, status: submission.status, submittedAt: submission.submittedAt } : null
    });
  } catch (e) {
    console.error('Portal error:', e);
    safeError(res, 500, 'Failed to load portal');
  }
});

// Client responds to an action request from their portal
app.post('/api/portal/respond', requireLogin, async (req, res) => {
  try {
    const user = await db.getUser(req.session.userId);
    if (!user) return res.status(401).json({ message: 'User not found' });
    const client = await db.getClientByContactEmail(user.email);
    if (!client) return res.status(404).json({ message: 'No client record found' });
    const { stepId, response } = req.body;
    if (!stepId || typeof stepId !== 'string') return res.status(400).json({ message: 'Step ID required' });
    if (!response || typeof response !== 'string' || response.trim().length === 0) {
      return res.status(400).json({ message: 'Response text required' });
    }
    if (response.length > 1000) return res.status(400).json({ message: 'Response must be under 1000 characters' });
    // Verify the step actually has an action note
    const stepData = client.steps[stepId];
    if (!stepData || !stepData.clientActionNote) {
      return res.status(400).json({ message: 'No action request on this step' });
    }
    const result = await db.setClientActionResponse(client.id, stepId, response.trim());
    // Log activity — use actual logged-in user's ID
    await db.createActivity({
      clientId: client.id,
      userId: req.session.userId,
      action: `client responded to action on "${stepName(stepId)}"`,
      details: (response.trim()).substring(0, 80)
    });
    res.json({ success: true, ...result });
  } catch (e) {
    console.error('Portal respond error:', e);
    safeError(res, 500, 'Failed to save response');
  }
});

// ══════════════════════════════════════════════════════════════
// ADMIN SETTINGS ROUTES
// ══════════════════════════════════════════════════════════════

// Get all email settings (admin only, masks API key)
app.get('/api/settings', requireAdmin, async (req, res) => {
  try {
    const settings = await db.getAllSettings();
    // Mask the API key — only show last 4 characters
    if (settings.sendgrid_api_key) {
      const key = settings.sendgrid_api_key;
      settings.sendgrid_api_key = key.length > 4
        ? '••••••••••••' + key.slice(-4)
        : '••••';
    }
    res.json({ settings });
  } catch (e) {
    console.error('Get settings error:', e);
    safeError(res, 500, 'Failed to fetch settings');
  }
});

// Update a setting (admin only)
app.put('/api/settings', requireAdmin, async (req, res) => {
  try {
    const { key, value } = req.body;
    if (!key || typeof key !== 'string') {
      return res.status(400).json({ message: 'Setting key is required' });
    }
    // Only allow specific keys
    const allowedKeys = ['sendgrid_api_key', 'email_from_address', 'email_from_name', 'email_enabled'];
    if (!allowedKeys.includes(key)) {
      return res.status(400).json({ message: 'Invalid setting key' });
    }
    // Validate values
    if (key === 'email_from_address' && value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
      return res.status(400).json({ message: 'Invalid email address format' });
    }
    if (key === 'email_enabled' && !['true', 'false'].includes(value)) {
      return res.status(400).json({ message: 'email_enabled must be "true" or "false"' });
    }
    if (key === 'sendgrid_api_key' && value && value.startsWith('••••')) {
      // User submitted the masked value — don't overwrite the real key
      return res.json({ success: true, message: 'API key unchanged (masked value detected)' });
    }
    const result = await db.setSetting(key, value || '');
    await db.createActivity({
      clientId: null,
      userId: req.session.userId,
      action: `updated setting "${key}"`,
      details: key === 'sendgrid_api_key' ? '(API key updated)' : (value || '').substring(0, 80)
    });
    res.json({ success: true, ...result });
  } catch (e) {
    console.error('Update setting error:', e);
    safeError(res, 500, 'Failed to update setting');
  }
});

// Send test email (admin only)
app.post('/api/settings/test-email', requireAdmin, async (req, res) => {
  try {
    const { toEmail } = req.body;
    if (!toEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(toEmail)) {
      return res.status(400).json({ message: 'Valid email address required' });
    }
    const result = await email.sendTestEmail(toEmail);
    if (result.success) {
      res.json({ success: true, message: `Test email sent to ${toEmail}` });
    } else {
      res.status(400).json({ success: false, message: result.error || 'Failed to send test email' });
    }
  } catch (e) {
    console.error('Test email error:', e);
    safeError(res, 500, 'Failed to send test email');
  }
});

// ══════════════════════════════════════════════════════════════
// BACKUP ROUTES
// ══════════════════════════════════════════════════════════════

// Export backup (JSON)
app.get('/api/backup/export', requireLogin, async (req, res) => {
  try {
    const data = await db.exportAll();
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="ReBillion_PM_Backup_${new Date().toISOString().slice(0,10)}.json"`);
    res.json(data);
  } catch (e) {
    safeError(res, 500, 'Export failed');
  }
});

// Export backup (Excel .xlsx)
app.get('/api/backup/export-xlsx', requireLogin, async (req, res) => {
  try {
    const data = await db.exportAll();
    const wb = XLSX.utils.book_new();

    // ── Clients Sheet ──
    const clientRows = (data.clients || []).map(c => ({
      'Company': c.company || '',
      'Type': c.type === 'tc_company' ? 'TC Company' : 'Brokerage',
      'Contact Name': c.contactName || c.contact_name || '',
      'Contact Email': c.contactEmail || c.contact_email || '',
      'Scenario': (c.scenario || '').replace(/-/g, ' '),
      'Sales Lead': c.salesLead || c.sales_lead_id || '',
      'Onboarding Lead': c.onboardingLead || c.onboarding_lead_id || '',
      'Txns/Month': c.txns || '',
      'Target Go-Live': c.targetGoLive || c.target_go_live || '',
      'Status': (c.status || '').replace('_', ' '),
      'Notes': c.notes || '',
      'Created': c.createdAt || c.created_at || ''
    }));
    const wsClients = XLSX.utils.json_to_sheet(clientRows.length ? clientRows : [{ 'Company': '(no data)' }]);
    // Set column widths
    wsClients['!cols'] = [
      { wch: 25 }, { wch: 14 }, { wch: 20 }, { wch: 28 }, { wch: 18 },
      { wch: 15 }, { wch: 18 }, { wch: 12 }, { wch: 14 }, { wch: 12 }, { wch: 40 }, { wch: 20 }
    ];
    XLSX.utils.book_append_sheet(wb, wsClients, 'Clients');

    // ── Checklist/Steps Sheet ──
    const stepRows = [];
    for (const c of (data.clients || [])) {
      const steps = c.steps || {};
      for (const [stepId, stepData] of Object.entries(steps)) {
        stepRows.push({
          'Company': c.company || '',
          'Step': stepName(stepId),
          'Status': (stepData.status || 'pending').replace('_', ' '),
          'Note': stepData.note || '',
          'Completed Date': stepData.completedDate || stepData.completed_date || '',
          'Completed By': stepData.completedBy || stepData.completed_by || ''
        });
      }
    }
    const wsSteps = XLSX.utils.json_to_sheet(stepRows.length ? stepRows : [{ 'Company': '(no data)' }]);
    wsSteps['!cols'] = [{ wch: 25 }, { wch: 35 }, { wch: 14 }, { wch: 40 }, { wch: 20 }, { wch: 15 }];
    XLSX.utils.book_append_sheet(wb, wsSteps, 'Checklist');

    // ── Team Sheet ──
    const teamRows = (data.team || []).map(t => ({
      'Name': t.name || '',
      'Role': t.role || '',
      'Email': t.email || '',
      'Type': t.type || '',
      'Default': t.isDefault || t.is_default ? 'Yes' : 'No'
    }));
    const wsTeam = XLSX.utils.json_to_sheet(teamRows.length ? teamRows : [{ 'Name': '(no data)' }]);
    wsTeam['!cols'] = [{ wch: 20 }, { wch: 20 }, { wch: 30 }, { wch: 12 }, { wch: 10 }];
    XLSX.utils.book_append_sheet(wb, wsTeam, 'Team');

    // Build lookup maps for readable names in Activities
    const userMap = {};
    for (const t of (data.team || [])) { userMap[t.id] = t.name; }
    const clientMap = {};
    for (const c of (data.clients || [])) { clientMap[c.id] = c.company; }

    // Also resolve Sales Lead and Onboarding Lead names in Clients sheet
    for (const row of clientRows) {
      if (row['Sales Lead'] && userMap[row['Sales Lead']]) row['Sales Lead'] = userMap[row['Sales Lead']];
      if (row['Onboarding Lead'] && userMap[row['Onboarding Lead']]) row['Onboarding Lead'] = userMap[row['Onboarding Lead']];
    }
    // Rebuild Clients sheet with resolved names
    const wsClientsResolved = XLSX.utils.json_to_sheet(clientRows.length ? clientRows : [{ 'Company': '(no data)' }]);
    wsClientsResolved['!cols'] = wsClients['!cols'];
    wb.Sheets['Clients'] = wsClientsResolved;

    // Also resolve Completed By in Steps sheet
    for (const row of stepRows) {
      if (row['Completed By'] && userMap[row['Completed By']]) row['Completed By'] = userMap[row['Completed By']];
    }
    const wsStepsResolved = XLSX.utils.json_to_sheet(stepRows.length ? stepRows : [{ 'Company': '(no data)' }]);
    wsStepsResolved['!cols'] = wsSteps['!cols'];
    wb.Sheets['Checklist'] = wsStepsResolved;

    // ── Activities Sheet ──
    const actRows = (data.activities || []).slice(0, 500).map(a => ({
      'User': userMap[a.user_id] || a.user_id || '',
      'Action': a.action || '',
      'Details': a.details || '',
      'Client': clientMap[a.client_id] || a.client_id || '',
      'Timestamp': a.timestamp || ''
    }));
    const wsAct = XLSX.utils.json_to_sheet(actRows.length ? actRows : [{ 'User': '(no data)' }]);
    wsAct['!cols'] = [{ wch: 15 }, { wch: 35 }, { wch: 40 }, { wch: 25 }, { wch: 22 }];
    XLSX.utils.book_append_sheet(wb, wsAct, 'Activities');

    // Generate buffer and send
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    const filename = `ReBillion_PM_Backup_${new Date().toISOString().slice(0,10)}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(Buffer.from(buf));
  } catch (e) {
    console.error('Excel export error:', e);
    safeError(res, 500, 'Excel export failed');
  }
});

// Import backup (JSON)
app.post('/api/backup/import', requireLogin, async (req, res) => {
  try {
    const result = await db.importAll(req.body);
    await db.createActivity({ clientId: null, userId: req.session.userId, action: 'imported data backup', details: `${result.clients} clients, ${result.team} team members` });
    res.json({ success: true, imported: result });
  } catch (e) {
    console.error('Import error:', e);
    safeError(res, 400, 'Import failed');
  }
});

// Import backup (Excel .xlsx)
app.post('/api/backup/import-xlsx', requireLogin, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

    const wb = XLSX.read(req.file.buffer, { type: 'buffer' });

    // Parse Clients sheet
    const clientsSheet = wb.Sheets['Clients'];
    const clientsRaw = clientsSheet ? XLSX.utils.sheet_to_json(clientsSheet) : [];

    // Parse Team sheet
    const teamSheet = wb.Sheets['Team'];
    const teamRaw = teamSheet ? XLSX.utils.sheet_to_json(teamSheet) : [];

    // Parse Activities sheet
    const actSheet = wb.Sheets['Activities'];
    const actRaw = actSheet ? XLSX.utils.sheet_to_json(actSheet) : [];

    // Parse Checklist/Steps sheet
    const stepsSheet = wb.Sheets['Checklist'];
    const stepsRaw = stepsSheet ? XLSX.utils.sheet_to_json(stepsSheet) : [];

    // Build a steps map grouped by company
    const stepsMap = {};
    for (const row of stepsRaw) {
      const company = row['Company'] || '';
      if (!stepsMap[company]) stepsMap[company] = {};
      stepsMap[company][row['Step ID']] = {
        status: (row['Status'] || 'pending').replace(' ', '_'),
        note: row['Note'] || '',
        completedDate: row['Completed Date'] || null,
        completedBy: row['Completed By'] || null
      };
    }

    // Convert to import format
    const clients = clientsRaw.filter(r => r['Company'] && r['Company'] !== '(no data)').map(r => ({
      id: 'id_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 7),
      company: r['Company'] || '',
      type: (r['Type'] || '').toLowerCase().includes('tc') ? 'tc_company' : 'brokerage',
      contactName: r['Contact Name'] || '',
      contactEmail: r['Contact Email'] || '',
      scenario: (r['Scenario'] || 'single office').replace(/\s+/g, '-'),
      salesLead: r['Sales Lead'] || null,
      onboardingLead: r['Onboarding Lead'] || null,
      txns: r['Txns/Month'] ? parseInt(r['Txns/Month'], 10) : null,
      targetGoLive: r['Target Go-Live'] || null,
      notes: r['Notes'] || '',
      status: (r['Status'] || 'active').replace(' ', '_'),
      steps: stepsMap[r['Company']] || {}
    }));

    const team = teamRaw.filter(r => r['Name'] && r['Name'] !== '(no data)').map(r => ({
      id: 'id_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 7),
      name: r['Name'] || '',
      role: r['Role'] || 'Observer',
      email: r['Email'] || '',
      type: (r['Type'] || 'member').toLowerCase(),
      isDefault: (r['Default'] || '').toLowerCase() === 'yes'
    }));

    const importData = { clients, team, activities: [] };
    const result = await db.importAll(importData);
    await db.createActivity({ clientId: null, userId: req.session.userId, action: 'imported Excel backup', details: `${result.clients} clients, ${result.team} team members` });
    res.json({ success: true, imported: result });
  } catch (e) {
    console.error('Excel import error:', e);
    safeError(res, 400, 'Excel import failed: ' + e.message);
  }
});

// ══════════════════════════════════════════════════════════════
// EXPORT APP FOR VERCEL
// ══════════════════════════════════════════════════════════════
module.exports = app;

// ══════════════════════════════════════════════════════════════
// START SERVER (Local development only)
// ══════════════════════════════════════════════════════════════
// Only start the server if not running on Vercel (which uses serverless functions)
if (!process.env.VERCEL) {
  async function start() {
    try {
      await db.init();
      const server = app.listen(PORT, () => {
        console.log(`\n  ReBillion PM Server running at http://localhost:${PORT}\n`);
        console.log('  Default logins (username / password):');
        console.log('    Lisa  / lisa');
        console.log('    Vikas / vikas');
        console.log('    Julie / julie');
        console.log('    Eddy  / eddy');
        console.log('    Atul  / atul\n');
      });

      // I7: Graceful shutdown on SIGTERM/SIGINT
      process.on('SIGTERM', async () => {
        console.log('SIGTERM received, shutting down gracefully...');
        await db.flushAndShutdown();
        server.close(() => {
          console.log('Server closed');
          process.exit(0);
        });
      });

      process.on('SIGINT', async () => {
        console.log('SIGINT received, shutting down gracefully...');
        await db.flushAndShutdown();
        server.close(() => {
          console.log('Server closed');
          process.exit(0);
        });
      });
    } catch (e) {
      console.error('Failed to start server:', e);
      process.exit(1);
    }
  }

  start();
}
