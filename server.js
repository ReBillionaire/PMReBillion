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
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

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

      // Check if email is @rebillion.ai domain
      const isRebillionEmail = email.endsWith('@rebillion.ai');

      // Create new user
      const newUser = await db.findOrCreateGoogleUser({
        email: email,
        name: profile.displayName || email.split('@')[0],
        type: isRebillionEmail ? 'member' : 'observer',
        role: isRebillionEmail ? 'team member' : 'observer'
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

// C9: Helmet security headers
app.use(helmet());

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
  // Exempt auth endpoints that don't have a CSRF token yet
  if (req.path === '/api/auth/login' ||
      req.path === '/api/auth/logout' ||
      req.path === '/auth/google/callback') {
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

// C5: Serve static files (except app.html and app.js which need auth)
const publicDir = path.join(__dirname, 'public');
app.use((req, res, next) => {
  if (req.path === '/app.html' || req.path === '/app.js') {
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

// Get CSRF token (for C4)
app.get('/api/csrf-token', requireLogin, (req, res) => {
  res.json({ token: res.locals.csrfToken });
});

// Google OAuth routes (only if configured)
if (googleAuthEnabled) {
  app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

  app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login.html?error=auth_failed' }),
    async (req, res) => {
      // Successful authentication, redirect to app
      req.session.userId = req.user.id;
      await new Promise((resolve, reject) => {
        req.session.save((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      res.redirect('/app.html');
    }
  );
} else {
  app.get('/auth/google', (req, res) => {
    res.redirect('/login.html?error=auth_failed');
  });
}

// Login (C6: rate limited)
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }
    const user = await db.getUserByName(username.trim());
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    req.session.userId = user.id;
    // Explicitly save session before responding (critical for serverless)
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    res.json({
      success: true,
      user: { id: user.id, name: user.name, role: user.role, email: user.email, color: user.color, type: user.type },
      csrfToken: res.locals.csrfToken
    });
  } catch (e) {
    console.error('Login error:', e);
    safeError(res, 500, 'Server error');
  }
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

// Delete client (I1: admin only)
app.delete('/api/clients/:id', requireLogin, requireAdmin, async (req, res) => {
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
      action: `marked "${req.params.stepId}" as ${status.replace('_', ' ')}`,
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
        action: `added note to "${req.params.stepId}"`,
        details: (note || '').substring(0, 80)
      });
    }
    res.json(result);
  } catch (e) {
    safeError(res, 500, 'Failed to save note');
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

// Delete team member (I1: admin only)
app.delete('/api/team/:id', requireLogin, requireAdmin, async (req, res) => {
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

// Delete activities (I1: admin only)
app.delete('/api/activities', requireLogin, requireAdmin, async (req, res) => {
  try {
    await db.clearActivities();
    res.json({ success: true });
  } catch (e) {
    safeError(res, 500, 'Failed to clear activities');
  }
});

// ══════════════════════════════════════════════════════════════
// BACKUP ROUTES
// ══════════════════════════════════════════════════════════════

// Export backup (I9: admin only)
app.get('/api/backup/export', requireLogin, requireAdmin, async (req, res) => {
  try {
    const data = await db.exportAll();
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="ReBillion_PM_Backup_${new Date().toISOString().slice(0,10)}.json"`);
    res.json(data);
  } catch (e) {
    safeError(res, 500, 'Export failed');
  }
});

// Import backup (I1: admin only)
app.post('/api/backup/import', requireLogin, requireAdmin, async (req, res) => {
  try {
    const result = await db.importAll(req.body);
    await db.createActivity({ clientId: null, userId: req.session.userId, action: 'imported data backup', details: `${result.clients} clients, ${result.team} team members` });
    res.json({ success: true, imported: result });
  } catch (e) {
    console.error('Import error:', e);
    safeError(res, 400, 'Import failed');
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
