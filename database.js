// ══════════════════════════════════════════════════════════════
// ReBillion PM — Database Layer (PostgreSQL + Vercel Postgres)
// ══════════════════════════════════════════════════════════════
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// PostgreSQL connection pool - created lazily on first access
let pool = null;

function getPool() {
  if (!pool) {
    const connectionString = process.env.POSTGRES_URL;
    if (!connectionString) {
      throw new Error('POSTGRES_URL environment variable not set');
    }
    pool = new Pool({
      connectionString,
      ssl: process.env.NODE_ENV === 'production' || process.env.VERCEL ? { rejectUnauthorized: false } : false
    });
  }
  return pool;
}

const SCHEMA_VERSION = 1;

// ── Helpers ──
function uid() { return crypto.randomUUID(); }
function now() { return new Date().toISOString(); }

// ══════════════════════════════════════════════════════════════
// INITIALIZE DATABASE
// ══════════════════════════════════════════════════════════════
async function init() {
  getPool(); // Ensure pool is initialized

  // Test connection
  const client = await pool.connect();
  try {
    await client.query('SELECT NOW()');
    console.log('Successfully connected to PostgreSQL database');
  } finally {
    client.release();
  }

  // Create tables
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      role TEXT NOT NULL,
      email TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      color TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'member',
      is_default INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS clients (
      id TEXT PRIMARY KEY,
      company TEXT NOT NULL,
      type TEXT NOT NULL,
      contact_name TEXT NOT NULL,
      contact_email TEXT,
      scenario TEXT,
      sales_lead_id TEXT,
      onboarding_lead_id TEXT,
      txns INTEGER,
      target_go_live TEXT,
      notes TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS client_steps (
      client_id TEXT NOT NULL,
      step_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      note TEXT DEFAULT '',
      links TEXT DEFAULT '[]',
      completed_date TEXT,
      completed_by TEXT,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (client_id, step_id)
    )
  `);

  // Migration: add links column if missing (for existing databases)
  try {
    await pool.query(`ALTER TABLE client_steps ADD COLUMN IF NOT EXISTS links TEXT DEFAULT '[]'`);
  } catch (e) {
    // Column may already exist, ignore
  }

  // Migration: add client_action_note column (for client-facing action requests)
  try {
    await pool.query(`ALTER TABLE client_steps ADD COLUMN IF NOT EXISTS client_action_note TEXT DEFAULT ''`);
  } catch (e) {
    // Column may already exist, ignore
  }

  // Migration: add client response columns (for client replies to action requests)
  try {
    await pool.query(`ALTER TABLE client_steps ADD COLUMN IF NOT EXISTS client_action_response TEXT DEFAULT ''`);
  } catch (e) {}
  try {
    await pool.query(`ALTER TABLE client_steps ADD COLUMN IF NOT EXISTS client_action_responded_at TEXT`);
  } catch (e) {}

  await pool.query(`
    CREATE TABLE IF NOT EXISTS activities (
      id TEXT PRIMARY KEY,
      client_id TEXT,
      user_id TEXT NOT NULL,
      action TEXT NOT NULL,
      details TEXT DEFAULT '',
      timestamp TEXT NOT NULL
    )
  `);

  // Onboarding submissions table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS onboarding_submissions (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      form_data TEXT NOT NULL DEFAULT '{}',
      status TEXT NOT NULL DEFAULT 'not_started',
      submitted_at TEXT,
      updated_at TEXT NOT NULL
    )
  `);

  // Migration: add onboarding columns to clients if missing
  try { await pool.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS onboarding_token TEXT`); } catch(e) {}
  try { await pool.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS onboarding_status TEXT DEFAULT 'not_started'`); } catch(e) {}
  try { await pool.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS google_drive_url TEXT DEFAULT ''`); } catch(e) {}

  // Create indices
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_client_steps_client ON client_steps(client_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_activities_client ON activities(client_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_activities_ts ON activities(timestamp DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
  try { await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_onboarding_token ON clients(onboarding_token) WHERE onboarding_token IS NOT NULL`); } catch(e) {}

  // Seed default users if empty
  const result = await pool.query('SELECT COUNT(*) as c FROM users');
  const userCount = parseInt(result.rows[0].c) || 0;
  if (userCount === 0) {
    await seedDefaultUsers();
  }

  // Migration: update default user emails to match Google OAuth accounts
  await migrateUserEmails();

  // Seed example clients if empty
  const clientResult = await pool.query('SELECT COUNT(*) as c FROM clients');
  const clientCount = parseInt(clientResult.rows[0].c) || 0;
  if (clientCount === 0) {
    await seedExampleClients();
  }

  console.log('Database initialized with PostgreSQL');
  return pool;
}

// ── Graceful shutdown ──
async function flushAndShutdown() {
  if (pool) {
    await pool.end();
    console.log('Database pool closed');
  }
  return true;
}

// ══════════════════════════════════════════════════════════════
// SEED DEFAULT USERS
// ══════════════════════════════════════════════════════════════
async function seedDefaultUsers() {
  const defaults = [
    { id: 't1', name: 'Lisa', role: 'Sales', email: 'lisa@simplyclosed.com', color: '#1565c0' },
    { id: 't2', name: 'Vikas', role: 'Sales', email: 'vikas@garvik.ai', color: '#1976d2' },
    { id: 't3', name: 'Julie', role: 'Onboarding / Account Mgr', email: 'julie@rebillion.ai', color: '#00838f' },
    { id: 't4', name: 'Eddy', role: 'Onboarding / Account Mgr', email: 'eddy@simplyclosed.com', color: '#00897b' },
    { id: 't5', name: 'Atul', role: 'Implementation', email: 'atul@garvik.ai', color: '#2e7d32' }
  ];

  for (const u of defaults) {
    const hash = await bcrypt.hash(u.name.toLowerCase(), 10);
    await pool.query(
      'INSERT INTO users (id, name, role, email, password_hash, color, type, is_default, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
      [u.id, u.name, u.role, u.email, hash, u.color, 'member', 1, now()]
    );
  }
}

// ══════════════════════════════════════════════════════════════
// MIGRATION: UPDATE USER EMAILS FOR GOOGLE OAUTH
// ══════════════════════════════════════════════════════════════
async function migrateUserEmails() {
  // Map default user IDs to their real Google-linked email addresses
  const emailMap = {
    t1: 'lisa@simplyclosed.com',
    t2: 'vikas@garvik.ai',
    // t3 (Julie) stays as julie@rebillion.ai — no Google account configured
    t4: 'eddy@simplyclosed.com',
    t5: 'atul@garvik.ai'
  };

  for (const [userId, newEmail] of Object.entries(emailMap)) {
    const result = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    if (result.rows.length > 0 && result.rows[0].email !== newEmail) {
      await pool.query('UPDATE users SET email = $1 WHERE id = $2', [newEmail, userId]);
      console.log(`Migrated ${userId} email: ${result.rows[0].email} → ${newEmail}`);
    }
  }
}

// ══════════════════════════════════════════════════════════════
// SEED EXAMPLE CLIENTS
// ══════════════════════════════════════════════════════════════
async function seedExampleClients() {
  const ts = now();
  const examples = [
    {
      id: 'c1', company: 'Keller Williams Denver', type: 'Brokerage',
      contactName: 'Sarah Mitchell', contactEmail: 'sarah@kwdenver.com',
      scenario: 'single-office', salesLead: 't1', onboardingLead: 't3',
      txns: 120, targetGoLive: '2026-03-15', notes: 'High priority — CEO wants fast rollout',
      status: 'active'
    },
    {
      id: 'c2', company: 'RE/MAX Pacific Northwest', type: 'Brokerage',
      contactName: 'James Chen', contactEmail: 'jchen@remaxpnw.com',
      scenario: 'multi-office', salesLead: 't2', onboardingLead: 't4',
      txns: 350, targetGoLive: '2026-04-01', notes: '3 offices across WA and OR',
      status: 'active'
    },
    {
      id: 'c3', company: 'Lone Star Title Co', type: 'Title',
      contactName: 'Maria Garcia', contactEmail: 'mgarcia@lonestartitle.com',
      scenario: 'single-office', salesLead: 't1', onboardingLead: 't3',
      txns: 80, targetGoLive: '2026-02-28', notes: 'Already using competitor, switching over',
      status: 'active'
    },
    {
      id: 'c4', company: 'Coldwell Banker Southeast', type: 'Brokerage',
      contactName: 'Robert Taylor', contactEmail: 'rtaylor@cbsoutheast.com',
      scenario: 'multi-office', salesLead: 't2', onboardingLead: 't4',
      txns: 500, targetGoLive: '2026-05-01', notes: 'Enterprise deal — 5 offices in FL and GA',
      status: 'active'
    },
    {
      id: 'c5', company: 'Summit Escrow Services', type: 'Escrow',
      contactName: 'Linda Park', contactEmail: 'lpark@summitescrow.com',
      scenario: 'single-office', salesLead: 't1', onboardingLead: 't3',
      txns: 45, targetGoLive: '2026-03-01', notes: 'Small but growing firm in AZ',
      status: 'active'
    }
  ];

  for (const c of examples) {
    await pool.query(
      `INSERT INTO clients (id, company, type, contact_name, contact_email, scenario, sales_lead_id, onboarding_lead_id, txns, target_go_live, notes, status, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
      [c.id, c.company, c.type, c.contactName, c.contactEmail, c.scenario,
       c.salesLead, c.onboardingLead, c.txns, c.targetGoLive, c.notes, c.status, ts, ts]
    );
  }

  // Add some example steps for the first client to show progress
  const stepExamples = [
    { clientId: 'c1', stepId: 'intro_call', status: 'completed', note: 'Great initial call, very engaged' },
    { clientId: 'c1', stepId: 'needs_assessment', status: 'completed', note: 'Needs MLS integration' },
    { clientId: 'c1', stepId: 'proposal_sent', status: 'completed', note: 'Sent pricing deck' },
    { clientId: 'c1', stepId: 'contract_signed', status: 'completed', note: 'Signed 2-year agreement' },
    { clientId: 'c1', stepId: 'data_collection', status: 'in_progress', note: 'Waiting for agent roster' },
    { clientId: 'c2', stepId: 'intro_call', status: 'completed', note: '' },
    { clientId: 'c2', stepId: 'needs_assessment', status: 'completed', note: 'Complex multi-office setup' },
    { clientId: 'c2', stepId: 'proposal_sent', status: 'in_progress', note: '' },
    { clientId: 'c3', stepId: 'intro_call', status: 'completed', note: '' },
    { clientId: 'c3', stepId: 'needs_assessment', status: 'completed', note: '' },
    { clientId: 'c3', stepId: 'proposal_sent', status: 'completed', note: '' },
    { clientId: 'c3', stepId: 'contract_signed', status: 'completed', note: '' },
    { clientId: 'c3', stepId: 'data_collection', status: 'completed', note: '' },
    { clientId: 'c3', stepId: 'system_config', status: 'in_progress', note: 'Configuring title workflows' },
    { clientId: 'c4', stepId: 'intro_call', status: 'completed', note: '' },
    { clientId: 'c4', stepId: 'needs_assessment', status: 'in_progress', note: 'Scheduling office visits' },
    { clientId: 'c5', stepId: 'intro_call', status: 'completed', note: '' },
    { clientId: 'c5', stepId: 'needs_assessment', status: 'completed', note: '' },
    { clientId: 'c5', stepId: 'proposal_sent', status: 'completed', note: '' },
    { clientId: 'c5', stepId: 'contract_signed', status: 'in_progress', note: 'Legal review in progress' }
  ];

  for (const s of stepExamples) {
    const completedDate = s.status === 'completed' ? ts : null;
    await pool.query(
      `INSERT INTO client_steps (client_id, step_id, status, note, completed_date, completed_by, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [s.clientId, s.stepId, s.status, s.note, completedDate, 't5', ts]
    );
  }

  // Add example activities
  const activityExamples = [
    { clientId: 'c1', userId: 't1', action: 'created new client', details: 'Keller Williams Denver' },
    { clientId: 'c1', userId: 't3', action: 'marked "intro_call" as completed', details: '' },
    { clientId: 'c1', userId: 't3', action: 'marked "contract_signed" as completed', details: '' },
    { clientId: 'c2', userId: 't2', action: 'created new client', details: 'RE/MAX Pacific Northwest' },
    { clientId: 'c3', userId: 't1', action: 'created new client', details: 'Lone Star Title Co' },
    { clientId: 'c4', userId: 't2', action: 'created new client', details: 'Coldwell Banker Southeast' },
    { clientId: 'c5', userId: 't1', action: 'created new client', details: 'Summit Escrow Services' },
    { clientId: 'c3', userId: 't5', action: 'marked "system_config" as in progress', details: '' }
  ];

  for (const a of activityExamples) {
    await pool.query(
      'INSERT INTO activities (id, client_id, user_id, action, details, timestamp) VALUES ($1, $2, $3, $4, $5, $6)',
      [uid(), a.clientId, a.userId, a.action, a.details, ts]
    );
  }

  console.log('Seeded 5 example clients with steps and activities');
}

// ══════════════════════════════════════════════════════════════
// USER QUERIES
// ══════════════════════════════════════════════════════════════
async function getUser(id) {
  const result = await pool.query(
    'SELECT id, name, role, email, color, type, is_default, created_at FROM users WHERE id = $1',
    [id]
  );
  if (!result.rows.length) return null;
  return rowToUser(result.rows[0]);
}

async function getUserByName(name) {
  const result = await pool.query(
    'SELECT * FROM users WHERE LOWER(name) = LOWER($1)',
    [name]
  );
  if (!result.rows.length) return null;
  return result.rows[0];
}

async function getUserByEmail(email) {
  const result = await pool.query(
    'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
    [email]
  );
  if (!result.rows.length) return null;
  return result.rows[0];
}

async function getAllUsers() {
  const result = await pool.query(
    'SELECT id, name, role, email, color, type, is_default, created_at FROM users ORDER BY is_default DESC, name ASC'
  );
  return result.rows.map(row => rowToUser(row));
}

async function createUser(data) {
  const id = uid();
  const colors = ['#1565c0','#00838f','#2e7d32','#7b1fa2','#c62828','#ef6c00','#283593','#00695c','#4e342e','#37474f'];
  const allUsers = await getAllUsers();
  const color = data.color || colors[allUsers.length % colors.length];
  const hash = bcrypt.hashSync(data.name.toLowerCase(), 10);

  await pool.query(
    'INSERT INTO users (id, name, role, email, password_hash, color, type, is_default, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
    [id, data.name, data.role, data.email || '', hash, color, data.type || 'member', 0, now()]
  );

  return getUser(id);
}

async function deleteUser(id) {
  // Prevent deleting default users
  const u = await getUser(id);
  if (!u || u.isDefault) return false;

  await pool.query('DELETE FROM users WHERE id = $1 AND is_default = 0', [id]);
  return true;
}

// ── Update user password ──
async function updatePassword(userId, hash) {
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, userId]);
  return true;
}

// ── Check if user is admin ──
async function isAdmin(userId) {
  const user = await getUser(userId);
  if (!user) return false;
  if (user.type === 'admin') return true;

  const adminRoles = ['Implementation', 'Manager'];
  return adminRoles.some(r => user.role.includes(r));
}

// ── Find or create user by email (for Google OAuth) ──
async function findOrCreateGoogleUser(data) {
  const { email, name, type, role } = typeof data === 'string'
    ? { email: data, name: null, type: 'observer', role: 'Observer' }
    : data;

  // Try to find existing user by email
  let user = await getUserByEmail(email);
  if (user) {
    return rowToUser(user);
  }

  // Create new user
  const id = uid();
  const colors = ['#1565c0','#00838f','#2e7d32','#7b1fa2','#c62828','#ef6c00','#283593','#00695c','#4e342e','#37474f'];
  const allUsers = await getAllUsers();
  const color = colors[allUsers.length % colors.length];

  // Generate a random hash for Google OAuth users (password won't be used)
  const randomPassword = uid();
  const hash = await bcrypt.hash(randomPassword, 10);

  await pool.query(
    'INSERT INTO users (id, name, role, email, password_hash, color, type, is_default, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
    [id, name || email.split('@')[0], role || 'Observer', email, hash, color, type || 'member', 0, now()]
  );

  return getUser(id);
}

// ══════════════════════════════════════════════════════════════
// CLIENT QUERIES
// ══════════════════════════════════════════════════════════════
async function getAllClients(limit, offset) {
  let query = 'SELECT * FROM clients ORDER BY created_at DESC';
  const params = [];

  if (limit !== undefined && offset !== undefined) {
    query += ' LIMIT $1 OFFSET $2';
    params.push(limit, offset);
  }

  const result = await pool.query(query, params);
  const clients = [];

  for (const row of result.rows) {
    const client = normalizeClient(row);
    client.steps = await getClientSteps(client.id);
    clients.push(client);
  }

  return clients;
}

async function getClient(id) {
  const result = await pool.query('SELECT * FROM clients WHERE id = $1', [id]);
  if (!result.rows.length) return null;

  const client = normalizeClient(result.rows[0]);
  client.steps = await getClientSteps(client.id);
  return client;
}

async function createClient(data) {
  const id = uid();
  const ts = now();

  await pool.query(
    `INSERT INTO clients (id, company, type, contact_name, contact_email, scenario, sales_lead_id, onboarding_lead_id, txns, target_go_live, notes, status, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
    [id, data.company, data.type, data.contactName, data.contactEmail || '', data.scenario || 'single-office',
     data.salesLead || null, data.onboardingLead || null, data.txns || null, data.targetGoLive || null,
     data.notes || '', 'active', ts, ts]
  );

  return getClient(id);
}

async function updateClient(id, data) {
  const fields = [];
  const vals = [];
  let paramIndex = 1;

  const allowed = {
    company: 'company', type: 'type', contactName: 'contact_name', contactEmail: 'contact_email',
    scenario: 'scenario', salesLead: 'sales_lead_id', onboardingLead: 'onboarding_lead_id',
    txns: 'txns', targetGoLive: 'target_go_live', notes: 'notes', status: 'status',
    onboardingToken: 'onboarding_token', onboardingStatus: 'onboarding_status', googleDriveUrl: 'google_drive_url'
  };

  for (const [jsKey, dbCol] of Object.entries(allowed)) {
    if (data[jsKey] !== undefined) {
      fields.push(`${dbCol} = $${paramIndex++}`);
      vals.push(data[jsKey]);
    }
  }

  if (!fields.length) return getClient(id);

  fields.push(`updated_at = $${paramIndex++}`);
  vals.push(now());
  vals.push(id);

  await pool.query(`UPDATE clients SET ${fields.join(', ')} WHERE id = $${paramIndex}`, vals);

  return getClient(id);
}

async function deleteClient(id) {
  // Delete in order to respect foreign key constraints
  await pool.query('DELETE FROM client_steps WHERE client_id = $1', [id]);
  await pool.query('DELETE FROM activities WHERE client_id = $1', [id]);
  await pool.query('DELETE FROM clients WHERE id = $1', [id]);
}

// ══════════════════════════════════════════════════════════════
// CLIENT STEPS QUERIES
// ══════════════════════════════════════════════════════════════
async function getClientSteps(clientId) {
  const result = await pool.query(
    'SELECT step_id, status, note, links, completed_date, completed_by, client_action_note, client_action_response, client_action_responded_at FROM client_steps WHERE client_id = $1',
    [clientId]
  );

  const steps = {};
  for (const row of result.rows) {
    let links = [];
    try { links = JSON.parse(row.links || '[]'); } catch(e) { links = []; }
    steps[row.step_id] = {
      status: row.status,
      note: row.note || '',
      links: links,
      completedDate: row.completed_date,
      completedBy: row.completed_by,
      clientActionNote: row.client_action_note || '',
      clientActionResponse: row.client_action_response || '',
      clientActionRespondedAt: row.client_action_responded_at || null
    };
  }

  return steps;
}

async function upsertStep(clientId, stepId, data) {
  const ts = now();
  const completedDate = data.status === 'completed' ? ts : null;
  const completedBy = data.status === 'completed' ? (data.completedBy || null) : null;

  // Use PostgreSQL INSERT ... ON CONFLICT for upsert
  await pool.query(
    `INSERT INTO client_steps (client_id, step_id, status, note, links, completed_date, completed_by, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (client_id, step_id)
     DO UPDATE SET
       status = $3,
       note = $4,
       completed_date = $6,
       completed_by = $7,
       updated_at = $8`,
    [clientId, stepId, data.status, data.note !== undefined ? data.note : '', '[]', completedDate, completedBy, ts]
  );

  // Update client updated_at
  await pool.query('UPDATE clients SET updated_at = $1 WHERE id = $2', [ts, clientId]);

  return { stepId, status: data.status, note: data.note || '', links: [], completedDate, completedBy };
}

async function setClientActionNote(clientId, stepId, note) {
  const ts = now();
  // Check if step row exists
  const result = await pool.query(
    'SELECT step_id FROM client_steps WHERE client_id = $1 AND step_id = $2',
    [clientId, stepId]
  );
  if (result.rows.length > 0) {
    await pool.query(
      'UPDATE client_steps SET client_action_note = $1, updated_at = $2 WHERE client_id = $3 AND step_id = $4',
      [note || '', ts, clientId, stepId]
    );
  } else {
    await pool.query(
      `INSERT INTO client_steps (client_id, step_id, status, note, links, client_action_note, completed_date, completed_by, updated_at)
       VALUES ($1, $2, 'pending', '', '[]', $3, NULL, NULL, $4)`,
      [clientId, stepId, note || '', ts]
    );
  }
  await pool.query('UPDATE clients SET updated_at = $1 WHERE id = $2', [ts, clientId]);
  return { stepId, clientActionNote: note || '' };
}

async function setClientActionResponse(clientId, stepId, response) {
  const ts = now();
  const result = await pool.query(
    'SELECT step_id FROM client_steps WHERE client_id = $1 AND step_id = $2',
    [clientId, stepId]
  );
  if (result.rows.length > 0) {
    await pool.query(
      'UPDATE client_steps SET client_action_response = $1, client_action_responded_at = $2, updated_at = $3 WHERE client_id = $4 AND step_id = $5',
      [response || '', ts, ts, clientId, stepId]
    );
  }
  await pool.query('UPDATE clients SET updated_at = $1 WHERE id = $2', [ts, clientId]);
  return { stepId, clientActionResponse: response || '', clientActionRespondedAt: ts };
}

async function addStepLink(clientId, stepId, link) {
  const ts = now();
  // Get current links
  const result = await pool.query(
    'SELECT links FROM client_steps WHERE client_id = $1 AND step_id = $2',
    [clientId, stepId]
  );
  let links = [];
  if (result.rows.length > 0) {
    try { links = JSON.parse(result.rows[0].links || '[]'); } catch(e) { links = []; }
  }
  const newLink = { id: uid(), url: link.url, label: link.label || '', addedBy: link.addedBy, addedAt: ts };
  links.push(newLink);

  if (result.rows.length > 0) {
    await pool.query(
      'UPDATE client_steps SET links = $1, updated_at = $2 WHERE client_id = $3 AND step_id = $4',
      [JSON.stringify(links), ts, clientId, stepId]
    );
  } else {
    await pool.query(
      `INSERT INTO client_steps (client_id, step_id, status, note, links, completed_date, completed_by, updated_at)
       VALUES ($1, $2, 'pending', '', $3, NULL, NULL, $4)`,
      [clientId, stepId, JSON.stringify(links), ts]
    );
  }

  await pool.query('UPDATE clients SET updated_at = $1 WHERE id = $2', [ts, clientId]);
  return newLink;
}

async function removeStepLink(clientId, stepId, linkId) {
  const ts = now();
  const result = await pool.query(
    'SELECT links FROM client_steps WHERE client_id = $1 AND step_id = $2',
    [clientId, stepId]
  );
  if (!result.rows.length) return false;
  let links = [];
  try { links = JSON.parse(result.rows[0].links || '[]'); } catch(e) { links = []; }
  links = links.filter(l => l.id !== linkId);
  await pool.query(
    'UPDATE client_steps SET links = $1, updated_at = $2 WHERE client_id = $3 AND step_id = $4',
    [JSON.stringify(links), ts, clientId, stepId]
  );
  return true;
}

// ══════════════════════════════════════════════════════════════
// ACTIVITY QUERIES
// ══════════════════════════════════════════════════════════════
async function createActivity(data) {
  const id = uid();
  const ts = data.timestamp || now();
  // user_id is NOT NULL in the schema — use 'system' as fallback for client/automated actions
  const userId = data.userId || 'system';

  await pool.query(
    'INSERT INTO activities (id, client_id, user_id, action, details, timestamp) VALUES ($1, $2, $3, $4, $5, $6)',
    [id, data.clientId || null, userId, data.action, data.details || '', ts]
  );

  // Keep max 500 activities
  await pool.query(
    `DELETE FROM activities WHERE id NOT IN (SELECT id FROM activities ORDER BY timestamp DESC LIMIT 500)`
  );

  return { id, clientId: data.clientId, userId: data.userId, action: data.action, details: data.details || '', timestamp: ts };
}

async function getActivities(limit = 60, offset = 0) {
  const result = await pool.query(
    'SELECT * FROM activities ORDER BY timestamp DESC LIMIT $1 OFFSET $2',
    [limit, offset]
  );
  return result.rows;
}

async function clearActivities() {
  await pool.query('DELETE FROM activities');
}

// ══════════════════════════════════════════════════════════════
// EXPORT / IMPORT
// ══════════════════════════════════════════════════════════════
async function exportAll() {
  const clients = await getAllClients();
  const team = await getAllUsers();
  const activities = await getActivities(500, 0);
  return { schemaVersion: SCHEMA_VERSION, exportDate: now(), clients, team, activities };
}

async function importAll(data) {
  // Validate import schema
  if (!data || !data.clients || !data.team) {
    throw new Error('Invalid backup data: missing clients or team');
  }
  if (!Array.isArray(data.clients) || !Array.isArray(data.team)) {
    throw new Error('Invalid backup data: clients and team must be arrays');
  }

  // Create backup before import
  let backup = null;
  try {
    backup = await exportAll();
  } catch (e) {
    console.warn('Could not create pre-import backup:', e.message);
  }

  try {
    // Start transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Clear existing data
      await client.query('DELETE FROM client_steps');
      await client.query('DELETE FROM activities');
      await client.query('DELETE FROM clients');
      await client.query('DELETE FROM users WHERE is_default = 0');

      // Import team (non-default)
      const defaultIds = ['t1','t2','t3','t4','t5'];
      for (const t of data.team) {
        if (defaultIds.includes(t.id)) continue;
        const hash = await bcrypt.hash(t.name.toLowerCase(), 10);
        await client.query(
          `INSERT INTO users (id, name, role, email, password_hash, color, type, is_default, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (id) DO NOTHING`,
          [t.id, t.name, t.role || 'Observer', t.email || '', hash, t.color || '#999', t.type || 'observer', 0, now()]
        );
      }

      // Import clients + steps
      for (const c of data.clients) {
        const ts = now();
        await client.query(
          `INSERT INTO clients (id, company, type, contact_name, contact_email, scenario, sales_lead_id, onboarding_lead_id, txns, target_go_live, notes, status, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
          [c.id, c.company, c.type, c.contactName || c.contact_name || '', c.contactEmail || c.contact_email || '',
           c.scenario || 'single-office', c.salesLead || c.sales_lead_id || null, c.onboardingLead || c.onboarding_lead_id || null,
           c.txns || null, c.targetGoLive || c.target_go_live || null, c.notes || '', c.status || 'active',
           c.createdAt || c.created_at || ts, ts]
        );

        // Import steps
        if (c.steps) {
          for (const [stepId, step] of Object.entries(c.steps)) {
            await client.query(
              `INSERT INTO client_steps (client_id, step_id, status, note, completed_date, completed_by, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (client_id, step_id)
               DO UPDATE SET status = $3, note = $4, completed_date = $5, completed_by = $6, updated_at = $7`,
              [c.id, stepId, step.status || 'pending', step.note || '', step.completedDate || step.completed_date || null,
               step.completedBy || step.completed_by || null, ts]
            );
          }
        }
      }

      // Import activities
      if (data.activities) {
        for (const a of data.activities) {
          await client.query(
            'INSERT INTO activities (id, client_id, user_id, action, details, timestamp) VALUES ($1, $2, $3, $4, $5, $6)',
            [a.id || uid(), a.clientId || a.client_id || null, a.userId || a.user_id || a.user || 't5',
             a.action || '', a.details || '', a.timestamp || now()]
          );
        }
      }

      await client.query('COMMIT');
      return { clients: data.clients.length, team: data.team.length, activities: (data.activities || []).length };
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    // Fallback rollback attempt
    if (backup) {
      console.warn('Import failed, attempting rollback:', e.message);
      await importAll(backup);
    }
    throw e;
  }
}

// ══════════════════════════════════════════════════════════════
// ONBOARDING QUERIES
// ══════════════════════════════════════════════════════════════
async function getClientByToken(token) {
  if (!token) return null;
  const result = await pool.query('SELECT * FROM clients WHERE onboarding_token = $1', [token]);
  if (!result.rows.length) return null;
  const client = normalizeClient(result.rows[0]);
  client.steps = await getClientSteps(client.id);
  return client;
}

async function generateOnboardingToken(clientId) {
  const token = crypto.randomBytes(16).toString('hex');
  await pool.query('UPDATE clients SET onboarding_token = $1, updated_at = $2 WHERE id = $3', [token, now(), clientId]);
  return token;
}

async function getOnboardingSubmission(clientId) {
  const result = await pool.query('SELECT * FROM onboarding_submissions WHERE client_id = $1 ORDER BY updated_at DESC LIMIT 1', [clientId]);
  if (!result.rows.length) return null;
  const row = result.rows[0];
  return { id: row.id, clientId: row.client_id, formData: JSON.parse(row.form_data || '{}'), status: row.status, submittedAt: row.submitted_at, updatedAt: row.updated_at };
}

async function saveOnboardingSubmission(clientId, formData, status) {
  const ts = now();
  const existing = await getOnboardingSubmission(clientId);
  if (existing) {
    await pool.query('UPDATE onboarding_submissions SET form_data = $1, status = $2, submitted_at = $3, updated_at = $4 WHERE id = $5',
      [JSON.stringify(formData), status, status === 'submitted' ? ts : existing.submittedAt, ts, existing.id]);
  } else {
    await pool.query('INSERT INTO onboarding_submissions (id, client_id, form_data, status, submitted_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [uid(), clientId, JSON.stringify(formData), status, status === 'submitted' ? ts : null, ts]);
  }
  // Update client onboarding status
  await pool.query('UPDATE clients SET onboarding_status = $1, updated_at = $2 WHERE id = $3', [status, ts, clientId]);
  return getOnboardingSubmission(clientId);
}

async function getClientByContactEmail(email) {
  if (!email) return null;
  const result = await pool.query('SELECT * FROM clients WHERE LOWER(contact_email) = LOWER($1)', [email]);
  if (!result.rows.length) return null;
  const client = normalizeClient(result.rows[0]);
  client.steps = await getClientSteps(client.id);
  return client;
}

// ══════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════
function rowToUser(row) {
  return {
    id: row.id,
    name: row.name,
    role: row.role,
    email: row.email,
    color: row.color,
    type: row.type,
    isDefault: !!row.is_default,
    createdAt: row.created_at
  };
}

function normalizeClient(row) {
  return {
    id: row.id,
    company: row.company,
    type: row.type,
    contactName: row.contact_name,
    contactEmail: row.contact_email,
    scenario: row.scenario,
    salesLead: row.sales_lead_id,
    onboardingLead: row.onboarding_lead_id,
    txns: row.txns,
    targetGoLive: row.target_go_live,
    notes: row.notes,
    status: row.status,
    steps: row.steps || {},
    onboardingToken: row.onboarding_token || null,
    onboardingStatus: row.onboarding_status || 'not_started',
    googleDriveUrl: row.google_drive_url || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

// ══════════════════════════════════════════════════════════════
// EXPORTS
// ══════════════════════════════════════════════════════════════
module.exports = {
  init,
  getPool,
  flushAndShutdown,
  getUser,
  getUserByName,
  getUserByEmail,
  getAllUsers,
  createUser,
  deleteUser,
  updatePassword,
  isAdmin,
  findOrCreateGoogleUser,
  getAllClients,
  getClient,
  createClient,
  updateClient,
  deleteClient,
  getClientSteps,
  upsertStep,
  addStepLink,
  removeStepLink,
  setClientActionNote,
  setClientActionResponse,
  createActivity,
  getActivities,
  clearActivities,
  exportAll,
  importAll,
  getClientByToken,
  generateOnboardingToken,
  getOnboardingSubmission,
  saveOnboardingSubmission,
  getClientByContactEmail
};
