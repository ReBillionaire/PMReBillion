// Vercel Serverless Function entry point
const db = require('../database');
const app = require('../server');

let initialized = false;

module.exports = async (req, res) => {
  if (!initialized) {
    await db.init();
    initialized = true;
    // Cleanup stale email log entries on cold start (fire-and-forget)
    db.cleanupEmailLog().catch(err => console.warn('Email log cleanup failed:', err.message));
  }
  return app(req, res);
};
