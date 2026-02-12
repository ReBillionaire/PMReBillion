// Vercel Serverless Function entry point
const db = require('../database');
const app = require('../server');

let initialized = false;

module.exports = async (req, res) => {
  if (!initialized) {
    await db.init();
    initialized = true;
  }
  return app(req, res);
};
