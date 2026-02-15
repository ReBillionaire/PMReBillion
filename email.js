// ══════════════════════════════════════════════════════════════
// ReBillion PM — Email Service (SendGrid) — Hardened
// ══════════════════════════════════════════════════════════════
const sgMail = require('@sendgrid/mail');
const db = require('./database');

// ══════════════════════════════════════════════════════════════
// SECURITY: Input Sanitization
// ══════════════════════════════════════════════════════════════

// Strict email validation
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  if (email.length > 254) return false; // RFC 5321
  const re = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return re.test(email);
}

// Sanitize text for HTML email templates (prevent XSS injection in emails)
function sanitizeHtml(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Sanitize URL — only allow http/https protocols
function sanitizeUrl(url) {
  if (!url || typeof url !== 'string') return '#';
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return '#';
    return parsed.toString();
  } catch {
    return '#';
  }
}

// Validate that the "from" email matches a trusted domain
const ALLOWED_SENDER_DOMAINS = ['rebillion.ai', 'garvik.ai'];
function isAllowedSenderDomain(email) {
  if (!email) return false;
  const domain = email.split('@')[1]?.toLowerCase();
  return ALLOWED_SENDER_DOMAINS.includes(domain);
}

// ══════════════════════════════════════════════════════════════
// DEDUPLICATION: Prevent duplicate emails
// ══════════════════════════════════════════════════════════════

// Cooldown periods in minutes per email type
const COOLDOWNS = {
  client_action: 10,       // Same action note to same client: 10 min cooldown
  form_submission: 30,     // Same client form submission notification: 30 min
  form_link: 5,            // Same form link to same email: 5 min
  test_email: 2            // Test emails: 2 min
};

// Check dedup + log on success. Returns { allowed: true } or { allowed: false, reason: string }
async function checkAndLogDedup(emailType, recipient, contextKey) {
  const cooldown = COOLDOWNS[emailType] || 10;
  try {
    const wasSent = await db.wasEmailSentRecently(emailType, recipient, contextKey, cooldown);
    if (wasSent) {
      console.log(`[EMAIL DEDUP] Blocked duplicate "${emailType}" to ${recipient} (context: ${contextKey}) — cooldown: ${cooldown}min`);
      return { allowed: false, reason: `Duplicate email blocked — same email was sent within the last ${cooldown} minutes` };
    }
    return { allowed: true };
  } catch (err) {
    // If dedup check fails (DB error), allow the email but log warning
    console.warn('[EMAIL DEDUP] Check failed, allowing email as fallback:', err.message);
    return { allowed: true };
  }
}

async function recordSentEmail(emailType, recipient, contextKey) {
  try {
    await db.logEmail(emailType, recipient, contextKey);
  } catch (err) {
    console.warn('[EMAIL LOG] Failed to record sent email:', err.message);
  }
}

// ══════════════════════════════════════════════════════════════
// CORE: Load & validate SendGrid settings
// ══════════════════════════════════════════════════════════════

async function loadEmailConfig() {
  const enabled = await db.getSetting('email_enabled');
  if (enabled !== 'true') {
    return { ok: false, error: 'Email notifications are disabled' };
  }

  const apiKey = await db.getSetting('sendgrid_api_key');
  if (!apiKey) {
    return { ok: false, error: 'SendGrid API key not configured' };
  }

  const fromEmail = await db.getSetting('email_from_address') || 'noreply@rebillion.ai';
  const fromName = await db.getSetting('email_from_name') || 'ReBillion.ai';

  // Security: validate sender domain
  if (!isAllowedSenderDomain(fromEmail)) {
    console.error(`[EMAIL SECURITY] Sender email "${fromEmail}" is not on an allowed domain. Allowed: ${ALLOWED_SENDER_DOMAINS.join(', ')}`);
    return { ok: false, error: 'Sender email domain not authorized' };
  }

  return { ok: true, apiKey, fromEmail, fromName };
}

// ══════════════════════════════════════════════════════════════
// Branded HTML Email Template
// ══════════════════════════════════════════════════════════════

function buildClientActionEmail({ toName, company, stepName, actionNote, portalUrl }) {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f8;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
          <!-- Header -->
          <tr>
            <td style="background:#1a3a2a;padding:24px 32px;border-radius:12px 12px 0 0;">
              <h1 style="margin:0;font-size:20px;font-weight:800;color:#fff;">
                ReBillion<span style="color:#D05F0D;">.ai</span>
              </h1>
              <p style="margin:4px 0 0;font-size:12px;color:rgba(255,255,255,0.5);">Client Onboarding Portal</p>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="background:#ffffff;padding:32px;border-left:1px solid #e0e8f0;border-right:1px solid #e0e8f0;">
              <p style="margin:0 0 16px;font-size:15px;color:#1a2a2a;">
                Hi ${sanitizeHtml(toName) || 'there'},
              </p>
              <p style="margin:0 0 24px;font-size:14px;color:#607d8b;line-height:1.6;">
                Your onboarding team at <strong style="color:#1a2a2a;">${sanitizeHtml(company)}</strong> has a new action item that requires your attention.
              </p>
              <!-- Step Badge -->
              <div style="background:#fff3e0;border-left:4px solid #D05F0D;border-radius:0 8px 8px 0;padding:16px 20px;margin:0 0 24px;">
                <p style="margin:0 0 4px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#e65100;">
                  Action Required
                </p>
                <p style="margin:0 0 8px;font-size:15px;font-weight:600;color:#1a2a2a;">
                  ${sanitizeHtml(stepName)}
                </p>
                <p style="margin:0;font-size:14px;color:#1a2a2a;line-height:1.5;">
                  ${sanitizeHtml(actionNote)}
                </p>
              </div>
              <!-- CTA Button -->
              <table cellpadding="0" cellspacing="0" style="margin:0 0 24px;">
                <tr>
                  <td style="background:#4B876C;border-radius:8px;">
                    <a href="${sanitizeUrl(portalUrl)}" style="display:inline-block;padding:12px 28px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;">
                      View Your Portal
                    </a>
                  </td>
                </tr>
              </table>
              <p style="margin:0;font-size:12px;color:#90a4ae;line-height:1.5;">
                If you have questions, reply to this email or reach out to your onboarding contact directly.
              </p>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="background:#f8fafb;padding:20px 32px;border:1px solid #e0e8f0;border-top:none;border-radius:0 0 12px 12px;">
              <p style="margin:0;font-size:11px;color:#90a4ae;text-align:center;">
                ReBillion.ai &mdash; Streamlining Real Estate Closings
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ══════════════════════════════════════════════════════════════
// Send Client Action Email
// ══════════════════════════════════════════════════════════════
async function sendClientActionEmail({ toEmail, toName, company, stepName, actionNote, portalUrl }) {
  try {
    // Validate recipient
    if (!isValidEmail(toEmail)) {
      console.warn(`[EMAIL] Invalid recipient email: ${toEmail}`);
      return { success: false, error: 'Invalid recipient email address' };
    }

    // Load and validate config
    const config = await loadEmailConfig();
    if (!config.ok) return { success: false, error: config.error };

    // Dedup check: same email type + same recipient + same step context
    const contextKey = `action:${company}:${stepName}`;
    const dedup = await checkAndLogDedup('client_action', toEmail, contextKey);
    if (!dedup.allowed) return { success: false, error: dedup.reason };

    sgMail.setApiKey(config.apiKey);

    const msg = {
      to: toEmail,
      from: { email: config.fromEmail, name: config.fromName },
      subject: `Action Required: ${(stepName || '').substring(0, 100)} — ${(company || '').substring(0, 100)}`,
      html: buildClientActionEmail({ toName, company, stepName, actionNote, portalUrl })
    };

    await sgMail.send(msg);
    await recordSentEmail('client_action', toEmail, contextKey);
    console.log(`[EMAIL] Sent client action to ${toEmail} for step "${stepName}" (${company})`);
    return { success: true };
  } catch (error) {
    const errMsg = error.response ? JSON.stringify(error.response.body) : error.message;
    console.error('[EMAIL ERROR] Client action email:', errMsg);
    return { success: false, error: errMsg };
  }
}

// ══════════════════════════════════════════════════════════════
// Send Test Email
// ══════════════════════════════════════════════════════════════
async function sendTestEmail(toEmail) {
  try {
    if (!isValidEmail(toEmail)) {
      return { success: false, error: 'Invalid email address' };
    }

    const apiKey = await db.getSetting('sendgrid_api_key');
    if (!apiKey) {
      return { success: false, error: 'SendGrid API key not configured. Please save your API key first.' };
    }

    const fromEmail = await db.getSetting('email_from_address') || 'noreply@rebillion.ai';
    const fromName = await db.getSetting('email_from_name') || 'ReBillion.ai';

    // Sender domain check (but more lenient for test emails)
    if (!isAllowedSenderDomain(fromEmail)) {
      return { success: false, error: `Sender domain not authorized. Allowed: ${ALLOWED_SENDER_DOMAINS.join(', ')}` };
    }

    // Dedup: rate limit test emails
    const dedup = await checkAndLogDedup('test_email', toEmail, 'test');
    if (!dedup.allowed) return { success: false, error: dedup.reason };

    sgMail.setApiKey(apiKey);

    const msg = {
      to: toEmail,
      from: { email: fromEmail, name: fromName },
      subject: 'ReBillion PM — Test Email',
      html: buildClientActionEmail({
        toName: 'Admin',
        company: 'Test Company',
        stepName: 'Test Step — Email Configuration',
        actionNote: 'This is a test email to verify your SendGrid configuration is working correctly. If you received this, your email setup is good to go!',
        portalUrl: '#'
      })
    };

    await sgMail.send(msg);
    await recordSentEmail('test_email', toEmail, 'test');
    return { success: true };
  } catch (error) {
    const errMsg = error.response ? JSON.stringify(error.response.body) : error.message;
    console.error('[EMAIL ERROR] Test email:', errMsg);
    return { success: false, error: errMsg };
  }
}

// ══════════════════════════════════════════════════════════════
// Send Form Submission Notification (to admin/team)
// ══════════════════════════════════════════════════════════════
async function sendFormSubmissionNotification({ company, contactName, contactEmail, appUrl }) {
  try {
    // Load and validate config
    const config = await loadEmailConfig();
    if (!config.ok) return { success: false, error: config.error };

    // Send to the configured from-email (admin)
    const toEmail = config.fromEmail;

    // Dedup: same company form submission notification
    const contextKey = `form_submit:${company}`;
    const dedup = await checkAndLogDedup('form_submission', toEmail, contextKey);
    if (!dedup.allowed) return { success: false, error: dedup.reason };

    sgMail.setApiKey(config.apiKey);

    const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f8;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
        <tr><td style="background:#1a3a2a;padding:24px 32px;border-radius:12px 12px 0 0;">
          <h1 style="margin:0;font-size:20px;font-weight:800;color:#fff;">ReBillion<span style="color:#D05F0D;">.ai</span></h1>
          <p style="margin:4px 0 0;font-size:12px;color:rgba(255,255,255,0.5);">Onboarding Form Submitted</p>
        </td></tr>
        <tr><td style="background:#ffffff;padding:32px;border-left:1px solid #e0e8f0;border-right:1px solid #e0e8f0;">
          <p style="margin:0 0 16px;font-size:15px;color:#1a2a2a;">A client has submitted their onboarding form.</p>
          <div style="background:#e8f5e9;border-left:4px solid #2e7d32;border-radius:0 8px 8px 0;padding:16px 20px;margin:0 0 24px;">
            <p style="margin:0 0 4px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#2e7d32;">Form Submitted</p>
            <p style="margin:0 0 8px;font-size:16px;font-weight:600;color:#1a2a2a;">${sanitizeHtml(company)}</p>
            <p style="margin:0;font-size:13px;color:#607d8b;">${sanitizeHtml(contactName)} &mdash; ${sanitizeHtml(contactEmail)}</p>
          </div>
          <table cellpadding="0" cellspacing="0" style="margin:0 0 24px;">
            <tr><td style="background:#4B876C;border-radius:8px;">
              <a href="${sanitizeUrl(appUrl)}" style="display:inline-block;padding:12px 28px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;">View in PM App</a>
            </td></tr>
          </table>
        </td></tr>
        <tr><td style="background:#f8fafb;padding:20px 32px;border:1px solid #e0e8f0;border-top:none;border-radius:0 0 12px 12px;">
          <p style="margin:0;font-size:11px;color:#90a4ae;text-align:center;">ReBillion.ai &mdash; Streamlining Real Estate Closings</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

    await sgMail.send({
      to: toEmail,
      from: { email: config.fromEmail, name: config.fromName },
      subject: `Onboarding Form Submitted — ${(company || '').substring(0, 100)}`,
      html
    });
    await recordSentEmail('form_submission', toEmail, contextKey);
    console.log(`[EMAIL] Form submission notification sent for ${company}`);
    return { success: true };
  } catch (error) {
    const errMsg = error.response ? JSON.stringify(error.response.body) : error.message;
    console.error('[EMAIL ERROR] Form submission notification:', errMsg);
    return { success: false, error: errMsg };
  }
}

// ══════════════════════════════════════════════════════════════
// Send Form Link to Client
// ══════════════════════════════════════════════════════════════
async function sendFormLinkEmail({ toEmail, toName, company, formUrl }) {
  try {
    // Validate recipient
    if (!isValidEmail(toEmail)) {
      return { success: false, error: 'Invalid recipient email address' };
    }

    // Load and validate config
    const config = await loadEmailConfig();
    if (!config.ok) return { success: false, error: config.error };

    // Dedup: same form link to same recipient
    const contextKey = `form_link:${company}`;
    const dedup = await checkAndLogDedup('form_link', toEmail, contextKey);
    if (!dedup.allowed) return { success: false, error: dedup.reason };

    sgMail.setApiKey(config.apiKey);

    const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f8;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
        <tr><td style="background:#1a3a2a;padding:24px 32px;border-radius:12px 12px 0 0;">
          <h1 style="margin:0;font-size:20px;font-weight:800;color:#fff;">ReBillion<span style="color:#D05F0D;">.ai</span></h1>
          <p style="margin:4px 0 0;font-size:12px;color:rgba(255,255,255,0.5);">Client Onboarding</p>
        </td></tr>
        <tr><td style="background:#ffffff;padding:32px;border-left:1px solid #e0e8f0;border-right:1px solid #e0e8f0;">
          <p style="margin:0 0 16px;font-size:15px;color:#1a2a2a;">Hi ${sanitizeHtml(toName) || 'there'},</p>
          <p style="margin:0 0 24px;font-size:14px;color:#607d8b;line-height:1.6;">
            Welcome to ReBillion! To get started with your onboarding, please fill out the form below. It takes about 5-10 minutes and helps us set up your platform exactly how you need it.
          </p>
          <div style="background:#f0f5f2;border-left:4px solid #4B876C;border-radius:0 8px 8px 0;padding:16px 20px;margin:0 0 24px;">
            <p style="margin:0 0 4px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#4B876C;">Your Onboarding Form</p>
            <p style="margin:0;font-size:14px;color:#1a2a2a;line-height:1.5;">Please complete this form with your contact info, current systems, and compliance details. You can save your progress and return later.</p>
          </div>
          <table cellpadding="0" cellspacing="0" style="margin:0 0 24px;">
            <tr><td style="background:#D05F0D;border-radius:8px;">
              <a href="${sanitizeUrl(formUrl)}" style="display:inline-block;padding:14px 32px;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;">Start Onboarding Form</a>
            </td></tr>
          </table>
          <p style="margin:0;font-size:12px;color:#90a4ae;line-height:1.5;">If you have questions or need help, reply to this email or contact your ReBillion representative directly.</p>
        </td></tr>
        <tr><td style="background:#f8fafb;padding:20px 32px;border:1px solid #e0e8f0;border-top:none;border-radius:0 0 12px 12px;">
          <p style="margin:0;font-size:11px;color:#90a4ae;text-align:center;">ReBillion.ai &mdash; Streamlining Real Estate Closings</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

    await sgMail.send({
      to: toEmail,
      from: { email: config.fromEmail, name: config.fromName },
      subject: `Complete Your Onboarding — ${(company || '').substring(0, 100)}`,
      html
    });
    await recordSentEmail('form_link', toEmail, contextKey);
    console.log(`[EMAIL] Form link emailed to ${toEmail} for ${company}`);
    return { success: true };
  } catch (error) {
    const errMsg = error.response ? JSON.stringify(error.response.body) : error.message;
    console.error('[EMAIL ERROR] Form link email:', errMsg);
    return { success: false, error: errMsg };
  }
}

module.exports = {
  sendClientActionEmail,
  sendTestEmail,
  sendFormSubmissionNotification,
  sendFormLinkEmail,
  isValidEmail,
  ALLOWED_SENDER_DOMAINS
};
