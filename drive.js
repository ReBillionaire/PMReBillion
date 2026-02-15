// ══════════════════════════════════════════════════════════════
// ReBillion PM — Google Drive Service (Service Account)
// ══════════════════════════════════════════════════════════════
const { google } = require('googleapis');
const db = require('./database');

// ── Get authenticated Drive client ──
async function getDriveClient() {
  const saJson = await db.getSetting('google_drive_service_account');
  if (!saJson) return null;

  try {
    const credentials = JSON.parse(saJson);
    const auth = new google.auth.GoogleAuth({
      credentials,
      scopes: ['https://www.googleapis.com/auth/drive.file']
    });
    return google.drive({ version: 'v3', auth });
  } catch (e) {
    console.error('Failed to initialize Drive client:', e.message);
    return null;
  }
}

// ── Extract folder ID from Google Drive URL or raw ID ──
function extractFolderId(input) {
  if (!input) return null;
  input = input.trim();
  // Direct ID (no slashes, no URL)
  if (/^[a-zA-Z0-9_-]{10,}$/.test(input)) return input;
  // URL patterns: /folders/ID, id=ID, /d/ID
  const patterns = [
    /\/folders\/([a-zA-Z0-9_-]+)/,
    /[?&]id=([a-zA-Z0-9_-]+)/,
    /\/d\/([a-zA-Z0-9_-]+)/
  ];
  for (const p of patterns) {
    const m = input.match(p);
    if (m) return m[1];
  }
  return input; // Assume raw ID
}

// ── Create a subfolder for a client ──
async function createClientFolder(clientCompany) {
  try {
    const enabled = await db.getSetting('google_drive_enabled');
    if (enabled !== 'true') {
      return { success: false, error: 'Google Drive integration is disabled' };
    }

    const rootFolderSetting = await db.getSetting('google_drive_root_folder_id');
    const rootFolderId = extractFolderId(rootFolderSetting);
    if (!rootFolderId) {
      return { success: false, error: 'Root folder not configured' };
    }

    const drive = await getDriveClient();
    if (!drive) {
      return { success: false, error: 'Service account not configured or invalid' };
    }

    // Create folder with client name + date
    const folderName = `${clientCompany} — Onboarding`;
    const fileMetadata = {
      name: folderName,
      mimeType: 'application/vnd.google-apps.folder',
      parents: [rootFolderId]
    };

    const folder = await drive.files.create({
      resource: fileMetadata,
      fields: 'id, webViewLink'
    });

    // Make the folder accessible via link (anyone with link can view/edit)
    await drive.permissions.create({
      fileId: folder.data.id,
      resource: {
        role: 'writer',
        type: 'anyone'
      }
    });

    const folderUrl = folder.data.webViewLink || `https://drive.google.com/drive/folders/${folder.data.id}`;
    console.log(`Created Drive folder for "${clientCompany}": ${folderUrl}`);

    return { success: true, folderId: folder.data.id, folderUrl };
  } catch (error) {
    const errMsg = error.message || JSON.stringify(error);
    console.error('Drive folder creation error:', errMsg);
    return { success: false, error: errMsg };
  }
}

// ── Test Drive connection ──
async function testDriveConnection() {
  try {
    const drive = await getDriveClient();
    if (!drive) {
      return { success: false, error: 'Service account not configured or invalid JSON' };
    }

    const rootFolderSetting = await db.getSetting('google_drive_root_folder_id');
    const rootFolderId = extractFolderId(rootFolderSetting);
    if (!rootFolderId) {
      return { success: false, error: 'Root folder ID not configured' };
    }

    // Try to list files in the root folder to verify access
    const result = await drive.files.get({
      fileId: rootFolderId,
      fields: 'id, name, mimeType'
    });

    if (result.data.mimeType !== 'application/vnd.google-apps.folder') {
      return { success: false, error: 'The configured ID is not a folder' };
    }

    return { success: true, folderName: result.data.name };
  } catch (error) {
    const errMsg = error.message || JSON.stringify(error);
    console.error('Drive connection test error:', errMsg);
    return { success: false, error: errMsg };
  }
}

module.exports = {
  createClientFolder,
  testDriveConnection,
  extractFolderId
};
