require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const companion = require('@uppy/companion');
const formidable = require('formidable');
const fs = require('fs/promises');
const fsSync = require('fs'); // For fs.createReadStream
const fetch = require('node-fetch');
const { randomUUID } = require('crypto');
const path = require('path');
const cors = require('cors');
// Google Calendar
const { google } = require('googleapis');
const jwt = require('jsonwebtoken');
// IPX
const { createIPX, ipxFSStorage, ipxHttpStorage, createIPXNodeServer } = require('ipx');
const axios = require('axios');
const dns = require('dns').promises;


// AWS SDK v3
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');


// Wasabi Config
const WASABI_BUCKET = process.env.WASABI_BUCKET;
const WASABI_REGION = process.env.WASABI_REGION;
const WASABI_ENDPOINT = process.env.WASABI_ENDPOINT;
const WASABI_KEY = process.env.WASABI_KEY;
const WASABI_SECRET = process.env.WASABI_SECRET;

// Mux Config
const MUX_TOKEN_ID = process.env.MUX_TOKEN_ID;
const MUX_TOKEN_SECRET = process.env.MUX_TOKEN_SECRET;

const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdir(UPLOAD_DIR, { recursive: true }).catch(() => { });

// S3: Wasabi (SDK v3)
const s3 = new S3Client({
  endpoint: WASABI_ENDPOINT,
  region: WASABI_REGION,
  credentials: {
    accessKeyId: WASABI_KEY,
    secretAccessKey: WASABI_SECRET
  },
  forcePathStyle: true // Important for Wasabi
});

const isVideoOrAudio = mimetype =>
  mimetype && (
    mimetype.startsWith('video/') ||
    mimetype.startsWith('audio/') ||
    mimetype === 'application/mp4'
  );

// ---- Streaming upload helpers

async function uploadToWasabi({ filepath, wasabiKey, mimetype, wasabiConfig }) {
  const fileStream = fsSync.createReadStream(filepath);
  
  // Create specific client for this upload
  const client = createS3Client(wasabiConfig);

  const command = new PutObjectCommand({
    Bucket: wasabiConfig.bucket,
    Key: wasabiKey,
    ContentType: mimetype || 'application/octet-stream',
    ACL: 'public-read'
  });

  const url = await getSignedUrl(client, command, { expiresIn: 600 });

  const resp = await fetch(url, {
    method: 'PUT',
    headers: {
      'Content-Type': mimetype || 'application/octet-stream',
      'x-amz-acl': 'public-read'
    },
    body: fileStream
  });

  if (!resp.ok) {
    const msg = await resp.text();
    throw new Error(`Wasabi PUT failed: ${resp.status} - ${msg}`);
  }
  
  // Construct URL based on the config endpoint/bucket
  // Removing 'https://' from endpoint to construct standard path style if needed, 
  // or just use standard Wasabi format if endpoint is standard.
  // Defaulting to standard structure:
  const regionStr = wasabiConfig.region ? `.${wasabiConfig.region}` : '';
  // Check if endpoint is custom or standard wasabi
  if (wasabiConfig.endpoint.includes('wasabisys.com')) {
     return `https://${wasabiConfig.bucket}.s3${regionStr}.wasabisys.com/${wasabiKey}`;
  } else {
     // Fallback for custom endpoints (though Wasabi usually follows above)
     return `${wasabiConfig.endpoint}/${wasabiConfig.bucket}/${wasabiKey}`;
  }
}

async function uploadToMux({ filepath, mimetype, originalFilename, tokenId, tokenSecret }) {
  const external_id = randomUUID();

  // Ensure we have valid credentials (either default or private)
  if (!tokenId || !tokenSecret) {
    throw new Error("Mux Credentials are missing (ID or Secret is null)");
  }

  const response = await fetch('https://api.mux.com/video/v1/uploads', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      // USE PASSED CREDENTIALS
      'Authorization': 'Basic ' + Buffer.from(`${tokenId}:${tokenSecret}`).toString('base64')
    },
    body: JSON.stringify({
      new_asset_settings: {
        playback_policies: ['public'],
        passthrough: originalFilename,
        meta: { external_id },
        master_access: "temporary"
      }
    })
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`MUX upload create failed: ${response.status}: ${text}`);
  }
  const json = await response.json();
  const upload_url = json.data.url;
  const upload_id = json.data.id;

  const fileStream = fsSync.createReadStream(filepath);

  const uploadResp = await fetch(upload_url, {
    method: 'PUT',
    headers: {
      'Content-Type': mimetype || 'application/octet-stream',
      'Origin': '*'
    },
    body: fileStream
  });
  if (!uploadResp.ok) {
    const text = await uploadResp.text();
    throw new Error(`MUX upload PUT failed: ${uploadResp.status}: ${text}`);
  }

  return {
    mux_upload_id: upload_id,
    upload_url,
    external_id
  };
}

// ---- Express Setup

const app = express();
app.use(cors({ origin: '*', credentials: false }));
app.use(bodyParser.json({ limit: '50mb' }));

app.use(session({
  secret: process.env.COMPANION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

const options = {
  providerOptions: {
    drive: {
      key: process.env.GOOGLE_KEY,
      secret: process.env.GOOGLE_SECRET
    },
    dropbox: {
      key: process.env.DROPBOX_KEY,
      secret: process.env.DROPBOX_SECRET
    },
    onedrive: {
      key: process.env.ONEDRIVE_KEY,
      secret: process.env.ONEDRIVE_SECRET
    }
  },
  server: {
    host: process.env.COMPANION_DOMAIN,
    protocol: 'https'
  },
  filePath: '/tmp',
  secret: process.env.COMPANION_SECRET,
  debug: true,
  uploadUrls: ['.*']
};

const { app: companionApp } = companion.app(options);
app.use(companionApp);

app.options('/upload', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, OPTIONS, POST');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
  res.status(204).end();
});

async function getMuxCredentials(memberUniqueId) {
  // 1. Initialize with Default Environment Variables
  let credentials = {
    id: MUX_TOKEN_ID,
    secret: MUX_TOKEN_SECRET
  };

  // If no member ID is provided, strictly use defaults
  if (!memberUniqueId) return credentials;

  try {
    // 2. Always query the API
    const response = await fetch("https://upward.page/api/1.1/wf/get_mux_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ member_unique_id: memberUniqueId })
    });

    if (response.ok) {
      const json = await response.json();
      
      // Bubble responses usually nest data inside a "response" object.
      // We handle both flat structure and nested structure just in case.
      const data = json.response || json;

      // 3. Check the flag
      // Convert to boolean in case it comes as string "true"
      const isPrivateLabelled = data.private_labelled === true || data.private_labelled === "true";

      if (isPrivateLabelled) {
        // Only override if the new keys actually exist
        if (data.mux_token_id && data.mux_token_secret) {
          credentials.id = data.mux_token_id;
          credentials.secret = data.mux_token_secret;
        } else {
          console.warn(`[Mux Auth] Private Label requested for ${memberUniqueId} but keys missing. Using default.`);
        }
      } 
      // If private_labelled is false, we simply do nothing and return the `credentials` object (which holds defaults)
    }
  } catch (error) {
    console.error(`[Mux Auth] API check failed for ${memberUniqueId}:`, error.message);
    // On error, we silently fall back to defaults
  }

  return credentials;
}

async function getWasabiCredentials(memberUniqueId) {
  // 1. Default Configuration
  let config = {
    bucket: process.env.WASABI_BUCKET,
    region: process.env.WASABI_REGION,
    endpoint: process.env.WASABI_ENDPOINT,
    accessKeyId: process.env.WASABI_KEY,
    secretAccessKey: process.env.WASABI_SECRET
  };

  if (!memberUniqueId) return config;

  try {
    // 2. Query API
    const response = await fetch("https://upward.page/api/1.1/wf/get_wasabi_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ member_unique_id: memberUniqueId })
    });

    if (response.ok) {
      const json = await response.json();
      const data = json.response || json;

      // 3. Check flag
      const isPrivateLabelled = data.private_labelled === true || data.private_labelled === "true";

      if (isPrivateLabelled) {
        if (data.bucket_key && data.bucket_secret && data.bucket_name) {
          config.bucket = data.bucket_name;
          // Ensure endpoint has protocol
          let ep = data.bucket_endpoint;
          if (ep && !ep.startsWith('http')) ep = `https://${ep}`;
          
          config.endpoint = ep;
          config.region = data.bucket_region;
          config.accessKeyId = data.bucket_key;
          config.secretAccessKey = data.bucket_secret;
        } else {
          console.warn(`[Wasabi Auth] Private Label requested for ${memberUniqueId} but keys missing. Using default.`);
        }
      }
    }
  } catch (error) {
    console.error(`[Wasabi Auth] API check failed for ${memberUniqueId}:`, error.message);
  }

  return config;
}

// Helper to create a client based on specific credentials
function createS3Client(config) {
  return new S3Client({
    endpoint: config.endpoint,
    region: config.region,
    credentials: {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey
    },
    forcePathStyle: true
  });
}


app.post('/upload', (req, res) => {
  const form = new formidable.IncomingForm({
    multiples: false,
    uploadDir: UPLOAD_DIR,
    keepExtensions: true,
    maxFileSize: 2 * 1024 * 1024 * 1024
  });

  req.on('aborted', () => { /* ... */ });

  form.parse(req, async (err, fields, files) => {
    if (err) { /* ... handle error ... */ return; }
    
    try {
      const uploaded = (files.file && files.file[0]) || files[Object.keys(files)[0]][0];
      const { filepath, originalFilename, mimetype, size } = uploaded;
      const timestamp = Date.now();
      const safeName = originalFilename.replace(/[^\w.\-]/g, '_');

      // 1. Extract Member ID
      const memberUniqueId = Array.isArray(fields.member_unique_id) 
        ? fields.member_unique_id[0] 
        : fields.member_unique_id;

      let result = {};
      
      if (isVideoOrAudio(mimetype)) {
        // --- MUX LOGIC ---
        const muxCreds = await getMuxCredentials(memberUniqueId);
        result = await uploadToMux({ 
          filepath, 
          mimetype, 
          originalFilename,
          tokenId: muxCreds.id,
          tokenSecret: muxCreds.secret
        });
      } else {
        // --- WASABI LOGIC ---
        const wasabiConfig = await getWasabiCredentials(memberUniqueId);
        const wasabiKey = `${timestamp}_${safeName}`;
        
        // Pass the dynamic config
        const url = await uploadToWasabi({ 
          filepath, 
          wasabiKey, 
          mimetype, 
          wasabiConfig 
        });
        result = { wasabi_url: url };
      }

      await fs.unlink(filepath).catch(() => { });

      res.status(200).json({
        ok: true,
        filename: originalFilename,
        mimetype,
        size,
        ...result
      });
    } catch (e) {
      console.error('Upload error:', e);
      res.status(500).json({ error: e.message });
    }
  });
});

///////////////////////////////////////////////////
////////     Wasabi Presign Upload    /////////////
///////////////////////////////////////////////////

app.options('/wasabi_presign_upload', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Accept');
  res.status(204).end();
});

app.post('/wasabi_presign_upload', express.json(), async (req, res) => {
  // Extract member_unique_id from body
  const { file_name, folder_structure, mimetype, member_unique_id } = req.body;
  
  if (!file_name || typeof file_name !== "string" || !folder_structure || typeof folder_structure !== "string") {
    return res.status(400).json({ error: 'file_name and folder_structure required' });
  }

  // Get Dynamic Credentials
  const wasabiConfig = await getWasabiCredentials(member_unique_id);
  
  // Create Dynamic Client
  const client = createS3Client(wasabiConfig);

  let folder = folder_structure.replace(/^\/+/, '');
  if (folder && !folder.endsWith('/')) folder += '/';

  const key = `${folder}${file_name}`;
  const contentType = mimetype || 'application/octet-stream';

  const command = new PutObjectCommand({
    Bucket: wasabiConfig.bucket,
    Key: key,
    ContentType: contentType,
    ACL: 'public-read'
  });

  try {
    const uploadUrl = await getSignedUrl(client, command, { expiresIn: 300 });
    
    // Construct File URL dynamically based on the bucket used
    const regionStr = wasabiConfig.region ? `.${wasabiConfig.region}` : '';
    let fileUrl;
    
    if (wasabiConfig.endpoint.includes('wasabisys.com')) {
       fileUrl = `https://${wasabiConfig.bucket}.s3${regionStr}.wasabisys.com/${key}`;
    } else {
       fileUrl = `${wasabiConfig.endpoint}/${wasabiConfig.bucket}/${key}`;
    }

    res.set('Access-Control-Allow-Origin', '*');
    res.json({ uploadUrl, fileUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
///////////////////////////////////////////////////
///////////    Google Calendar    /////////////////
///////////////////////////////////////////////////

// ==== CONFIGURATION ====

const CONFIG_GOOGLE_CALENDAR = {
  CLIENT_ID: process.env.GOOGLE_CALENDAR_CLIENT_ID,
  CLIENT_SECRET: process.env.GOOGLE_CALENDAR_CLIENT_SECRET,
  JWT_SECRET: process.env.COMPANION_SECRET,
  TOKEN_EXPIRY: '5m',
  COOKIE_NAME: 'google_auth_state',
  COMPANION_DOMAIN: `https://${process.env.COMPANION_DOMAIN}`,
  SCOPES: [
    'https://www.googleapis.com/auth/calendar'
  ]
};

// ==== GOOGLE OAUTH2 CLIENT ====
const oauth2Client = new google.auth.OAuth2(
  CONFIG_GOOGLE_CALENDAR.CLIENT_ID,
  CONFIG_GOOGLE_CALENDAR.CLIENT_SECRET,
  `${CONFIG_GOOGLE_CALENDAR.COMPANION_DOMAIN}/login/google/callback`
);

// ==== STATE UTILS ====
function generateStateToken(origin) {
  return jwt.sign({ origin }, CONFIG_GOOGLE_CALENDAR.JWT_SECRET, { expiresIn: CONFIG_GOOGLE_CALENDAR.TOKEN_EXPIRY });
}
function verifyStateToken(token) {
  try {
    const decoded = jwt.verify(token, CONFIG_GOOGLE_CALENDAR.JWT_SECRET);
    return decoded.origin;
  } catch (err) {
    return null;
  }
}

// ==== LOGIN ENDPOINT ====
app.get('/login/google/calendar', (req, res) => {
  const { origin } = req.query;
  if (!origin) return res.status(400).json({ error: 'Origin parameter is required' });

  const stateToken = generateStateToken(origin);
  res.cookie(CONFIG_GOOGLE_CALENDAR.COOKIE_NAME, stateToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 5 * 60 * 1000 // 5 minutes
  });

  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: false,
    scope: CONFIG_GOOGLE_CALENDAR.SCOPES
  });
  res.redirect(url);
});

// ==== CALLBACK ENDPOINT ====
app.get('/login/google/callback', async (req, res) => {
  const { code } = req.query;
  const stateToken = req.cookies[CONFIG_GOOGLE_CALENDAR.COOKIE_NAME];
  if (!stateToken) return res.status(400).send('Missing state token');
  const origin = verifyStateToken(stateToken);
  if (!origin) return res.status(400).send('Invalid state token');
  res.clearCookie(CONFIG_GOOGLE_CALENDAR.COOKIE_NAME);

  try {
    const { tokens } = await oauth2Client.getToken(code);

    const refresh_token = tokens.refresh_token || null;
    const access_token = tokens.access_token || null;
    const expires_in = tokens.expiry_date
      ? Math.floor((tokens.expiry_date - Date.now()) / 1000)
      : null;

    const infoForJwt = {
      refresh_token,
      access_token,
      expires_in
    };

    const loginToken = jwt.sign(infoForJwt, CONFIG_GOOGLE_CALENDAR.JWT_SECRET, { expiresIn: '2m' });

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Google Calendar Authentication</title>
        <script>
          (function() {
            const token = '${loginToken}';
            const targetOrigin = '${origin}';
            const source = 'companion-google-calendar';

            if (window.opener && !window.opener.closed) {
              window.opener.postMessage({
                source: source,
                loginToken: token,
                status: 'success'
              }, targetOrigin);

              localStorage.setItem('googleCalendarRefreshToken', token);
              localStorage.setItem('googleCalendarAuthOrigin', targetOrigin);

              setTimeout(() => window.close(), 100);
            } else {
              document.getElementById('auto-close').style.display = 'none';
              document.getElementById('manual-close').style.display = 'block';
            }

            window.addEventListener('beforeunload', function() {
              if (window.opener && !window.opener.closed) {
                window.opener.postMessage({ source: source, loginToken: token, status: 'success' }, targetOrigin);
              }
            });
          })();
        </script>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 40px; }
          #manual-close { display: none; margin-top: 20px; }
          button { padding: 10px 20px; background: #4285F4; color: white; border: none; border-radius: 4px; cursor: pointer; }
        </style>
      </head>
      <body>
        <p id="auto-close">Authentication complete. Closing window...</p>
        <div id="manual-close">
          <p>Authentication complete. You may now close this window.</p>
          <button onclick="window.close()">Close Window</button>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    const safeMsg = ("" + error.message).replace(/'/g, "\\'");
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Google Calendar Error</title>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-google-calendar',
            status: 'error',
            error: '${safeMsg}'
          }, '${origin}');
          window.close();
        </script>
      </head>
      <body>
        <p>Authentication failed. Closing window...</p>
      </body>
      </html>
    `);
  }
});

// ==== TOKEN INFO VERIFICATION ENDPOINT ====
app.get('/login/tokeninfo/calendar', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ failed: true, error: 'Token is required' });

  try {
    const decoded = jwt.verify(token, CONFIG_GOOGLE_CALENDAR.JWT_SECRET);
    if (!decoded.refresh_token) {
      return res.status(401).json({ failed: true, error: 'No refresh_token present. Did user consent?' });
    }
    res.json({
      refresh_token: decoded.refresh_token,
      access_token: decoded.access_token,
      expires_in: decoded.expires_in,
      failed: false
    });
  } catch (err) {
    res.status(401).json({ failed: true, error: 'Invalid or expired token' });
  }
});


///////////////////////////////////////////////////
///////////    Outlook Calendar    ////////////////
///////////////////////////////////////////////////

const { AuthorizationCode } = require('simple-oauth2'); // USE THIS, not .create!

const CONFIG_OUTLOOK_CALENDAR = {
  CLIENT_ID: process.env.OUTLOOK_CALENDAR_CLIENT_ID,
  CLIENT_SECRET: process.env.OUTLOOK_CALENDAR_CLIENT_SECRET,
  REDIRECT_URI: `https://${process.env.COMPANION_DOMAIN}/login/outlook/callback`,
  JWT_SECRET: process.env.COMPANION_SECRET,
  TOKEN_EXPIRY: '5m',
  COOKIE_NAME: 'outlook_auth_state',
  COMPANION_DOMAIN: `https://${process.env.COMPANION_DOMAIN}`,
  AUTHORITY: 'https://login.microsoftonline.com/common',
  SCOPE: [
    'openid',
    'offline_access',
    'profile',
    'email',
    'https://graph.microsoft.com/Calendars.ReadWrite'
  ],
};

const outlookOauth2 = new AuthorizationCode({
  client: {
    id: CONFIG_OUTLOOK_CALENDAR.CLIENT_ID,
    secret: CONFIG_OUTLOOK_CALENDAR.CLIENT_SECRET
  },
  auth: {
    tokenHost: CONFIG_OUTLOOK_CALENDAR.AUTHORITY,
    authorizePath: '/oauth2/v2.0/authorize',
    tokenPath: '/oauth2/v2.0/token',
  }
});

function generateOutlookStateToken(origin) {
  return jwt.sign({ origin }, CONFIG_OUTLOOK_CALENDAR.JWT_SECRET, { expiresIn: CONFIG_OUTLOOK_CALENDAR.TOKEN_EXPIRY });
}
function verifyOutlookStateToken(token) {
  try {
    const decoded = jwt.verify(token, CONFIG_OUTLOOK_CALENDAR.JWT_SECRET);
    return decoded.origin;
  } catch (err) {
    return null;
  }
}

app.get('/login/outlook/calendar', (req, res) => {
  const { origin } = req.query;
  if (!origin) return res.status(400).json({ error: 'Origin parameter is required' });

  const stateToken = generateOutlookStateToken(origin);
  res.cookie(CONFIG_OUTLOOK_CALENDAR.COOKIE_NAME, stateToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 300000, // 5 min
  });

  const authorizationUri = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?` +
    `response_type=code` +
    `&client_id=${encodeURIComponent(CONFIG_OUTLOOK_CALENDAR.CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(CONFIG_OUTLOOK_CALENDAR.REDIRECT_URI)}` +
    `&scope=${encodeURIComponent(CONFIG_OUTLOOK_CALENDAR.SCOPE.join(' '))}` +
    `&prompt=consent`;

  console.log("MS Authorize URI:", authorizationUri);
  res.redirect(authorizationUri);
});

app.get('/login/outlook/callback', async (req, res) => {
  const { code, error, error_description } = req.query;
  const stateToken = req.cookies[CONFIG_OUTLOOK_CALENDAR.COOKIE_NAME];
  if (!stateToken) return res.status(400).send('Missing state token');
  const origin = verifyOutlookStateToken(stateToken);
  if (!origin) return res.status(400).send('Invalid state token');
  res.clearCookie(CONFIG_OUTLOOK_CALENDAR.COOKIE_NAME);

  if (error) {
    const safeMsg = (error_description || error).replace(/'/g, "\\'");
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentication Error</title>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-outlook-calendar',
            status: 'error',
            error: '${safeMsg}'
          }, '${origin}');
          window.close();
        </script>
      </head>
      <body>
        <p>Authentication failed. Closing window...</p>
      </body>
      </html>
    `);
  }

  try {
    // Exchange code for token
    const formdata = new URLSearchParams({
      client_id: CONFIG_OUTLOOK_CALENDAR.CLIENT_ID,
      client_secret: CONFIG_OUTLOOK_CALENDAR.CLIENT_SECRET,
      scope: CONFIG_OUTLOOK_CALENDAR.SCOPE.join(' '),
      code: code,
      redirect_uri: CONFIG_OUTLOOK_CALENDAR.REDIRECT_URI,
      grant_type: 'authorization_code'
    });

    const tokenEndpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
    const fetchResp = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: formdata.toString()
    });

    // For raw debug:
    const rawBody = await fetchResp.text();
    console.log("MS token endpoint raw response:", rawBody);

    let tokenObj = null;
    try {
      tokenObj = JSON.parse(rawBody);
    } catch (e) {
      // Microsoft error: not JSON
      throw new Error("Token response was not JSON: " + rawBody.slice(0, 200));
    }

    if (tokenObj.error) {
      throw new Error(`Token error: ${tokenObj.error} - ${tokenObj.error_description || ''}`);
    }

    // Now you have `tokenObj` as the parsed token JSON:
    const token = tokenObj;

    const refresh_token = token.refresh_token || null;
    const refresh_token_expires_in = token.expires_in ? `${token.expires_in}` : null;

    // Fetch user info from Microsoft Graph
    let email = null, name = null, picture = null;
    if (token.access_token) {
      try {
        const userResp = await fetch('https://graph.microsoft.com/v1.0/me', {
          method: 'GET',
          headers: { Authorization: 'Bearer ' + token.access_token }
        });
        if (userResp.ok) {
          const user = await userResp.json();
          email = user.mail || user.userPrincipalName || null;
          name = user.displayName || null;
          try {
            const picResp = await fetch('https://graph.microsoft.com/v1.0/me/photo/$value', {
              headers: { Authorization: 'Bearer ' + token.access_token }
            });
            if (picResp.ok) {
              const picBuf = await picResp.arrayBuffer();
              const base64 = Buffer.from(picBuf).toString('base64');
              picture = 'data:image/jpeg;base64,' + base64;
            }
          } catch (_) { }
        }
      } catch (e) { }
    }

    const infoForJwt = {
      refresh_token,
      refresh_token_expires_in,
      email, name, picture,
    };

    const loginToken = jwt.sign(infoForJwt, CONFIG_OUTLOOK_CALENDAR.JWT_SECRET, { expiresIn: '2m' });

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Outlook Authentication</title>
        <script>
          (function() {
            const token = '${loginToken}';
            const targetOrigin = '${origin}';
            const source = 'companion-outlook-calendar';
            if (window.opener && !window.opener.closed) {
              window.opener.postMessage({
                source: source,
                loginToken: token,
                status: 'success'
              }, targetOrigin);
              localStorage.setItem('outlookCalendarRefreshToken', token);
              localStorage.setItem('outlookCalendarAuthOrigin', targetOrigin);
              setTimeout(() => window.close(), 100);
            } else {
              document.getElementById('auto-close').style.display = 'none';
              document.getElementById('manual-close').style.display = 'block';
            }
            window.addEventListener('beforeunload', function() {
              if (window.opener && !window.opener.closed) {
                window.opener.postMessage({
                  source: source, loginToken: token, status: 'success'
                }, targetOrigin);
              }
            });
          })();
        </script>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 40px; }
          #manual-close { display: none; margin-top: 20px; }
          button { padding: 10px 20px; background: #4267B2; color: white; border: none; border-radius: 4px; cursor: pointer; }
        </style>
      </head>
      <body>
        <p id="auto-close">Authentication complete. Closing window...</p>
        <div id="manual-close">
          <p>Authentication complete. You may now close this window.</p>
          <button onclick="window.close()">Close Window</button>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    const safeMsg = ('' + err.message).replace(/'/g, "\\'");
    console.error("Outlook oauth2 callback error:", err);
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentication Error</title>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-outlook-calendar',
            status: 'error',
            error: '${safeMsg}'
          }, '${origin}');
          window.close();
        </script>
      </head>
      <body>
        <p>Authentication failed. Closing window...</p>
      </body>
      </html>
    `);
  }
});

// ==== CALENDAR TOKEN VERIFY ENDPOINT ====
app.get('/login/tokeninfo/outlook', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ failed: true, error: 'Token is required' });

  try {
    const decoded = jwt.verify(token, CONFIG_OUTLOOK_CALENDAR.JWT_SECRET);
    if (!decoded.refresh_token) {
      return res.status(401).json({ failed: true, error: 'No refresh_token present. Did user consent?' });
    }
    res.json({
      refresh_token: decoded.refresh_token,
      refresh_token_expires_in: decoded.refresh_token_expires_in,
      email: decoded.email,
      name: decoded.name,
      picture: decoded.picture,
      failed: false
    });
  } catch (err) {
    console.error("Tokeninfo/outlook error:", err);
    res.status(401).json({ failed: true, error: 'Invalid or expired token' });
  }
});


///////////////////////////////////////////////////
////////////            Zoom        ///////////////
///////////////////////////////////////////////////

const CONFIG_ZOOM = {
  // These serve as defaults if no private label is found
  DEFAULT_CLIENT_ID: process.env.ZOOM_CLIENT_ID,
  DEFAULT_CLIENT_SECRET: process.env.ZOOM_CLIENT_SECRET,
  REDIRECT_URI: `https://${process.env.COMPANION_DOMAIN}/login/zoom/callback`,
  JWT_SECRET: process.env.COMPANION_SECRET,
  TOKEN_EXPIRY: '5m',
  COOKIE_NAME: 'zoom_auth_state',
  COMPANION_DOMAIN: `https://${process.env.COMPANION_DOMAIN}`
};

// Helper: Get Dynamic Zoom Credentials
async function getZoomCredentials(memberUniqueId) {
  let credentials = {
    clientId: CONFIG_ZOOM.DEFAULT_CLIENT_ID,
    clientSecret: CONFIG_ZOOM.DEFAULT_CLIENT_SECRET
  };

  if (!memberUniqueId) return credentials;

  try {
    const response = await fetch("https://upward.page/api/1.1/wf/get_zoom_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ member: memberUniqueId }) // Prompt specified key "member"
    });

    if (response.ok) {
      const json = await response.json();
      const data = json.response || json;

      // Check if private labelled
      const isPrivateLabelled = data.private_labelled === true || data.private_labelled === "true";

      if (isPrivateLabelled) {
        if (data.zoom_client_id && data.zoom_client_secret) {
          credentials.clientId = data.zoom_client_id;
          credentials.clientSecret = data.zoom_client_secret;
        }
      }
    }
  } catch (error) {
    console.error(`[Zoom Auth] API check failed for ${memberUniqueId}:`, error.message);
  }

  return credentials;
}

// STATE TOKEN GENERATION/VERIFY
// Updated to include member_unique_id in the payload
function generateZoomStateToken(origin, memberUniqueId) {
  return jwt.sign({ origin, memberUniqueId }, CONFIG_ZOOM.JWT_SECRET, { expiresIn: CONFIG_ZOOM.TOKEN_EXPIRY });
}

function verifyZoomStateToken(token) {
  try {
    // Returns full decoded object { origin, memberUniqueId } or null
    return jwt.verify(token, CONFIG_ZOOM.JWT_SECRET);
  } catch (err) {
    return null;
  }
}

// STEP 1: Start OAuth
app.get('/login/zoom', async (req, res) => {
  const { origin, member_unique_id } = req.query; // Get member_unique_id from frontend
  if (!origin) return res.status(400).json({ error: 'Origin parameter is required' });

  // 1. Fetch Credentials (to get the correct Client ID for the URL)
  const creds = await getZoomCredentials(member_unique_id);

  // 2. Encode member_unique_id into state so we have it on callback
  const stateToken = generateZoomStateToken(origin, member_unique_id);

  res.cookie(CONFIG_ZOOM.COOKIE_NAME, stateToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 300000, // 5 min
  });

  const authorizeUrl = `https://zoom.us/oauth/authorize?` +
    `response_type=code` +
    `&client_id=${encodeURIComponent(creds.clientId)}` +
    `&redirect_uri=${encodeURIComponent(CONFIG_ZOOM.REDIRECT_URI)}` +
    `&state=${encodeURIComponent(stateToken)}`;

  res.redirect(authorizeUrl);
});

// STEP 2: OAuth2 Callback
app.get('/login/zoom/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;
  const cookieState = req.cookies[CONFIG_ZOOM.COOKIE_NAME];
  
  // Verify cookie state
  const decodedState = verifyZoomStateToken(cookieState);
  res.clearCookie(CONFIG_ZOOM.COOKIE_NAME);

  if (!decodedState || !decodedState.origin) {
    return res.status(400).send('Missing or invalid state token');
  }

  const origin = decodedState.origin;
  const memberUniqueId = decodedState.memberUniqueId;

  // Verify returned state param (CSRF check)
  if (state) {
    const checkState = verifyZoomStateToken(state);
    if (!checkState || checkState.origin !== origin) {
      return res.status(400).send('Invalid state parameter');
    }
  }

  if (error) {
    const safeMsg = (error_description || error).replace(/'/g, "\\'");
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-zoom-auth',
            status: 'error',
            error: '${safeMsg}'
          }, '${origin}');
          window.close();
        </script>
      </head>
      <body><p>Authentication failed. Closing...</p></body>
      </html>
    `);
  }

  try {
    // 1. Fetch Credentials again using the ID from the state
    const creds = await getZoomCredentials(memberUniqueId);

    // 2. Exchange code for token using dynamic creds
    const tokenEndpoint = 'https://zoom.us/oauth/token';
    const basicHeader = Buffer.from(`${creds.clientId}:${creds.clientSecret}`).toString('base64');

    const tokenResp = await fetch(`${tokenEndpoint}?grant_type=authorization_code&code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(CONFIG_ZOOM.REDIRECT_URI)}`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${basicHeader}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const tokenRaw = await tokenResp.text();
    let tokenObj;
    try { tokenObj = JSON.parse(tokenRaw); }
    catch (e) { throw new Error("Token response was not JSON: " + tokenRaw.slice(0, 100)); }

    if (tokenObj.error) {
      throw new Error(`Token error: ${tokenObj.error} - ${tokenObj.reason || ''}`);
    }

    const refresh_token = tokenObj.refresh_token || null;
    const refresh_token_expires_in = tokenObj.refresh_token_expires_in || null;

    // Try to fetch user email
    let email = null, name = null, picture = null;
    if (tokenObj.access_token) {
      try {
        const meResp = await fetch('https://api.zoom.us/v2/users/me', {
          method: 'GET',
          headers: {
            'Authorization': 'Bearer ' + tokenObj.access_token
          }
        });
        if (meResp.ok) {
          const meData = await meResp.json();
          email = meData.email || null;
          name = meData.first_name && meData.last_name ? (meData.first_name + ' ' + meData.last_name) : (meData.first_name || meData.last_name) || meData.id || null;
          picture = meData.pic_url || null;
        }
      } catch (_) { }
    }

    const infoForJwt = {
      refresh_token, refresh_token_expires_in, email, name, picture
    };
    const loginToken = jwt.sign(infoForJwt, CONFIG_ZOOM.JWT_SECRET, { expiresIn: '2m' });

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Zoom Authentication</title>
        <script>
          (function() {
            const token = '${loginToken}';
            const targetOrigin = '${origin}';
            const source = 'companion-zoom-auth';

            if (window.opener && !window.opener.closed) {
              window.opener.postMessage({
                source: source,
                loginToken: token,
                status: 'success'
              }, targetOrigin);

              localStorage.setItem('zoomRefreshToken', token);
              localStorage.setItem('zoomAuthOrigin', targetOrigin);

              setTimeout(() => window.close(), 100);
            } else {
              document.getElementById('auto-close').style.display = 'none';
              document.getElementById('manual-close').style.display = 'block';
            }
          })();
        </script>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 40px; }
          #manual-close { display: none; margin-top: 20px; }
          button { padding: 10px 20px; background: #2D8CFF; color: white; border: none; border-radius: 4px; cursor: pointer; }
        </style>
      </head>
      <body>
        <p id="auto-close">Authentication complete. Closing window...</p>
        <div id="manual-close">
          <p>Authentication complete. You may now close this window.</p>
          <button onclick="window.close()">Close Window</button>
        </div>
      </body>
      </html>
    `);
  } catch (e) {
    const safeMsg = ('' + e.message).replace(/'/g, "\\'");
    console.error("Zoom oauth2 callback error:", e);
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-zoom-auth',
            status: 'error',
            error: '${safeMsg}'
          }, '${origin}');
          window.close();
        </script>
      </head>
      <body><p>Authentication failed. Closing window...</p></body>
      </html>
    `);
  }
});

// 3. Verify JWT issued above
app.get('/login/tokeninfo/zoom', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ failed: true, error: 'Token is required' });

  try {
    const decoded = jwt.verify(token, CONFIG_ZOOM.JWT_SECRET);
    if (!decoded.refresh_token) {
      return res.status(401).json({ failed: true, error: 'No refresh_token present. Did user consent?' });
    }
    res.json({
      refresh_token: decoded.refresh_token,
      refresh_token_expires_in: decoded.refresh_token_expires_in,
      email: decoded.email,
      name: decoded.name,
      picture: decoded.picture,
      failed: false
    });
  } catch (err) {
    console.error("Tokeninfo/zoom error:", err);
    res.status(401).json({ failed: true, error: 'Invalid or expired token' });
  }
});

/////////////////////////////////////////////////////
///////////     Google Analytics   /////////////////
////////////////////////////////////////////////////

const CONFIG_GOOGLE_ANALYTICS = {
  CLIENT_ID: process.env.GOOGLE_ANALYTICS_CLIENT_ID,
  CLIENT_SECRET: process.env.GOOGLE_ANALYTICS_CLIENT_SECRET,
  JWT_SECRET: process.env.COMPANION_SECRET,
  TOKEN_EXPIRY: '5m',
  COOKIE_NAME: 'google_analytics_auth_state',
  COMPANION_DOMAIN: `https://${process.env.COMPANION_DOMAIN}`,
  SCOPES: [
    // Only what's required for Analytics property/datastream management
    "https://www.googleapis.com/auth/analytics.edit",
    "https://www.googleapis.com/auth/analytics.readonly"
  ]
};

const analyticsOAuth2Client = new google.auth.OAuth2(
  CONFIG_GOOGLE_ANALYTICS.CLIENT_ID,
  CONFIG_GOOGLE_ANALYTICS.CLIENT_SECRET,
  `${CONFIG_GOOGLE_ANALYTICS.COMPANION_DOMAIN}/login/google-analytics/callback`
);

function generateAnalyticsStateToken(origin) {
  return jwt.sign({ origin }, CONFIG_GOOGLE_ANALYTICS.JWT_SECRET, { expiresIn: CONFIG_GOOGLE_ANALYTICS.TOKEN_EXPIRY });
}
function verifyAnalyticsStateToken(token) {
  try {
    const decoded = jwt.verify(token, CONFIG_GOOGLE_ANALYTICS.JWT_SECRET);
    return decoded.origin;
  } catch (e) {
    return null;
  }
}

// === OAUTH2 LOGIN ENDPOINT ===
app.get('/login/google-analytics', (req, res) => {
  const { origin } = req.query;
  if (!origin) return res.status(400).json({ error: "Origin parameter is required" });

  const stateToken = generateAnalyticsStateToken(origin);
  res.cookie(CONFIG_GOOGLE_ANALYTICS.COOKIE_NAME, stateToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 5 * 60 * 1000 // 5 minutes
  });

  const url = analyticsOAuth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: false,
    scope: CONFIG_GOOGLE_ANALYTICS.SCOPES
  });
  res.redirect(url);
});

// === OAUTH2 CALLBACK ===
app.get('/login/google-analytics/callback', async (req, res) => {
  const { code } = req.query;
  const stateToken = req.cookies[CONFIG_GOOGLE_ANALYTICS.COOKIE_NAME];
  if (!stateToken) return res.status(400).send('Missing state token');
  const origin = verifyAnalyticsStateToken(stateToken);
  if (!origin) return res.status(400).send('Invalid state token');
  res.clearCookie(CONFIG_GOOGLE_ANALYTICS.COOKIE_NAME);

  try {
    const { tokens } = await analyticsOAuth2Client.getToken(code);

    const refresh_token = tokens.refresh_token || null;
    const access_token = tokens.access_token || null;
    const expires_in = tokens.expiry_date
      ? Math.floor((tokens.expiry_date - Date.now()) / 1000)
      : null;

    const infoForJwt = {
      refresh_token,
      access_token,
      expires_in
    };

    const loginToken = jwt.sign(infoForJwt, CONFIG_GOOGLE_ANALYTICS.JWT_SECRET, { expiresIn: '2m' });

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Google Analytics Authentication</title>
        <script>
          (function() {
            const token = '${loginToken}';
            const targetOrigin = '${origin}';
            const source = 'companion-google-analytics';

            if (window.opener && !window.opener.closed) {
              window.opener.postMessage({
                source: source,
                loginToken: token,
                status: 'success'
              }, targetOrigin);

              localStorage.setItem('googleAnalyticsRefreshToken', token);
              localStorage.setItem('googleAnalyticsAuthOrigin', targetOrigin);

              setTimeout(() => window.close(), 100);
            } else {
              document.getElementById('auto-close').style.display = 'none';
              document.getElementById('manual-close').style.display = 'block';
            }

            window.addEventListener('beforeunload', function() {
              if (window.opener && !window.opener.closed) {
                window.opener.postMessage({ source: source, loginToken: token, status: 'success' }, targetOrigin);
              }
            });
          })();
        </script>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 40px; }
          #manual-close { display: none; margin-top: 20px; }
          button { padding: 10px 20px; background: #4285F4; color: white; border: none; border-radius: 4px; cursor: pointer; }
        </style>
      </head>
      <body>
        <p id="auto-close">Authentication complete. Closing window...</p>
        <div id="manual-close">
          <p>Authentication complete. You may now close this window.</p>
          <button onclick="window.close()">Close Window</button>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    const safeMsg = ("" + error.message).replace(/'/g, "\\'");
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Google Analytics Error</title>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-google-analytics',
            status: 'error',
            error: '${safeMsg}'
          }, '${origin}');
          window.close();
        </script>
      </head>
      <body>
        <p>Authentication failed. Closing window...</p>
      </body>
      </html>
    `);
  }
});

// === TOKEN INFO VERIFICATION ENDPOINT ===
app.get('/login/tokeninfo/analytics', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ failed: true, error: 'Token is required' });

  try {
    const decoded = jwt.verify(token, CONFIG_GOOGLE_ANALYTICS.JWT_SECRET);
    if (!decoded.refresh_token) {
      return res.status(401).json({ failed: true, error: 'No refresh_token present. Did user consent?' });
    }
    res.json({
      refresh_token: decoded.refresh_token,
      access_token: decoded.access_token,
      expires_in: decoded.expires_in,
      failed: false
    });
  } catch (err) {
    res.status(401).json({ failed: true, error: 'Invalid or expired token' });
  }
});



///////////////////////////////////////////////////
//////  IPX SERVER FOR IMAGE OPTIMIZATION  ////////
///////////////////////////////////////////////////
const ipx = createIPX({
  httpStorage: ipxHttpStorage({
    domains: [
      "upward.s3.us-east-2.wasabisys.com",
      "aa70287ff58ea68c3f5d2d6e98c40119.cdn.bubble.io",
      "s3.us-east-2.wasabisys.com",
      "1house.info"
      // ,"another-allowed-remote-host.com"
    ]
    // You can also use a RegExp/string for wildcards if needed, but restrict as much as possible for security!
  })
});
app.use('/ipx', createIPXNodeServer(ipx));


///////////////////////////////////////////////////
////////////    Google Meet Auth    ///////////////
///////////////////////////////////////////////////

const CONFIG_GOOGLE_MEET = {
  CLIENT_ID: process.env.GOOGLE_MEET_CLIENT_ID,
  CLIENT_SECRET: process.env.GOOGLE_MEET_CLIENT_SECRET,
  JWT_SECRET: process.env.COMPANION_SECRET,
  TOKEN_EXPIRY: '5m',
  COOKIE_NAME: 'google_meet_auth_state',
  COMPANION_DOMAIN: `https://${process.env.COMPANION_DOMAIN}`,
  SCOPES: [
    "https://www.googleapis.com/auth/meetings.space.created"
  ]
};

const meetOauth2Client = new google.auth.OAuth2(
  CONFIG_GOOGLE_MEET.CLIENT_ID,
  CONFIG_GOOGLE_MEET.CLIENT_SECRET,
  `${CONFIG_GOOGLE_MEET.COMPANION_DOMAIN}/login/google/meet/callback`
);

function generateMeetStateToken(origin) {
  return jwt.sign({ origin }, CONFIG_GOOGLE_MEET.JWT_SECRET, { expiresIn: CONFIG_GOOGLE_MEET.TOKEN_EXPIRY });
}
function verifyMeetStateToken(token) {
  try {
    const decoded = jwt.verify(token, CONFIG_GOOGLE_MEET.JWT_SECRET);
    return decoded.origin;
  } catch (err) {
    return null;
  }
}

app.get('/login/google/meet', (req, res) => {
  const { origin } = req.query;
  if (!origin) return res.status(400).json({ error: 'Origin parameter is required' });

  const stateToken = generateMeetStateToken(origin);
  res.cookie(CONFIG_GOOGLE_MEET.COOKIE_NAME, stateToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 5 * 60 * 1000,
  });

  const url = meetOauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: false,
    scope: CONFIG_GOOGLE_MEET.SCOPES
  });
  res.redirect(url);
});

app.get('/login/google/meet/callback', async (req, res) => {
  const { code } = req.query;
  const stateToken = req.cookies[CONFIG_GOOGLE_MEET.COOKIE_NAME];
  if (!stateToken) return res.status(400).send('Missing state token');
  const origin = verifyMeetStateToken(stateToken);
  if (!origin) return res.status(400).send('Invalid state token');
  res.clearCookie(CONFIG_GOOGLE_MEET.COOKIE_NAME);

  try {
    const { tokens } = await meetOauth2Client.getToken(code);

    const refresh_token = tokens.refresh_token || null;
    const access_token = tokens.access_token || null;
    const expires_in = tokens.expiry_date
      ? Math.floor((tokens.expiry_date - Date.now()) / 1000)
      : null;

    const infoForJwt = {
      refresh_token,
      access_token,
      expires_in
    };

    const loginToken = jwt.sign(infoForJwt, CONFIG_GOOGLE_MEET.JWT_SECRET, { expiresIn: '2m' });

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Google Meet Authentication</title>
        <script>
          (function() {
            const token = '${loginToken}';
            const targetOrigin = '${origin}';
            const source = 'companion-google-meet';
            if (window.opener && !window.opener.closed) {
              window.opener.postMessage({ source, loginToken: token, status: 'success' }, targetOrigin);
              localStorage.setItem('googleMeetRefreshToken', token);
              localStorage.setItem('googleMeetAuthOrigin', targetOrigin);
              setTimeout(() => window.close(), 100);
            } else {
              document.getElementById('auto-close').style.display = 'none';
              document.getElementById('manual-close').style.display = 'block';
            }
            window.addEventListener('beforeunload', function() {
              if (window.opener && !window.opener.closed) {
                window.opener.postMessage({ source, loginToken: token, status: 'success' }, targetOrigin);
              }
            });
          })();
        </script>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 40px; }
          #manual-close { display: none; margin-top: 20px; }
          button { padding: 10px 20px; background: #4285F4; color: white; border: none; border-radius: 4px; cursor: pointer; }
        </style>
      </head>
      <body>
        <p id="auto-close">Authentication complete. Closing window...</p>
        <div id="manual-close">
          <p>Authentication complete. You may now close this window.</p>
          <button onclick="window.close()">Close Window</button>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    const safeMsg = ('' + error.message).replace(/'/g, "\\'");
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Google Meet Error</title>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-google-meet',
            status: 'error',
            error: '${safeMsg}'
          }, '${origin}');
          window.close();
        </script>
      </head>
      <body>
        <p>Authentication failed. Closing window...</p>
      </body>
      </html>
    `);
  }
});

// ==== MEET TOKEN VERIFY ENDPOINT ====
app.get('/login/tokeninfo/meet', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ failed: true, error: 'Token is required' });

  try {
    const decoded = jwt.verify(token, CONFIG_GOOGLE_MEET.JWT_SECRET);
    if (!decoded.refresh_token) {
      return res.status(401).json({ failed: true, error: 'No refresh_token present. Did user consent?' });
    }
    res.json({
      refresh_token: decoded.refresh_token,
      access_token: decoded.access_token,
      expires_in: decoded.expires_in,
      failed: false
    });
  } catch (err) {
    res.status(401).json({ failed: true, error: 'Invalid or expired token' });
  }
});


///////////////////////////////////////////////////
//      Google Login OAuth (profile only)        //
///////////////////////////////////////////////////

// ==== CONFIGURATION ====

const CONFIG_GOOGLE_LOGIN = {
  CLIENT_ID: process.env.GOOGLE_LOGIN_CLIENT_ID,
  CLIENT_SECRET: process.env.GOOGLE_LOGIN_CLIENT_SECRET,
  JWT_SECRET: process.env.COMPANION_SECRET, // or your own separate one
  TOKEN_EXPIRY: '2m',
  COOKIE_NAME: 'google_login_state',
  COMPANION_DOMAIN: `https://${process.env.COMPANION_DOMAIN}`,
  ALLOWED_REDIRECT_PATHS: ['/'],
};

// ==== GOOGLE OAUTH2 CLIENT ====
const loginOauth2Client = new google.auth.OAuth2(
  CONFIG_GOOGLE_LOGIN.CLIENT_ID,
  CONFIG_GOOGLE_LOGIN.CLIENT_SECRET,
  `${CONFIG_GOOGLE_LOGIN.COMPANION_DOMAIN}/login/google/oauth/callback`
);

// ==== UTILITY FUNCTIONS ====
function generateLoginStateToken(origin) {
  return jwt.sign({ origin }, CONFIG_GOOGLE_LOGIN.JWT_SECRET, { expiresIn: CONFIG_GOOGLE_LOGIN.TOKEN_EXPIRY });
}
function verifyLoginStateToken(token) {
  try {
    const decoded = jwt.verify(token, CONFIG_GOOGLE_LOGIN.JWT_SECRET);
    return decoded.origin;
  } catch (err) {
    return null;
  }
}

// ==== LOGIN: GOOGLE OAUTH FOR PROFILE ====
app.get('/login/google/oauth', (req, res) => {
  const { origin } = req.query;
  if (!origin) return res.status(400).json({ error: 'Origin parameter is required' });

  const stateToken = generateLoginStateToken(origin);
  res.cookie(CONFIG_GOOGLE_LOGIN.COOKIE_NAME, stateToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 120000, // 2 min
  });

  const url = loginOauth2Client.generateAuthUrl({
    access_type: 'online',
    prompt: 'select_account', // or 'consent' if you want to always show
    include_granted_scopes: true,
    scope: [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'
    ],
  });
  res.redirect(url);
});

// ==== GOOGLE OAUTH2 CALLBACK (/login/google/oauth/callback)====
app.get('/login/google/oauth/callback', async (req, res) => {
  const { code } = req.query;
  const stateToken = req.cookies[CONFIG_GOOGLE_LOGIN.COOKIE_NAME];
  if (!stateToken) return res.status(400).send('Missing state token');
  const origin = verifyLoginStateToken(stateToken);
  if (!origin) return res.status(400).send('Invalid state token');
  res.clearCookie(CONFIG_GOOGLE_LOGIN.COOKIE_NAME);

  try {
    const { tokens } = await loginOauth2Client.getToken(code);
    loginOauth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({ version: 'v2', auth: loginOauth2Client });
    const { data } = await oauth2.userinfo.get();

    // Extract names (prefer given/family, fallback split)
    let first_name = data.given_name, last_name = data.family_name;
    if (!first_name || !last_name) {
      if (data.name) {
        const parts = data.name.trim().split(/\s+/);
        first_name = parts[0];
        last_name = parts.length > 1 ? parts.slice(1).join(' ') : '';
      } else {
        first_name = last_name = '';
      }
    }

    const infoForJwt = {
      first_name: first_name,
      last_name: last_name,
      email: data.email,
      picture: data.picture
    };

    const loginToken = jwt.sign(infoForJwt, CONFIG_GOOGLE_LOGIN.JWT_SECRET, { expiresIn: CONFIG_GOOGLE_LOGIN.TOKEN_EXPIRY });

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Google OAuth Login</title>
        <script>
          (function() {
            const token = '${loginToken}';
            const targetOrigin = '${origin}';
            const source = 'companion-google-login';

            // Try postMessage to opener
            if (window.opener && !window.opener.closed) {
              window.opener.postMessage({
                source: source,
                loginToken: token,
                status: 'success'
              }, targetOrigin);

              // Fallback: localStorage
              localStorage.setItem('googleLoginToken', token);
              localStorage.setItem('googleLoginOrigin', targetOrigin);

              setTimeout(() => window.close(), 100);
            } else {
              document.getElementById('auto-close').style.display = 'none';
              document.getElementById('manual-close').style.display = 'block';
            }

            window.addEventListener('beforeunload', function() {
              if (window.opener && !window.opener.closed) {
                window.opener.postMessage({
                  source: source, loginToken: token, status: 'success'
                }, targetOrigin);
              }
            });
          })();
        </script>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 40px; }
          #manual-close { display: none; margin-top: 20px; }
          button { padding: 10px 20px; background: #4285F4; color: white; border: none; border-radius: 4px; cursor: pointer; }
        </style>
      </head>
      <body>
        <p id="auto-close">Authentication complete. Closing window...</p>
        <div id="manual-close">
          <p>Authentication complete. You may now close this window.</p>
          <button onclick="window.close()">Close Window</button>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    const safeMsg = ('' + error.message).replace(/'/g, "\\'");
    console.error("OAuth2 /oauth callback error:", error);
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentication Error</title>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-google-login',
            status: 'error',
            error: '${safeMsg}'
          }, '${origin}');
          window.close();
        </script>
      </head>
      <body>
        <p>Authentication failed. Closing window...</p>
      </body>
      </html>
    `);
  }
});

// ==== TOKEN INFO ENDPOINT FOR /login/google/oauth TOKENS ====
app.get('/login/tokeninfo/google', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ failed: true, error: 'Token is required' });

  try {
    const decoded = jwt.verify(token, CONFIG_GOOGLE_LOGIN.JWT_SECRET);

    res.json({
      first_name: decoded.first_name,
      last_name: decoded.last_name,
      email: decoded.email,
      picture: decoded.picture,
      failed: false
    });
  } catch (err) {
    console.error("Tokeninfo/google error:", err);
    res.status(401).json({ failed: true, error: 'Invalid or expired token' });
  }
});


///////////////////////////////////////////////////
//      Facebook Login OAuth (profile only)      //
///////////////////////////////////////////////////

const CONFIG_FACEBOOK_LOGIN = {
  APP_ID: process.env.FACEBOOK_APP_ID,
  APP_SECRET: process.env.FACEBOOK_APP_SECRET,
  JWT_SECRET: process.env.COMPANION_SECRET,
  TOKEN_EXPIRY: '2m',
  COOKIE_NAME: 'facebook_login_state',
  COMPANION_DOMAIN: `https://${process.env.COMPANION_DOMAIN}`
};

// ==== State Token utils ====
function generateFbLoginStateToken(origin) {
  return jwt.sign({ origin }, CONFIG_FACEBOOK_LOGIN.JWT_SECRET, { expiresIn: CONFIG_FACEBOOK_LOGIN.TOKEN_EXPIRY });
}
function verifyFbLoginStateToken(token) {
  try {
    const decoded = jwt.verify(token, CONFIG_FACEBOOK_LOGIN.JWT_SECRET);
    return decoded.origin;
  } catch {
    return null;
  }
}

// ==== FACEBOOK LOGIN START ====
app.get('/login/facebook/oauth', (req, res) => {
  const { origin } = req.query;
  if (!origin) return res.status(400).json({ error: 'Origin parameter is required' });

  const stateToken = generateFbLoginStateToken(origin);
  res.cookie(CONFIG_FACEBOOK_LOGIN.COOKIE_NAME, stateToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 120000
  });

  const redirectUri = `${CONFIG_FACEBOOK_LOGIN.COMPANION_DOMAIN}/login/facebook/oauth/callback`;
  const authUrl = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${encodeURIComponent(CONFIG_FACEBOOK_LOGIN.APP_ID)}`
    + `&redirect_uri=${encodeURIComponent(redirectUri)}`
    + `&scope=email,public_profile`
    + `&response_type=code`
    + `&state=facebook-login`;

  res.redirect(authUrl);
});

// ==== FACEBOOK OAUTH CALLBACK ====
app.get('/login/facebook/oauth/callback', async (req, res) => {
  const { code } = req.query;
  const stateToken = req.cookies[CONFIG_FACEBOOK_LOGIN.COOKIE_NAME];
  if (!stateToken) return res.status(400).send('Missing state token');
  const origin = verifyFbLoginStateToken(stateToken);
  if (!origin) return res.status(400).send('Invalid state token');
  res.clearCookie(CONFIG_FACEBOOK_LOGIN.COOKIE_NAME);

  try {
    // 1. Exchange code for access_token:
    const redirectUri = `${CONFIG_FACEBOOK_LOGIN.COMPANION_DOMAIN}/login/facebook/oauth/callback`;
    const accessResp = await axios.get('https://graph.facebook.com/v19.0/oauth/access_token', {
      params: {
        client_id: CONFIG_FACEBOOK_LOGIN.APP_ID,
        client_secret: CONFIG_FACEBOOK_LOGIN.APP_SECRET,
        redirect_uri: redirectUri,
        code
      }
    });
    const access_token = accessResp.data.access_token;

    // 2. Fetch user info
    const userResp = await axios.get('https://graph.facebook.com/me', {
      params: {
        fields: 'id,first_name,last_name,email,picture.type(large)',
        access_token
      }
    });
    const user = userResp.data;

    const infoForJwt = {
      first_name: user.first_name || "",
      last_name: user.last_name || "",
      email: user.email || "",
      picture: user.picture?.data?.url || ""
    };

    const loginToken = jwt.sign(infoForJwt, CONFIG_FACEBOOK_LOGIN.JWT_SECRET, { expiresIn: CONFIG_FACEBOOK_LOGIN.TOKEN_EXPIRY });

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Facebook OAuth Login</title>
        <script>
          (function() {
            const token = '${loginToken}';
            const targetOrigin = '${origin}';
            const source = 'companion-facebook-login';

            if (window.opener && !window.opener.closed) {
              window.opener.postMessage({
                source: source,
                loginToken: token,
                status: 'success'
              }, targetOrigin);

              localStorage.setItem('facebookLoginToken', token);
              localStorage.setItem('facebookLoginOrigin', targetOrigin);

              setTimeout(() => window.close(), 100);
            } else {
              document.getElementById('auto-close').style.display = 'none';
              document.getElementById('manual-close').style.display = 'block';
            }

            window.addEventListener('beforeunload', function() {
              if (window.opener && !window.opener.closed) {
                window.opener.postMessage({
                  source: source,
                  loginToken: token,
                  status: 'success'
                }, targetOrigin);
              }
            });
          })();
        </script>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 40px; }
          #manual-close { display: none; margin-top: 20px; }
          button { padding: 10px 20px; background: #1877f3; color: white; border: none; border-radius: 4px; cursor: pointer; }
        </style>
      </head>
      <body>
        <p id="auto-close">Authentication complete. Closing window...</p>
        <div id="manual-close">
          <p>Authentication complete. You may now close this window.</p>
          <button onclick="window.close()">Close Window</button>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    const safeMsg = ('' + error.message).replace(/'/g, "\\'");
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentication Error</title>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-facebook-login',
            status: 'error',
            error: '${safeMsg}'
          }, '${origin}');
          window.close();
        </script>
      </head>
      <body>
        <p>Authentication failed. Closing window...</p>
      </body>
      </html>
    `);
  }
});

// ==== TOKEN INFO ENDPOINT FOR /login/facebook/oauth TOKENS ====
app.get('/login/tokeninfo/facebook', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ failed: true, error: 'Token is required' });

  try {
    const decoded = jwt.verify(token, CONFIG_FACEBOOK_LOGIN.JWT_SECRET);

    res.json({
      first_name: decoded.first_name,
      last_name: decoded.last_name,
      email: decoded.email,
      picture: decoded.picture,
      failed: false
    });
  } catch (err) {
    res.status(401).json({ failed: true, error: 'Invalid or expired token' });
  }
});


///////////////////////////////////////////////////
///   Apple Login OAuth (one-time profile only)  ///
///////////////////////////////////////////////////

// Config (set your Service ID and Companion domain)
const APPLE_CLIENT_ID = process.env.APPLE_CLIENT_ID;  // Your Service ID (ex: com.example.web)
const APPLE_REDIRECT_URI = `https://${process.env.COMPANION_DOMAIN}/login/apple/callback`;
const APPLE_JWT_SECRET = process.env.COMPANION_SECRET; // Use your app's JWT secret
const APPLE_COOKIE_NAME = 'apple_login_state';

// STATE HANDLING
const TOKEN_EXPIRY = '2m';
function generateAppleState(origin) {
  return jwt.sign({ origin }, APPLE_JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
}
function verifyAppleState(token) {
  try {
    const decoded = jwt.verify(token, APPLE_JWT_SECRET);
    return decoded.origin;
  } catch (e) { return null; }
}

// 1. Start Apple login
app.get('/login/apple/oauth', (req, res) => {
  const { origin } = req.query;
  if (!origin) return res.status(400).json({ error: 'Origin parameter is required' });

  const stateToken = generateAppleState(origin);
  res.cookie(APPLE_COOKIE_NAME, stateToken, {
    httpOnly: true, secure: true, sameSite: 'none', maxAge: 120000
  });

  const params = new URLSearchParams({
    client_id: APPLE_CLIENT_ID,
    redirect_uri: APPLE_REDIRECT_URI,
    response_type: 'code id_token',
    scope: 'name email',
    response_mode: 'form_post',
    state: 'apple-login'
  });
  res.redirect(`https://appleid.apple.com/auth/authorize?${params.toString()}`);
});

// 2. Apple callback (POST)
app.post('/login/apple/callback', express.urlencoded({ extended: true }), (req, res) => {
  // Apple will POST: code, id_token, state, user (only first sign-in)
  const stateToken = req.cookies[APPLE_COOKIE_NAME];
  if (!stateToken) return res.status(400).send('Missing state token');
  const origin = verifyAppleState(stateToken);
  if (!origin) return res.status(400).send('Invalid state token');
  res.clearCookie(APPLE_COOKIE_NAME);

  // Extract user info
  let first_name = "", last_name = "", email = "", picture = null;
  if (req.body.user) {
    try {
      const userObj = JSON.parse(req.body.user);
      first_name = userObj.name ? userObj.name.firstName : "";
      last_name = userObj.name ? userObj.name.lastName : "";
      email = userObj.email || "";
    } catch (e) { }
  }
  // If not present, fallback: email from id_token
  if (!email && req.body.id_token) {
    try {
      const decoded = JSON.parse(Buffer.from(req.body.id_token.split('.')[1], 'base64').toString());
      email = decoded.email || "";
    } catch (e) { }
  }

  const infoForJwt = {
    first_name,
    last_name,
    email,
    picture: null
  };
  const loginToken = jwt.sign(infoForJwt, APPLE_JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Apple OAuth Login</title>
      <script>
        (function() {
          const token = '${loginToken}';
          const targetOrigin = '${origin}';
          const source = 'companion-apple-login';

          if (window.opener && !window.opener.closed) {
            window.opener.postMessage({ source, loginToken: token, status: 'success' }, targetOrigin);
            localStorage.setItem('appleLoginToken', token);
            localStorage.setItem('appleLoginOrigin', targetOrigin);
            setTimeout(() => window.close(), 100);
          } else {
            document.getElementById('auto-close').style.display = 'none';
            document.getElementById('manual-close').style.display = 'block';
          }
          window.addEventListener('beforeunload', function() {
            if (window.opener && !window.opener.closed) {
              window.opener.postMessage({ source, loginToken: token, status: 'success' }, targetOrigin);
            }
          });
        })();
      </script>
      <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 40px; }
        #manual-close { display: none; margin-top: 20px; }
        button { padding: 10px 20px; background: #000000; color: white; border: none; border-radius: 4px; cursor: pointer; }
      </style>
    </head>
    <body>
      <p id="auto-close">Authentication complete. Closing window...</p>
      <div id="manual-close">
        <p>Authentication complete. You may now close this window.</p>
        <button onclick="window.close()">Close Window</button>
      </div>
    </body>
    </html>
  `);
});

// 3. Token verification endpoint
app.get('/login/tokeninfo/apple', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ failed: true, error: 'Token is required' });
  try {
    const decoded = jwt.verify(token, APPLE_JWT_SECRET);
    res.json({
      first_name: decoded.first_name,
      last_name: decoded.last_name,
      email: decoded.email,
      picture: null,
      failed: false
    });
  } catch (err) {
    res.status(401).json({ failed: true, error: 'Invalid or expired token' });
  }
});



///////////////////////////////////////////////////
//         LinkedIn Login OAuth (OpenID)         //
///////////////////////////////////////////////////

const CONFIG_LINKEDIN_LOGIN = {
  CLIENT_ID: process.env.LINKEDIN_CLIENT_ID,
  CLIENT_SECRET: process.env.LINKEDIN_CLIENT_SECRET,
  JWT_SECRET: process.env.COMPANION_SECRET,
  TOKEN_EXPIRY: '2m',
  COOKIE_NAME: 'linkedin_login_state',
  COMPANION_DOMAIN: `https://${process.env.COMPANION_DOMAIN}`
};

function generateLinkedinLoginStateToken(origin) {
  return jwt.sign({ origin }, CONFIG_LINKEDIN_LOGIN.JWT_SECRET, { expiresIn: CONFIG_LINKEDIN_LOGIN.TOKEN_EXPIRY });
}
function verifyLinkedinLoginStateToken(token) {
  try {
    const decoded = jwt.verify(token, CONFIG_LINKEDIN_LOGIN.JWT_SECRET);
    return decoded.origin;
  } catch {
    return null;
  }
}

// ==== 1. Kick off login ====
app.get('/login/linkedin/oauth', (req, res) => {
  const { origin } = req.query;
  if (!origin) return res.status(400).json({ error: 'Origin parameter is required' });

  const stateToken = generateLinkedinLoginStateToken(origin);
  res.cookie(CONFIG_LINKEDIN_LOGIN.COOKIE_NAME, stateToken, {
    httpOnly: true, secure: true, sameSite: 'none', maxAge: 120000
  });

  const redirect_uri = `${CONFIG_LINKEDIN_LOGIN.COMPANION_DOMAIN}/login/linkedin/callback`;

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CONFIG_LINKEDIN_LOGIN.CLIENT_ID,
    redirect_uri,
    state: 'linkedin-login',
    scope: 'openid email profile'
  });

  res.redirect('https://www.linkedin.com/oauth/v2/authorization?' + params.toString());
});

// ==== 2. Handle callback and POST to plugin ====
app.get('/login/linkedin/callback', async (req, res) => {
  const { code } = req.query;
  const stateToken = req.cookies[CONFIG_LINKEDIN_LOGIN.COOKIE_NAME];
  if (!stateToken) return res.status(400).send('Missing state token');
  const origin = verifyLinkedinLoginStateToken(stateToken);
  if (!origin) return res.status(400).send('Invalid state token');
  res.clearCookie(CONFIG_LINKEDIN_LOGIN.COOKIE_NAME);

  try {
    // 1. Exchange code for access_token & id_token
    const redirect_uri = `${CONFIG_LINKEDIN_LOGIN.COMPANION_DOMAIN}/login/linkedin/callback`;

    const tokenResp = await axios.post('https://www.linkedin.com/oauth/v2/accessToken', new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri,
      client_id: CONFIG_LINKEDIN_LOGIN.CLIENT_ID,
      client_secret: CONFIG_LINKEDIN_LOGIN.CLIENT_SECRET
    }).toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const access_token = tokenResp.data.access_token;
    const id_token = tokenResp.data.id_token;

    // 2. Decode the id_token JWT for name/email/profile
    let first_name = "", last_name = "", email = "", picture = null;
    if (id_token) {
      try {
        // decode JWT
        const payload = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64').toString());
        // LinkedIn OpenID typically gives these
        first_name = payload.given_name || payload.name || "";
        last_name = payload.family_name || "";
        email = payload.email || payload.email_verified || "";
        picture = payload.picture || null;
        // Fallback: sometimes "sub" or other properties
        if (!email && payload.sub) email = payload.sub;
      } catch (e) { }
    }

    // If fallback, still get legacy info per old method:
    if (!first_name || !last_name || !email) {
      try {
        // r_liteprofile, r_emailaddress are still allowed together with openid
        const [profileResp, emailResp] = await Promise.all([
          axios.get('https://api.linkedin.com/v2/me?projection=(id,localizedFirstName,localizedLastName,profilePicture(displayImage~:playableStreams))', {
            headers: { Authorization: 'Bearer ' + access_token }
          }),
          axios.get('https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))', {
            headers: { Authorization: 'Bearer ' + access_token }
          })
        ]);
        const profile = profileResp.data;
        email = (emailResp.data.elements[0]['handle~'] && emailResp.data.elements[0]['handle~'].emailAddress) || email;
        first_name = profile.localizedFirstName || first_name;
        last_name = profile.localizedLastName || last_name;

        if (profile.profilePicture && profile.profilePicture['displayImage~'] && profile.profilePicture['displayImage~'].elements) {
          const elementsArray = profile.profilePicture['displayImage~'].elements;
          picture = elementsArray[elementsArray.length - 1].identifiers[0].identifier;
        }
      } catch { }
    }

    const infoForJwt = {
      first_name: first_name || "",
      last_name: last_name || "",
      email: email || "",
      picture: picture || null
    };

    const loginToken = jwt.sign(infoForJwt, CONFIG_LINKEDIN_LOGIN.JWT_SECRET, { expiresIn: CONFIG_LINKEDIN_LOGIN.TOKEN_EXPIRY });

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>LinkedIn OAuth Login</title>
        <script>
          (function() {
            const token = '${loginToken}';
            const targetOrigin = '${origin}';
            const source = 'companion-linkedin-login';

            if (window.opener && !window.opener.closed) {
              window.opener.postMessage({
                source: source,
                loginToken: token,
                status: 'success'
              }, targetOrigin);

              localStorage.setItem('linkedinLoginToken', token);
              localStorage.setItem('linkedinLoginOrigin', targetOrigin);

              setTimeout(() => window.close(), 100);
            } else {
              document.getElementById('auto-close').style.display = 'none';
              document.getElementById('manual-close').style.display = 'block';
            }

            window.addEventListener('beforeunload', function() {
              if (window.opener && !window.opener.closed) {
                window.opener.postMessage({
                  source: source, loginToken: token, status: 'success'
                }, targetOrigin);
              }
            });
          })();
        </script>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 40px; }
          #manual-close { display: none; margin-top: 20px; }
          button { padding: 10px 20px; background: #0077b5; color: white; border: none; border-radius: 4px; cursor: pointer; }
        </style>
      </head>
      <body>
        <p id="auto-close">Authentication complete. Closing window...</p>
        <div id="manual-close">
          <p>Authentication complete. You may now close this window.</p>
          <button onclick="window.close()">Close Window</button>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    const safeMsg = ('' + error.message).replace(/'/g, "\\'");
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>LinkedIn Auth Error</title>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-linkedin-login',
            status: 'error',
            error: '${safeMsg}'
          }, '${origin}');
          window.close();
        </script>
      </head>
      <body>
        <p>Authentication failed. Closing window...</p>
      </body>
      </html>
    `);
  }
});

// ==== 3. Verify JWT endpoint for plugin ====
app.get('/login/tokeninfo/linkedin', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ failed: true, error: 'Token is required' });
  try {
    const decoded = jwt.verify(token, CONFIG_LINKEDIN_LOGIN.JWT_SECRET);
    res.json({
      first_name: decoded.first_name,
      last_name: decoded.last_name,
      email: decoded.email,
      picture: decoded.picture,
      failed: false
    });
  } catch (err) {
    res.status(401).json({ failed: true, error: 'Invalid or expired token' });
  }
});


///////////////////////////////////////////////////
/////////    GOOGLE DRIVE PICKER    ///////////////
///////////////////////////////////////////////////


const CONFIG_GDRIVE_PICKER = {
  CLIENT_ID:     '231297576692-c70ckvdglp7vtnamitq3h2ccrodkdi8a.apps.googleusercontent.com',      // format: XXXXXXXXXXXX-abc123.apps.googleusercontent.com
  CLIENT_SECRET: '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',
  JWT_SECRET:    'super_secret_change_me',
  COMPANION_DOMAIN: 'services.upward.page',
  COOKIE_NAME:   'gdrive_picker_state',
  TOKEN_EXPIRY:  '3m',
  SCOPE:         'https://www.googleapis.com/auth/drive.file'
};

const gdriveOauth2Client = new google.auth.OAuth2(
  '231297576692-c70ckvdglp7vtnamitq3h2ccrodkdi8a.apps.googleusercontent.com',
  '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',
  `https://services.upward.page/login/gdrive_picker/callback`
);

function generateGDriveStateToken(origin) {
  return jwt.sign({ origin }, CONFIG_GDRIVE_PICKER.JWT_SECRET, { expiresIn: CONFIG_GDRIVE_PICKER.TOKEN_EXPIRY });
}
function verifyGDriveStateToken(token) {
  try {
    const decoded = jwt.verify(token, CONFIG_GDRIVE_PICKER.JWT_SECRET);
    return decoded.origin;
  } catch (err) {
    return null;
  }
}

// --- 1. Start Google Drive Picker OAuth
app.get('/login/gdrive_picker', (req, res) => {
  const { origin } = req.query;
  if (!origin) return res.status(400).json({ error: 'Origin parameter is required' });

  // Set state as signed JWT with origin
  const stateToken = generateGDriveStateToken(origin);
  res.cookie(CONFIG_GDRIVE_PICKER.COOKIE_NAME, stateToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 3 * 60 * 1000 // 3 minutes
  });

  const url = gdriveOauth2Client.generateAuthUrl({
    access_type: 'online',
    prompt: 'select_account',
    include_granted_scopes: false,
    scope: [CONFIG_GDRIVE_PICKER.SCOPE]
    // No need to set redirect_uri, set in client config above.
  });

  res.redirect(url);
});

// --- 2. OAuth2 callback
app.get('/login/gdrive_picker/callback', async (req, res) => {
  const { code } = req.query;
  const stateToken = req.cookies[CONFIG_GDRIVE_PICKER.COOKIE_NAME];
  if (!stateToken) return res.status(400).send('Missing state token');
  const origin = verifyGDriveStateToken(stateToken);
  if (!origin) return res.status(400).send('Invalid or expired state token');
  res.clearCookie(CONFIG_GDRIVE_PICKER.COOKIE_NAME);

  try {
    const { tokens } = await gdriveOauth2Client.getToken(code);
    const access_token = tokens.access_token;

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Google Drive Auth</title>
        <script>
          (function() {
            window.opener && window.opener.postMessage({
              source: 'companion-google-login',
              status: 'success',
              access_token: '${access_token}'
            }, '${origin}');
            setTimeout(() => window.close(), 150);
          })();
        </script>
      </head>
      <body>
        <p>Google Drive authentication complete. You may close this window.</p>
      </body>
      </html>
    `);
  } catch (error) {
    const safeMsg = ("" + (error && error.message || error)).replace(/'/g, "\\'");
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Google Drive Auth Failed</title>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-google-login',
            status: 'error',
            error: '${safeMsg}'
          }, '${origin}');
          window.close();
        </script>
      </head>
      <body>
        <p>Google authentication failed. You may close this window.</p>
      </body>
      </html>
    `);
  }
});


///////////////////////////////////////////////////
//////////    UNLAYER MUX UPLOAD    ///////////////
///////////////////////////////////////////////////

app.options('/unlayer_editor_mux_upload', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
  res.status(204).end();
});

app.post('/unlayer_editor_mux_upload', async (req, res) => {
  try {
    const { filename, mimetype } = req.body || {};
    if (!filename) return res.status(400).json({ error: "Missing filename" });
    // Optionally validate file extension or mimetype

    // 1. Create Mux Direct Upload (get upload URL and asset ID)
    const external_id = randomUUID();

    const response = await fetch('https://api.mux.com/video/v1/uploads', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + Buffer.from(`${MUX_TOKEN_ID}:${MUX_TOKEN_SECRET}`).toString('base64')
      },
      body: JSON.stringify({
        new_asset_settings: {
          playback_policies: ['public'],
          passthrough: filename,
          meta: { external_id }
        },
        cors_origin: "*"
      })
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`MUX upload create failed: ${response.status}: ${text}`);
    }

    const json = await response.json();
    const { url: upload_url, id: upload_id } = json.data || {};

    // 2. Respond with upload_url and id. Frontend should upload using a PUT to that URL.
    res.status(200).json({
      ok: true,
      upload_url,
      upload_id,
      external_id
    });
  } catch (e) {
    console.error('unlayer_editor_mux_upload error:', e);
    res.status(500).json({ error: e.message });
  }
});


// (Requires Mux Node SDK or fetch)
app.get('/unlayer_mux_upload_status', async (req, res) => {
  try {
    const { upload_id } = req.query;
    if (!upload_id) return res.status(400).json({ error: "Missing upload_id" });
    // Query Mux Direct Uploads API to get the associated asset
    const response = await fetch('https://api.mux.com/video/v1/uploads/' + upload_id, {
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${MUX_TOKEN_ID}:${MUX_TOKEN_SECRET}`).toString('base64')
      }
    });
    if (!response.ok) throw new Error("Mux status error");
    const data = await response.json();
    const upload = data.data;
    if (upload.asset_id) {
      // now get the playback ID!
      const assetResp = await fetch('https://api.mux.com/video/v1/assets/' + upload.asset_id, {
        headers: {
          'Authorization': 'Basic ' + Buffer.from(`${MUX_TOKEN_ID}:${MUX_TOKEN_SECRET}`).toString('base64')
        }
      });
      const assetData = await assetResp.json();
      const asset = assetData.data;
      if (asset.playback_ids && asset.playback_ids[0]) {
        // Return the ready-to-play Mux "Playback URL!"
        res.json({
          playback_id: asset.playback_ids[0].id,
          playback_url: `https://stream.mux.com/${asset.playback_ids[0].id}.m3u8`,
          status: asset.status
        });
        return;
      }
    }
    // Not ready yet
    res.json({ status: upload.status });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});



///////////////////////////////////////////////////
///////////         GPT        /////////////////
///////////////////////////////////////////////////

app.post("/gpt", async (req, res) => {
  const { prompt, instructions } = req.body;
  if (!prompt) return res.status(400).json({ error: "No prompt" });

  // Build API payload
  const payload = {
    model: "gpt-4.1",
    input: prompt,
    tools: [{ type: "web_search_preview" }]
  };
  // Only add `instructions` if it exists
  if (instructions) {
    payload.instructions = instructions;
  }

  try {
    const openaiRes = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + process.env.OPENAI_API_KEY
      },
      body: JSON.stringify(payload)
    });

    const data = await openaiRes.json();
    // Find the "message" type output
    const messageOutput = data.output?.find(item => item.type === "message");
    // Find the content (text) in the message output
    const outputText = messageOutput?.content?.find(c => c.type === "output_text")?.text || "";

    res.json({ content: outputText });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


///////////////////////////////////////////////////
///////////      MUX ASSET        /////////////////
///////////////////////////////////////////////////

app.put('/mux/assets/:asset_id/master-access', async (req, res) => {
  const asset_id = req.params.asset_id;
  const muxRes = await fetch(`https://api.mux.com/video/v1/assets/${asset_id}/master-access`, {
    method: 'PUT',
    headers: {
      'Authorization': 'Basic ' + Buffer.from(`${MUX_TOKEN_ID}:${MUX_TOKEN_SECRET}`).toString('base64'),
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify(req.body)
  });
  const data = await muxRes.json();
  res.json(data);
});

app.get('/mux/assets/:asset_id', async (req, res) => {
  const asset_id = req.params.asset_id;
  const muxRes = await fetch(`https://api.mux.com/video/v1/assets/${asset_id}`, {
    headers: {
      'Authorization': 'Basic ' + Buffer.from(`${MUX_TOKEN_ID}:${MUX_TOKEN_SECRET}`).toString('base64'),
      'Accept': 'application/json'
    }
  });
  const data = await muxRes.json();
  res.json(data);
});



///////////////////////////////////////////////////
///////////      DNS Records      /////////////////
///////////////////////////////////////////////////

app.get('/dns', async (req, res) => {
  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    // Perform lookups in parallel
    const [a, aaaa, mx, txt, ns, cname, soa] = await Promise.allSettled([
      dns.resolve4(domain).catch(() => null), // A Records
      dns.resolve6(domain).catch(() => null), // AAAA Records
      dns.resolveMx(domain).catch(() => null), // MX Records
      dns.resolveTxt(domain).catch(() => null), // TXT Records
      dns.resolveNs(domain).catch(() => null), // NS Records
      dns.resolveCname(domain).catch(() => null), // CNAME Records
      dns.resolveSoa(domain).catch(() => null)  // SOA Records
    ]);

    res.json({
      domain,
      records: {
        A: a.value,
        AAAA: aaaa.value,
        MX: mx.value,
        TXT: txt.value ? txt.value.flat() : null, // Flatten array of arrays
        NS: ns.value,
        CNAME: cname.value,
        SOA: soa.value
      }
    });

  } catch (error) {
    // If the domain itself is invalid or completely unresolvable
    res.status(500).json({ error: `DNS lookup failed: ${error.message}` });
  }
});




///////////////////////////////////////////////////
///////////         Server        /////////////////
///////////////////////////////////////////////////

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

const PORT = process.env.PORT || 3020;
const server = app.listen(PORT, () => {
  console.log(`✅ Server running at port ${PORT}`);
});

companion.socket(server, options);
