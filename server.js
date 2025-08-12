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
fs.mkdir(UPLOAD_DIR, { recursive: true }).catch(() => {});

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

async function uploadToWasabi({ filepath, wasabiKey, mimetype }) {
  const fileStream = fsSync.createReadStream(filepath);

  const command = new PutObjectCommand({
    Bucket: WASABI_BUCKET,
    Key: wasabiKey,
    ContentType: mimetype || 'application/octet-stream',
    ACL: 'public-read'
  });

  const url = await getSignedUrl(s3, command, { expiresIn: 600 });

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
  return `https://${WASABI_BUCKET}.s3.${WASABI_REGION}.wasabisys.com/${wasabiKey}`;
}

async function uploadToMux({ filepath, mimetype, originalFilename }) {
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
        passthrough: originalFilename,
        meta: { external_id }
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

app.post('/upload', (req, res) => {
  const form = new formidable.IncomingForm({
    multiples: false,
    uploadDir: UPLOAD_DIR,
    keepExtensions: true,
    maxFileSize: 2 * 1024 * 1024 * 1024
  });

  req.on('aborted', () => {
    console.warn('⚠️ Request aborted by the client.');
    form.emit('error', new Error('Client aborted the request.'));
  });

  form.on('fileBegin', (name, file) => {
    console.log(`Upload started: ${file.originalFilename}`);
  });
  form.on('file', (name, file) => {
    console.log(`File uploaded: ${file.originalFilename}`);
  });
  form.on('end', () => {
    console.log('Formidable parse complete');
  });
  form.on('error', err => {
    console.error('Formidable internal error:', err);
  });

  form.parse(req, async (err, fields, files) => {
    if (err) {
      console.error('Formidable error:', err);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Formidable error: ' + err.message });
      }
      return;
    }
    try {
      const uploaded = (files.file && files.file[0]) || files[Object.keys(files)[0]][0];
      const { filepath, originalFilename, mimetype, size } = uploaded;
      const timestamp = Date.now();
      const safeName = originalFilename.replace(/[^\w.\-]/g, '_');

      let result = {};
      if (isVideoOrAudio(mimetype)) {
        result = await uploadToMux({ filepath, mimetype, originalFilename });
      } else {
        const wasabiKey = `${timestamp}_${safeName}`;
        const url = await uploadToWasabi({ filepath, wasabiKey, mimetype });
        result = { wasabi_url: url };
      }

      await fs.unlink(filepath).catch(() => {});

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
  ALLOWED_REDIRECT_PATHS: ['/'],
};

// ==== GOOGLE OAUTH2 CLIENT ====
const oauth2Client = new google.auth.OAuth2(
  CONFIG_GOOGLE_CALENDAR.CLIENT_ID,
  CONFIG_GOOGLE_CALENDAR.CLIENT_SECRET,
  `${CONFIG_GOOGLE_CALENDAR.COMPANION_DOMAIN}/login/google/callback`
);
google.options({ auth: oauth2Client });

// ==== UTILITY FUNCTIONS ====
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

// ==== LOGIN: GOOGLE CALENDAR WITH REFRESH TOKEN ====
app.get('/login/google/calendar', (req, res) => {
  const { origin } = req.query;
  if (!origin) return res.status(400).json({ error: 'Origin parameter is required' });

  const stateToken = generateStateToken(origin);
  res.cookie(CONFIG_GOOGLE_CALENDAR.COOKIE_NAME, stateToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 300000, // 5 min
  });

  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent', // Always prompt for consent to force refresh_token
    include_granted_scopes: true,
    scope: [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/calendar',
    ],
  });
  res.redirect(url);
});

// ==== GOOGLE OAUTH2 CALLBACK ====
app.get('/login/google/callback', async (req, res) => {
  const { code } = req.query;
  const stateToken = req.cookies[CONFIG_GOOGLE_CALENDAR.COOKIE_NAME];
  if (!stateToken) return res.status(400).send('Missing state token');
  const origin = verifyStateToken(stateToken);
  if (!origin) return res.status(400).send('Invalid state token');
  res.clearCookie(CONFIG_GOOGLE_CALENDAR.COOKIE_NAME);

  try {
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // User info
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data } = await oauth2.userinfo.get();

    const refresh_token = tokens.refresh_token || null;
    const refresh_token_expires_in = tokens.expiry_date
      ? Math.floor((tokens.expiry_date - Date.now()) / 1000)
      : null;

    const infoForJwt = {
      refresh_token,
      refresh_token_expires_in,
      email: data.email,
      name: data.name,
      picture: data.picture,
    };

    const loginToken = jwt.sign(infoForJwt, CONFIG_GOOGLE_CALENDAR.JWT_SECRET, { expiresIn: '2m' });

    // If 'refresh_token' present, send as calendar source, else regular login
    const isCalendar = refresh_token !== null;
    const postMessageSource = isCalendar ? 'companion-google-calendar' : 'companion-google-login';
    const storageTokenKey = isCalendar ? 'googleCalendarRefreshToken' : 'googleAuthToken';
    const storageOriginKey = isCalendar ? 'googleCalendarAuthOrigin' : 'googleAuthOrigin';

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Google Authentication</title>
        <script>
          (function() {
            const token = '${loginToken}';
            const targetOrigin = '${origin}';
            const source = '${postMessageSource}';

            // Try immediate postMessage to popup opener
            if (window.opener && !window.opener.closed) {
              window.opener.postMessage({
                source: source,
                loginToken: token,
                status: 'success'
              }, targetOrigin);

              // Fallback: store in localStorage
              localStorage.setItem('${storageTokenKey}', token);
              localStorage.setItem('${storageOriginKey}', targetOrigin);

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
    console.error("OAuth2 callback error:", error); // log for debugging
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentication Error</title>
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

// ==== CALENDAR TOKEN VERIFY ENDPOINT ====
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
      refresh_token_expires_in: decoded.refresh_token_expires_in,
      email: decoded.email,
      name: decoded.name,
      picture: decoded.picture,
      failed: false
    });
  } catch (err) {
    console.error("Tokeninfo/calendar error:", err);
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

  const authorizationUri = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?`+
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
          } catch(_) {}
        }
      } catch(e) {}
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
  CLIENT_ID: process.env.ZOOM_CLIENT_ID,
  CLIENT_SECRET: process.env.ZOOM_CLIENT_SECRET,
  REDIRECT_URI: `https://${process.env.COMPANION_DOMAIN}/login/zoom/callback`,
  JWT_SECRET: process.env.COMPANION_SECRET,
  TOKEN_EXPIRY: '5m',
  COOKIE_NAME: 'zoom_auth_state',
  COMPANION_DOMAIN: `https://${process.env.COMPANION_DOMAIN}`
};

// STATE TOKEN GENERATION/VERIFY
function generateZoomStateToken(origin) {
  return jwt.sign({ origin }, CONFIG_ZOOM.JWT_SECRET, { expiresIn: CONFIG_ZOOM.TOKEN_EXPIRY });
}
function verifyZoomStateToken(token) {
  try {
    const decoded = jwt.verify(token, CONFIG_ZOOM.JWT_SECRET);
    return decoded.origin;
  } catch (err) {
    return null;
  }
}

// STEP 1: Start OAuth
app.get('/login/zoom', (req, res) => {
  const { origin } = req.query;
  if (!origin) return res.status(400).json({ error: 'Origin parameter is required' });

  const stateToken = generateZoomStateToken(origin);

  res.cookie(CONFIG_ZOOM.COOKIE_NAME, stateToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 300000, // 5 min
  });

  const authorizeUrl = `https://zoom.us/oauth/authorize?` +
    `response_type=code` +
    `&client_id=${encodeURIComponent(CONFIG_ZOOM.CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(CONFIG_ZOOM.REDIRECT_URI)}` +
    `&state=${encodeURIComponent(stateToken)}`; // Pass state

  res.redirect(authorizeUrl);
});

// STEP 2: OAuth2 Callback
app.get('/login/zoom/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;
  const cookieState = req.cookies[CONFIG_ZOOM.COOKIE_NAME];
  let origin = verifyZoomStateToken(cookieState);
  res.clearCookie(CONFIG_ZOOM.COOKIE_NAME);

  // If state param is present, verify it
  if (state) {
    // If malicious state, delete auth cookie and abort
    const stateOrigin = verifyZoomStateToken(state);
    if (!stateOrigin) {
      return res.status(400).send('Invalid state token');
    }
    origin = stateOrigin;
  }
  if (!origin) return res.status(400).send('Missing state token');

  if (error) {
    const safeMsg = (error_description || error).replace(/'/g, "\\'");
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentication Error</title>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-zoom-auth',
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
    const tokenEndpoint = 'https://zoom.us/oauth/token';
    const basicHeader = Buffer.from(`${CONFIG_ZOOM.CLIENT_ID}:${CONFIG_ZOOM.CLIENT_SECRET}`).toString('base64');

    const tokenResp = await fetch(`${tokenEndpoint}?grant_type=authorization_code&code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(CONFIG_ZOOM.REDIRECT_URI)}`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${basicHeader}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
      // Body not needed for Zoom's API (params in URL)
    });

    const tokenRaw = await tokenResp.text();
    let tokenObj;
    try { tokenObj = JSON.parse(tokenRaw); }
    catch (e) { throw new Error("Token response was not JSON: " + tokenRaw.slice(0, 100)); }

    if (tokenObj.error) {
      throw new Error(`Token error: ${tokenObj.error} - ${tokenObj.reason||''}`);
    }

    const refresh_token = tokenObj.refresh_token || null;
    // Zoom tokens typically expire_in is access token validity (default 1h), but refresh tokens live 15 years or until revoked
    const refresh_token_expires_in = tokenObj.refresh_token_expires_in || null; // Not always present

    // Try to fetch user email (optional)
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
          // For Zoom, fetching a profile picture URL is not always possible (pro accounts)
          picture = meData.pic_url || null;
        }
      } catch(_) {}
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
        <title>Authentication Error</title>
        <script>
          window.opener && window.opener.postMessage({
            source: 'companion-zoom-auth',
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

// 3. Verify JWT issued above (used by Bubble plugin code)
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
    "https://www.googleapis.com/auth/analytics.edit"
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
      "aa70287ff58ea68c3f5d2d6e98c40119.cdn.bubble.io"
      // ,"another-allowed-remote-host.com"
    ]
    // You can also use a RegExp/string for wildcards if needed, but restrict as much as possible for security!
  })
});
app.use('/ipx', createIPXNodeServer(ipx));



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
