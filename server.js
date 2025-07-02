require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const companion = require('@uppy/companion');
const formidable = require('formidable');
const fs = require('fs/promises');
const AWS = require('aws-sdk');
const fetch = require('node-fetch');
const { randomUUID } = require('crypto');
const path = require('path');
const cors = require('cors');

// Wasabi Config (Use process.env for secrets in real deploys!)
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

// S3: Wasabi
const s3 = new AWS.S3({
  endpoint: WASABI_ENDPOINT,
  region: WASABI_REGION,
  accessKeyId: WASABI_KEY,
  secretAccessKey: WASABI_SECRET,
  signatureVersion: 'v4',
});

const isVideoOrAudio = mimetype =>
  mimetype && (
    mimetype.startsWith('video/') ||
    mimetype.startsWith('audio/') ||
    mimetype === 'application/mp4'
  );

async function uploadToWasabi({ fileData, wasabiKey, mimetype }) {
  const url = await s3.getSignedUrlPromise('putObject', {
    Bucket: WASABI_BUCKET,
    Key: wasabiKey,
    ContentType: mimetype || 'application/octet-stream',
    Expires: 600,
    ACL: 'public-read',
  });
  const resp = await fetch(url, {
    method: 'PUT',
    headers: {
      'Content-Type': mimetype || 'application/octet-stream',
      'x-amz-acl': 'public-read'
    },
    body: fileData,
  });
  if (!resp.ok) {
    const msg = await resp.text()
    throw new Error(`Wasabi PUT failed: ${resp.status} - ${msg}`)
  }
  return `https://${WASABI_BUCKET}.s3.${WASABI_REGION}.wasabisys.com/${wasabiKey}`;
}

async function uploadToMux({ fileData, mimetype, originalFilename }) {
  const external_id = randomUUID();

  const response = await fetch('https://api.mux.com/video/v1/uploads', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Basic ' + Buffer.from(`${MUX_TOKEN_ID}:${MUX_TOKEN_SECRET}`).toString('base64'),
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
    throw new Error(`MUX upload create failed: ${response.status}: ${text}`)
  }
  const json = await response.json();
  const upload_url = json.data.url;
  const upload_id = json.data.id;

  const uploadResp = await fetch(upload_url, {
    method: 'PUT',
    headers: {
      'Content-Type': mimetype || 'application/octet-stream',
      'Origin': '*'
    },
    body: fileData
  });
  if (!uploadResp.ok) {
    const text = await uploadResp.text();
    throw new Error(`MUX upload PUT failed: ${uploadResp.status}: ${text}`)
  }

  return {
    mux_upload_id: upload_id,
    upload_url,
    external_id
  };
}

// ---- Express Setup

const app = express();

// --- Generic CORS for all API endpoints
app.use(cors({ origin: '*', credentials: false }));

// --- Body parser (for session/cookies)
app.use(bodyParser.json({ limit: '50mb' }));

app.use(session({
  secret: process.env.COMPANION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,       // must be false unless on HTTPS custom domain!
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// ---- Uppy Companion middleware (cloud providers)
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

// ---- Your /upload endpoint!
app.options('/upload', (req, res) => {
  // CORS options/preflight
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, OPTIONS, POST');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
  res.status(204).end();
});

app.post('/upload', (req, res) => {
  const form = formidable({ multiples: false, uploadDir: UPLOAD_DIR, keepExtensions: true });
  form.parse(req, async (err, fields, files) => {
    if (err) {
      res.status(500).json({error: err.message});
      return;
    }
    try {
      const uploaded = (files.file && files.file[0]) || files[Object.keys(files)[0]][0];
      const { filepath, originalFilename, mimetype, size } = uploaded;
      const timestamp = Date.now();
      const safeName = originalFilename.replace(/[^\w.\-]/g, '_');
      const fileData = await fs.readFile(filepath);

      let result = {};
      if (isVideoOrAudio(mimetype)) {
        result = await uploadToMux({ fileData, mimetype, originalFilename });
      } else {
        const wasabiKey = `${timestamp}_${safeName}`;
        const url = await uploadToWasabi({ fileData, wasabiKey, mimetype });
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
      res.status(500).json({ error: e.message });
    }
  });
});

// ---- 404 fallback
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ---- Start up, enable ws
const PORT = process.env.PORT || 3020;
const server = app.listen(PORT, () => {
  console.log(`✅ Server running at port ${PORT}`);
});

// ---- WebSockets for Companion events (must pass the http.Server instance)
companion.socket(server, options);
