require('dotenv').config();
const express = require('express');
const AWS = require('aws-sdk');
const fetch = require('node-fetch');
const { randomUUID } = require('crypto');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs/promises');
const fsSync = require('fs');
const cors = require('cors');
const { Server, FileStore, EVENTS } = require('tus-node-server');

// ============== CONFIG =================

const WASABI_BUCKET = process.env.WASABI_BUCKET;
const WASABI_REGION = process.env.WASABI_REGION;
const WASABI_ENDPOINT = process.env.WASABI_ENDPOINT;
const WASABI_KEY = process.env.WASABI_KEY;
const WASABI_SECRET = process.env.WASABI_SECRET;
const MUX_TOKEN_ID = process.env.MUX_TOKEN_ID;
const MUX_TOKEN_SECRET = process.env.MUX_TOKEN_SECRET;

// ============== S3/Wasabi SETUP ==============

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

// ============== STREAMING UPLOAD HELPERS ==============

async function uploadToWasabi({ filepath, wasabiKey, mimetype }) {
  const fileStream = fsSync.createReadStream(filepath);
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
    body: fileStream
  });
  if (!resp.ok) {
    const msg = await resp.text();
    throw new Error(`Wasabi PUT failed: ${resp.status} - ${msg}`)
  }
  return `https://${WASABI_BUCKET}.s3.${WASABI_REGION}.wasabisys.com/${wasabiKey}`;
}

async function uploadToMux({ filepath, mimetype, originalFilename }) {
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
    throw new Error(`MUX upload PUT failed: ${uploadResp.status}: ${text}`)
  }
  return {
    mux_upload_id: upload_id,
    upload_url,
    external_id
  };
}

// ================== EXPRESS & TUS ===================

const app = express();
app.use(cors({ origin: '*', credentials: false }));
app.use(bodyParser.json({ limit: '50mb' })); // not needed for tus but safe for other endpoints
app.use(session({
  secret: process.env.COMPANION_SECRET || 'secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// ========== TUS SERVER SETUP ============
const TUS_UPLOAD_DIR = path.join(__dirname, 'tus_uploads');
fs.mkdir(TUS_UPLOAD_DIR, { recursive: true }).catch(() => {});

const tusServer = new Server();
tusServer.datastore = new FileStore({ path: '/files', directory: TUS_UPLOAD_DIR });

// Helper to decode Upload-Metadata header
// See: https://tus.io/protocols/resumable-upload.html#upload-metadata
function parseTusMetadata(str) {
  if (!str) return {};
  // str: "filename dmlkZW8ubXA0,filetype dmlkZW8vbXA0"
  return Object.fromEntries(str.split(',')
    .map(pair => {
      const [k, v=""] = pair.trim().split(' ');
      return [k, Buffer.from(v, 'base64').toString('utf8')];
    })
  );
}

// === POST-PROCESS EACH UPLOAD IMMEDIATELY ON FINISH ===
tusServer.on(EVENTS.EVENT_UPLOAD_COMPLETE, async event => {
  try {
    const { id, upload_metadata } = event.file;
    const filepath = path.join(TUS_UPLOAD_DIR, id);
    const metadata = parseTusMetadata(upload_metadata); // filename/filetype guaranteed from Uppy client config
    const originalFilename = metadata.filename || `upload_${id}`;
    const mimetype = metadata.filetype || metadata.type || 'application/octet-stream';
    const timestamp = Date.now();
    const safeName = originalFilename.replace(/[^\w.\-]/g, '_');

    console.log(`📦 Upload complete: ${originalFilename} (${mimetype})`);

    // Decide destination and process (stream)
    let uploadResult;
    if (isVideoOrAudio(mimetype)) {
      uploadResult = await uploadToMux({ filepath, mimetype, originalFilename });
      console.log('🎥 Uploaded to Mux:', uploadResult);
    } else {
      const wasabiKey = `${timestamp}_${safeName}`;
      const url = await uploadToWasabi({ filepath, wasabiKey, mimetype });
      uploadResult = { wasabi_url: url };
      console.log('📁 Uploaded to Wasabi:', uploadResult);
    }

    // Always remove temp file after processing
    await fs.unlink(filepath).catch(() => {});
    console.log(`🗑️ Removed temp file ${filepath}`);
  } catch (e) {
    console.error(`❌ Error handling TUS upload:`, e);
  }
});

// ----- TUS SERVER MOUNT -----
app.all('/files/*', (req, res) => { tusServer.handle(req, res); });

// Optional: home/help route
app.get('/', (req, res) => {
  res.send('Uppy Tus + Wasabi+Mux relay is running.<br><br>Upload with Uppy Tus to /files/');
});

// Fallback 404
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// --- Start server
const PORT = process.env.PORT || 3020;
const server = app.listen(PORT, () => {
  console.log(`✅ App + tus-node-server running at port ${PORT}`);
});
