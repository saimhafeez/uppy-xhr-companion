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

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

const PORT = process.env.PORT || 3020;
const server = app.listen(PORT, () => {
  console.log(`✅ Server running at port ${PORT}`);
});

companion.socket(server, options);
