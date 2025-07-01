// index.js
import express from 'express'
import formidable from 'formidable'
import fetch from 'node-fetch'
import fs from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { mkdir } from 'node:fs/promises'
import { randomUUID } from 'crypto'
import AWS from 'aws-sdk'
import session from 'express-session'
import bodyParser from 'body-parser'
import * as dotenv from 'dotenv'
import { app as companionApp, socket as companionSocket } from '@uppy/companion'

// Load .env
dotenv.config()

// env safety: set all these in Render.com ENV vars!
const {
  GOOGLE_KEY, GOOGLE_SECRET,
  DROPBOX_KEY, DROPBOX_SECRET,
  ONEDRIVE_KEY, ONEDRIVE_SECRET,
  COMPANION_SECRET,
  COMPANION_DOMAIN,
  WASABI_BUCKET, WASABI_REGION, WASABI_ENDPOINT, WASABI_KEY, WASABI_SECRET,
  MUX_TOKEN_ID, MUX_TOKEN_SECRET
} = process.env

// For file uploads (see Render's docs about /tmp dir)
const UPLOAD_DIR = '/opt/render/project/tmp/uploads'
await mkdir(UPLOAD_DIR, { recursive: true })

// AWS Client
const s3 = new AWS.S3({
  endpoint: WASABI_ENDPOINT,
  region: WASABI_REGION,
  accessKeyId: WASABI_KEY,
  secretAccessKey: WASABI_SECRET,
  signatureVersion: 'v4',
})

const isVideoOrAudio = (mimetype) =>
  mimetype && (
    mimetype.startsWith('video/') ||
    mimetype.startsWith('audio/') ||
    mimetype === 'application/mp4'
  )

async function uploadToWasabi({ fileData, wasabiKey, mimetype }) {
  const url = await s3.getSignedUrlPromise('putObject', {
    Bucket: WASABI_BUCKET,
    Key: wasabiKey,
    ContentType: mimetype || 'application/octet-stream',
    Expires: 600,
  })
  const resp = await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': mimetype || 'application/octet-stream' },
    body: fileData,
  })
  if (!resp.ok) {
    const msg = await resp.text()
    throw new Error(`Wasabi PUT failed: ${resp.status} - ${msg}`)
  }
  return `https://${WASABI_BUCKET}.s3.${WASABI_REGION}.wasabisys.com/${wasabiKey}`;
}

async function uploadToMux({ fileData, mimetype, originalFilename }) {
  const external_id = randomUUID();

  // 1. Create direct upload URL
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
  })
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`MUX upload create failed: ${response.status}: ${text}`)
  }
  const json = await response.json();
  const upload_url = json.data.url;
  const upload_id = json.data.id;

  // 2. Upload the vid to mux
  const uploadResp = await fetch(upload_url, {
    method: 'PUT',
    headers: {
      'Content-Type': mimetype || 'application/octet-stream',
      'Origin': '*'
    },
    body: fileData
  })
  if (!uploadResp.ok) {
    const text = await uploadResp.text();
    throw new Error(`MUX upload PUT failed: ${uploadResp.status}: ${text}`)
  }

  return { mux_upload_id: upload_id, upload_url, external_id }
}

const app = express()
app.use(bodyParser.json())
app.use(session({
  secret: COMPANION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,       // For HTTP/WS in development. Set true in prod over HTTPS.
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}))

// ---- Uppy Companion Middleware ----
const companionOptions = {
  providerOptions: {
    drive: { key: GOOGLE_KEY, secret: GOOGLE_SECRET },
    dropbox: { key: DROPBOX_KEY, secret: DROPBOX_SECRET },
    onedrive: { key: ONEDRIVE_KEY, secret: ONEDRIVE_SECRET }
  },
  server: {
    host: COMPANION_DOMAIN,
    protocol: 'https'
  },
  filePath: '/opt/render/project/tmp',
  secret: COMPANION_SECRET,
  debug: true,
  uploadUrls: ['.*'] // allow all
}
app.use(companionApp(companionOptions))

// ---- XHR Upload Endpoint (/upload) ----
app.post('/upload', (req, res) => {
  const form = formidable({ multiples: false, uploadDir: UPLOAD_DIR, keepExtensions: true })

  form.parse(req, async (err, fields, files) => {
    const headers = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'OPTIONS, POST, GET',
      'Access-Control-Max-Age': 2592000,
    }
    if (err) {
      res.writeHead(500, headers)
      res.end(JSON.stringify({ error: err.message }))
      return
    }
    try {
      const uploaded = (files.file && files.file[0]) || files[Object.keys(files)[0]][0]
      const { filepath, originalFilename, mimetype, size } = uploaded
      const timestamp = Date.now()
      const safeName = originalFilename.replace(/[^\w.\-]/g, '_')
      const fileData = await fs.readFile(filepath)

      let result = {}
      if (isVideoOrAudio(mimetype)) {
        result = await uploadToMux({ fileData, mimetype, originalFilename })
      } else {
        const wasabiKey = `${timestamp}_${safeName}`
        const url = await uploadToWasabi({ fileData, wasabiKey, mimetype })
        result = { wasabi_url: url }
      }

      await fs.unlink(filepath).catch(() => { })

      res.writeHead(200, headers)
      res.end(JSON.stringify({
        ok: true,
        filename: originalFilename,
        mimetype,
        size,
        ...result
      }))
    } catch (e) {
      res.writeHead(500, headers)
      res.end(JSON.stringify({ error: e.message }))
    }
  })
})

// ---- Optionally health check ----
app.get('/health', (req, res) => {
  res.json({ status: 'ok' })
})

const PORT = process.env.PORT || 3020
const server = app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`)
})
// WebSocket for Companion status
companionSocket(server, companionOptions)
