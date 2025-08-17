const { initFirebaseAdminFromEnv, authenticate } = require("./auth-middleware");

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const CryptoJS = require("crypto-js");
const bcrypt = require("bcrypt");

const app = express();


//// ✅ Initialize Firebase Admin from env
initFirebaseAdminFromEnv();


app.use(cors());
app.use(express.json());

// ✅ Protect all /api routes
app.use("/api", authenticate);

// code to test mongoose connection


mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Connected'))
.catch((err) => console.error('❌ MongoDB Error:', err));
//
//remove above line if dont work





const client = new MongoClient(process.env.MONGO_URI);
let db;

client.connect().then(() => {
  const coll = client.db("cipherwall").collection("messages");
  db = coll;
  coll.createIndex({ createdAt: 1 }, { expireAfterSeconds: 3600 });
  console.log("✅ Connected & TTL index set");
});

// Save endpoint – hashes key if provided (AES/Caesar)
app.post("/api/save", async (req, res) => {
  const { encrypted, type, payload, key } = req.body;
  if (!payload) return res.status(400).json({ error: "No payload provided." });

  let hashedKey = null;
  if (key && ["aes", "caesar"].includes(type)) {
    hashedKey = await bcrypt.hash(key, 10);
  }

  const result = await db.insertOne({
    encrypted,
    type,
    payload,
    key: hashedKey,
    createdAt: new Date(),
  });
  res.json({ id: result.insertedId });
});

// Fetch endpoint – returns doc
app.get("/api/fetch/:id", async (req, res) => {
  try {
    const doc = await db.findOne({ _id: new ObjectId(req.params.id) });
    if (!doc) return res.status(404).json({ error: "Not found." });
    res.json(doc);
  } catch {
    res.status(400).json({ error: "Invalid ID." });
  }
});

// Decrypt endpoint – compares key, then decrypts payload
app.post("/api/decrypt", async (req, res) => {
  const { id, key } = req.body;
  if (!id || !key) return res.status(400).json({ error: "Missing id or key." });

  try {
    const doc = await db.findOne({ _id: new ObjectId(id) });
    if (!doc) return res.status(404).json({ error: "Message not found." });

    // Validate key if encrypted
    if (doc.encrypted && doc.key) {
      const match = await bcrypt.compare(key, doc.key);
      if (!match) return res.status(403).json({ error: "Incorrect key." });
    }

    let decrypted = "";

    // AES decryption
    if (doc.type === "aes") {
      const bytes = CryptoJS.AES.decrypt(doc.payload, key);
      decrypted = bytes.toString(CryptoJS.enc.Utf8);
    }


else if (doc.type === "caesar") {
  const shift = parseInt(key, 10) % 26;
  decrypted = doc.payload.split('').map(char => {
    if (char >= 'A' && char <= 'Z') {
      return String.fromCharCode(((char.charCodeAt(0) - 65 - shift + 26) % 26) + 65);
    }
    if (char >= 'a' && char <= 'z') {
      return String.fromCharCode(((char.charCodeAt(0) - 97 - shift + 26) % 26) + 97);
    }
    return char; // Keep space, symbols, digits, punctuation
  }).join('');
}




    // Other cipher types not supported here
    else {
      return res.status(400).json({ error: "Unsupported cipher type." });
    }

    if (!decrypted) throw new Error("Decryption failed");

    res.json({ decrypted });
  } catch (e) {
    console.error("❌ /api/decrypt error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get("/", (_, res) => res.send("✅ CipherWall backend is running."));
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Listening on port ${PORT}`));



// Fetch endpoint – returns doc
app.get("/api/message/:id", async (req, res) => {
  try {
    const doc = await db.findOne({ _id: new ObjectId(req.params.id) });
    if (!doc) return res.status(404).json({ error: "Not found." });
    res.json(doc);
  } catch {
    res.status(400).json({ error: "Invalid ID." });
  }
});

////////////////////////////adding file code



// ------------------- Image Encryption Dependencies -------------------

const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const { Readable } = require('stream');

// Image upload
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// MongoDB model
const ImageSchema = new mongoose.Schema({
  data: Buffer,
  iv: String,
  keyHash: String,
});
const EncryptedImage = mongoose.model('EncryptedImage', ImageSchema);

// ------------------- Image Encryption API -------------------
app.post('/api/encrypt-image', upload.single('image'), async (req, res) => {
  console.info("into encryptimg api 1");
  console.info("AVC",req.file);
  console.info("AVC",req.body.password);
  const { password } = req.body;
  const imageBuffer = req.file.buffer;
console.info("into encryptimg api 2");
  const key = crypto.createHash('sha256').update(password).digest(); // Derive key
  const iv = crypto.randomBytes(16);
  console.info("into encryptimg api 3");
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(imageBuffer), cipher.final()]);
console.info("into encryptimg api 4");
  const image = new EncryptedImage({
    data: encrypted,
    iv: iv.toString('hex'),
    keyHash: crypto.createHash('sha256').update(password).digest('hex'),
  });

  const saved = await image.save();
  res.json({ id: saved._id });
});

// // ------------------- Image Decryption API -------------------
app.get('/api/decrypt-image/:id', async (req, res) => {
  const { key } = req.query;
  const imgDoc = await EncryptedImage.findById(req.params.id);
  if (!imgDoc) return res.status(404).send('Image not found');

  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  if (keyHash !== imgDoc.keyHash) return res.status(401).send('Invalid key');

  const iv = Buffer.from(imgDoc.iv, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', crypto.createHash('sha256').update(key).digest(), iv);
  const decrypted = Buffer.concat([decipher.update(imgDoc.data), decipher.final()]);

  res.contentType('image/png');
  res.send(decrypted);
});
 

//////////////////////////////////////

// check mongo connectoion

app.get('/test-mongo', async (req, res) => {
  try {
    await mongoose.connection.db.admin().ping();
    res.send('✅ MongoDB is connected');
  } catch (err) {
    res.status(500).send('❌ MongoDB connection failed');
  }
});
