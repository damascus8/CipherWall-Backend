require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const CryptoJS = require("crypto-js");
const bcrypt = require("bcrypt");

const app = express();
app.use(cors());
app.use(express.json());

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
    // Caesar decryption
    
    // else if (doc.type === "caesar") {


    //   const shift = parseInt(key);
    //   decrypted = doc.payload
    //     .split("")
    //     .map(c => {
    //       const base = c >= "a" && c <= "z" ? 97 : 65;
    //       return String.fromCharCode((c.charCodeAt(0) - base - shift + 26) % 26 + base);
    //     })
    //     .join("");
    
    //   }


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


// app.get("/api/message/:id", async (req, res) => {
//   const { id } = req.params;
//   try {
//     const record = await db.collection("messages").findOne({ _id: new ObjectId(id) });
//     console.log("record"+record);
//     if (!record) return res.status(404).json({ error: "Message not found" });

//     res.json({ payload: record.payload, type: record.type });
//   } catch (err) {
//     res.status(500).json({ error: "Failed to retrieve message" });
//   }
// });
//


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

/////////////////////////////////
// image upload

/**
const multer = require("multer");
const storage = multer.memoryStorage();
const upload = multer({ storage });


// 🔐 Save Encrypted Image
app.post("/api/upload-image", upload.single("image"), async (req, res) => {
  const { key } = req.body;
  const imageBuffer = req.file?.buffer;

  if (!key || !imageBuffer) {
    return res.status(400).json({ error: "Missing key or image." });
  }

  try {
    const encrypted = CryptoJS.AES.encrypt(
      imageBuffer.toString("base64"), // Encrypt as base64 string
      key
    ).toString();

    const result = await db.insertOne({
      type: "image",
      encrypted: true,
      payload: encrypted,
      createdAt: new Date(),
    });

    res.json({ id: result.insertedId });
  } catch (err) {
    console.error("Image upload error:", err.message);
    res.status(500).json({ error: "Failed to encrypt image." });
  }
});



app.post("/api/decrypt-image", async (req, res) => {
  const { id, key } = req.body;
  if (!id || !key) return res.status(400).json({ error: "Missing id or key." });

  try {
    const doc = await db.findOne({ _id: new ObjectId(id) });
    if (!doc || doc.type !== "image") {
      return res.status(404).json({ error: "Image not found." });
    }

    const bytes = CryptoJS.AES.decrypt(doc.payload, key);
    const base64 = bytes.toString(CryptoJS.enc.Utf8);
    if (!base64) throw new Error("Incorrect key");

    const buffer = Buffer.from(base64, "base64");
    res.setHeader("Content-Type", "image/png"); // or jpeg
    res.send(buffer);
  } catch (err) {
    console.error("Decrypt image error:", err.message);
    res.status(500).json({ error: "Failed to decrypt image." });
  }
});

 */

// ✅ Save encrypted image (with optional password)
app.post("/api/image/upload", async (req, res) => {
  const { imageData, key } = req.body;
  if (!imageData) return res.status(400).json({ error: "Missing image data" });

  let hashedKey = null;
  if (key) {
    hashedKey = await bcrypt.hash(key, 10);
  }

  const result = await db.insertOne({
    type: "image",
    payload: imageData,
    key: hashedKey,
    createdAt: new Date(),
  });

  res.json({ id: result.insertedId });
});

// ✅ Decrypt image by ID + key
app.post("/api/image/decrypt", async (req, res) => {
  const { id, key } = req.body;
  if (!id) return res.status(400).json({ error: "Missing ID" });

  const doc = await db.findOne({ _id: new ObjectId(id), type: "image" });
  if (!doc) return res.status(404).json({ error: "Image not found" });

  if (doc.key) {
    const match = await bcrypt.compare(key || "", doc.key);
    if (!match) return res.status(403).json({ error: "Incorrect key" });
  }

  res.json({ decrypted: doc.payload });
});