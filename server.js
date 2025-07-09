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

// Connect to DB and ensure TTL index
client.connect().then(() => {
  const collection = client.db("cipherwall").collection("messages");
  db = collection;
  collection.createIndex({ createdAt: 1 }, { expireAfterSeconds: 3600 }); // ⏳ 1 hr TTL
  console.log("✅ Connected to MongoDB");
});

// Save encrypted/plaintext message
// app.post("/api/save", async (req, res) => {
//   const { encrypted, type, payload } = req.body;
//   if (!payload) return res.status(400).json({ error: "No payload provided" });

//   const result = await db.insertOne({ encrypted, type, payload, createdAt: new Date() });
//   res.json({ id: result.insertedId });
// });

app.post("/api/save", async (req, res) => {
  const { encrypted, type, payload, key } = req.body;

  if (!payload) return res.status(400).json({ error: "No payload provided" });

  let hashedKey = null;
  if (key) {
    const saltRounds = 10;
    hashedKey = await bcrypt.hash(key, saltRounds);
  }

  const result = await db.insertOne({
    encrypted,
    type,
    payload,
    key: hashedKey, // Optional: saved hashed
    createdAt: new Date(),
  });

  res.json({ id: result.insertedId });
});




// Fetch message by ID
app.get("/api/fetch/:id", async (req, res) => {
  try {
    const doc = await db.findOne({ _id: new ObjectId(req.params.id) });
    if (!doc) return res.status(404).json({ error: "Not found" });
    res.json(doc);
  } catch {
    res.status(400).json({ error: "Invalid ID" });
  }
});

// ✅ Backend Decryption Route
app.post("/api/decrypt", async (req, res) => {
  const { id, key } = req.body;

  if (!id || !key) {
    return res.status(400).json({ error: "Missing ID or key" });
  }

  try {
    const doc = await db.findOne({ _id: new ObjectId(id) });

    if (!doc) return res.status(404).json({ error: "Message not found" });

    // Compare key if encrypted
    if (doc.encrypted && doc.key) {
      const isMatch = await bcrypt.compare(key, doc.key);
      if (!isMatch) return res.status(403).json({ error: "Incorrect key" });
    }

    // Decrypt message
    let decrypted = "";

    if (doc.type === "aes") {
      const bytes = CryptoJS.AES.decrypt(doc.payload, key);
      decrypted = bytes.toString(CryptoJS.enc.Utf8);
    } else if (doc.type === "caesar") {
      decrypted = caesarDecrypt(doc.payload, parseInt(key));
    } else {
      return res.status(400).json({ error: "Unsupported decryption type" });
    }

    if (!decrypted) throw new Error("Failed to decrypt");

    res.json({ decrypted });
  } catch (err) {
    console.error("❌ Backend decryption error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});




function caesarDecrypt(str, shift) {
  return str
    .split("")
    .map((char) => {
      if (char.match(/[a-z]/)) {
        return String.fromCharCode(
          ((char.charCodeAt(0) - 97 - shift + 26) % 26) + 97
        );
      } else if (char.match(/[A-Z]/)) {
        return String.fromCharCode(
          ((char.charCodeAt(0) - 65 - shift + 26) % 26) + 65
        );
      }
      return char;
    })
    .join("");
}

// Default homepage route
app.get("/", (req, res) => {
  res.send("✅ CipherWall Backend is running.");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
