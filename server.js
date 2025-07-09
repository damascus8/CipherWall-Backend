require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const CryptoJS = require("crypto-js");

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
app.post("/api/save", async (req, res) => {
  const { encrypted, type, payload } = req.body;
  if (!payload) return res.status(400).json({ error: "No payload provided" });

  const result = await db.insertOne({ encrypted, type, payload, createdAt: new Date() });
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
  const { payload, key, type } = req.body;

  try {
    if (!payload || !key || !type) {
      return res.status(400).json({ error: "Missing parameters" });
    }

    let decrypted = "";

    if (type === "aes") {
      const bytes = CryptoJS.AES.decrypt(payload, key);
      decrypted = bytes.toString(CryptoJS.enc.Utf8);
    } else if (type === "caesar") {
      decrypted = caesarDecrypt(payload, parseInt(key));
    } else {
      return res.status(400).json({ error: "Unsupported decryption type" });
    }

    if (!decrypted) throw new Error("Failed to decrypt");

    res.json({ decrypted });
  } catch (err) {
    console.error("❌ Backend decryption error:", err.message);
    res.status(400).json({ error: "Invalid key or corrupted data" });
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
