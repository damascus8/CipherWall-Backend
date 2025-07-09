require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
app.use(cors());
app.use(express.json());

const client = new MongoClient(process.env.MONGO_URI);
let db;

client.connect().then(() => {
  db = client.db("cipherwall").collection("messages");
  console.log("✅ Connected to MongoDB");
});

// Save encrypted/plaintext message (with optional password)
app.post("/api/save", async (req, res) => {
  const { encrypted, type, payload, password } = req.body;
  if (!payload) return res.status(400).json({ error: "No payload provided" });

  // 🔒 Hash password if provided
  let hashedPassword = null;
  if (password) {
    const salt = await bcrypt.genSalt(10);
    hashedPassword = await bcrypt.hash(password, salt);
  }

  // ⏰ Set expiry 24h from now
  const expiryDate = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  const result = await db.insertOne({
    encrypted,
    type,
    payload,
    password: hashedPassword,
    createdAt: new Date(),
    expiresAt: expiryDate
  });

  res.json({ id: result.insertedId });
});

// Fetch message by ID (and check expiry)
app.get("/api/fetch/:id", async (req, res) => {
  try {
    const doc = await db.findOne({ _id: new ObjectId(req.params.id) });

    if (!doc) return res.status(404).json({ error: "Not found" });

    // ⛔ Auto-expiry logic
    if (doc.expiresAt && new Date() > new Date(doc.expiresAt)) {
      return res.status(410).json({ error: "Message expired" });
    }

    res.json({
      encrypted: doc.encrypted,
      type: doc.type,
      payload: doc.payload,
      password: !!doc.password // just indicate if password protected
    });
  } catch {
    res.status(400).json({ error: "Invalid ID" });
  }
});

// Home route
app.get("/", (req, res) => {
  res.send("✅ CipherWall Backend is running.");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
