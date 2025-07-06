require("dotenv").config();
const express = require("express");
const cors = require("cors");
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

// Save encrypted message
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
