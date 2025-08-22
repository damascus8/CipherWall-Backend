// // auth-middleware.js
// const admin = require("firebase-admin");

// let initialized = false;

// function initFirebaseAdminFromEnv() {
//   if (initialized) return;
//   const raw = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
//   if (!raw) throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_KEY in env");

//   const serviceAccount = JSON.parse(raw);
//   admin.initializeApp({
//     credential: admin.credential.cert(serviceAccount),
//   });
//   initialized = true;
// }

// async function authenticate(req, res, next) {
//   const header = req.headers.authorization || "";
//   const token = header.startsWith("Bearer ") ? header.slice(7) : null;
//   if (!token) return res.status(401).json({ error: "No token provided" });

//   try {
//     const decoded = await admin.auth().verifyIdToken(token);
//     req.user = decoded; // contains uid, email, phone_number, etc
//     next();
//   } catch (err) {
//     console.error("Auth failed:", err.message);
//     res.status(401).json({ error: "Invalid or expired token" });
//   }
// }

// module.exports = { initFirebaseAdminFromEnv, authenticate };

// auth-middleware.js
const admin = require("firebase-admin");

let initialized = false;

// 🔹 Initialize Firebase Admin using service account JSON from .env
function initFirebaseAdminFromEnv() {
  if (initialized) return;

  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_KEY; // updated env name
  if (!raw) throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_KEY in env");

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(raw);
  } catch (err) {
    throw new Error("Invalid JSON in FIREBASE_SERVICE_ACCOUNT_KEY");
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });

  initialized = true;
  console.log("✅ Firebase Admin initialized");
}

// 🔹 Middleware to verify Firebase ID token
async function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded; // contains uid, email, etc
    next();
  } catch (err) {
    console.error("❌ Firebase Auth failed:", err.message);
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

module.exports = { initFirebaseAdminFromEnv, authenticate };
