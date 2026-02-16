require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
app.use(cors());
app.use(express.json());

const db = new Database("app.db");

// --- DB init
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('resident','partner','admin')),
  status TEXT NOT NULL CHECK (status IN ('active','pending','blocked')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

// --- helper: create token
function signToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, status: user.status },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// --- auth middleware
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const [type, token] = header.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({ message: "No token" });
  }
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user?.role !== role) return res.status(403).json({ message: "Forbidden" });
    return next();
  };
}

// --- seed admin (1 раз)
(function seedAdmin() {
  const adminEmail = "admin@demo.com";
  const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(adminEmail);
  if (!exists) {
    const hash = bcrypt.hashSync("Admin12345!", 10);
    db.prepare(
      "INSERT INTO users (email, password_hash, role, status) VALUES (?, ?, 'admin', 'active')"
    ).run(adminEmail, hash);
    console.log("Seeded admin:", adminEmail, "password: Admin12345!");
  }
})();

// --- REGISTER
// body: { email, password, role } role is 'resident' or 'partner'
app.post("/api/auth/register", async (req, res) => {
  const { email, password, role } = req.body || {};

  if (!email || !password) return res.status(400).json({ message: "email/password required" });
  if (!["resident", "partner"].includes(role)) {
    return res.status(400).json({ message: "role must be resident or partner" });
  }

  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) return res.status(409).json({ message: "Email already exists" });

  const password_hash = await bcrypt.hash(password, 10);
  const status = role === "partner" ? "pending" : "active";

  const info = db
    .prepare("INSERT INTO users (email, password_hash, role, status) VALUES (?, ?, ?, ?)")
    .run(email, password_hash, role, status);

  const user = db
    .prepare("SELECT id, email, role, status, created_at FROM users WHERE id = ?")
    .get(info.lastInsertRowid);

  const token = signToken(user);
  return res.status(201).json({ user, token });
});

// --- LOGIN
// body: { email, password }
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: "email/password required" });

  const user = db
    .prepare("SELECT id, email, password_hash, role, status, created_at FROM users WHERE email = ?")
    .get(email);

  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  if (user.status === "blocked") return res.status(403).json({ message: "User blocked" });

  const safeUser = { id: user.id, email: user.email, role: user.role, status: user.status, created_at: user.created_at };
  const token = signToken(safeUser);
  return res.json({ user: safeUser, token });
});

// --- ME
app.get("/api/auth/me", requireAuth, (req, res) => {
  const user = db
    .prepare("SELECT id, email, role, status, created_at FROM users WHERE id = ?")
    .get(req.user.sub);
  if (!user) return res.status(404).json({ message: "Not found" });
  return res.json({ user });
});

// --- ADMIN: list users
app.get("/api/admin/users", requireAuth, requireRole("admin"), (req, res) => {
  const users = db
    .prepare("SELECT id, email, role, status, created_at FROM users ORDER BY created_at DESC")
    .all();
  return res.json({ users });
});

// --- ADMIN: update status (approve partner, block user, etc.)
// body: { status } status: active|pending|blocked
app.patch("/api/admin/users/:id/status", requireAuth, requireRole("admin"), (req, res) => {
  const id = Number(req.params.id);
  const { status } = req.body || {};
  if (!["active", "pending", "blocked"].includes(status)) {
    return res.status(400).json({ message: "Invalid status" });
  }

  const exists = db.prepare("SELECT id FROM users WHERE id = ?").get(id);
  if (!exists) return res.status(404).json({ message: "Not found" });

  db.prepare("UPDATE users SET status = ? WHERE id = ?").run(status, id);
  const user = db.prepare("SELECT id, email, role, status, created_at FROM users WHERE id = ?").get(id);
  return res.json({ user });
});

app.listen(process.env.PORT || 3001, () => {
  console.log(`API running on http://localhost:${process.env.PORT || 3001}`);
});