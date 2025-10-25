// index.js
const express = require("express");
require("dotenv").config();
const path = require("path");
const bodyParser = require("body-parser");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
const port = process.env.PORT || 3000;

/* ------------------ ENV / PROD FLAGS ------------------ */
const isProd = process.env.NODE_ENV === "production";
if (isProd) app.set("trust proxy", 1); // จำเป็นบน Render (อยู่หลัง proxy)

/* ------------------ VIEWS / PARSERS ------------------ */
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(bodyParser.urlencoded({ extended: false }));

/* ------------------ SESSION ------------------ */
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: isProd ? { secure: true, sameSite: "lax" } : {},
  })
);

/* ------------------ DATABASE POOL ------------------ */
const pool = new Pool(
  isProd
    ? { connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } } // Render
    : { user: "postgres", host: "localhost", database: "webstore", password: "skz42130", port: 5432 } // Local
);

/* ------------------ UTILS ------------------ */
function ensureAuth(req, res, next) {
  if (req.session.user) return next();
  return res.redirect("/signin");
}
function getCart(req) {
  if (!req.session.cart) req.session.cart = []; // [{id,name,price,qty}]
  return req.session.cart;
}

/* ------------------ LOCALS (ใช้บนทุก view) ------------------ */
app.use((req, res, next) => {
  const cart = getCart(req);
  res.locals.user = req.session.user || null;
  res.locals.cartCount = cart.reduce((s, i) => s + i.qty, 0);
  next();
});

/* ------------------ AUTH ------------------ */
// Sign up (GET)
app.get("/signup", (req, res) => {
  res.render("signup", { error: null });
});

// Sign up (POST)
app.post("/signup", async (req, res) => {
  const name = (req.body.name || "").trim();
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";

  if (!email || !password) return res.render("signup", { error: "กรอกอีเมลและรหัสผ่าน" });

  try {
    const exist = await pool.query("SELECT member_id FROM member WHERE email=$1", [email]);
    if (exist.rowCount > 0) {
      return res.render("signup", { error: "อีเมลนี้มีผู้ใช้แล้ว" });
    }

    const hash = await bcrypt.hash(password, 12);
    const memberId = Date.now().toString().slice(-10); // ง่าย ๆ พอใช้ได้ในเดโม

    await pool.query(
      "INSERT INTO member (member_id, member_name, point, tel, email, password_hash) VALUES ($1,$2,0,$3,$4,$5)",
      [memberId, name || email.split("@")[0], null, email, hash]
    );

    req.session.user = { id: memberId, display_name: name || email.split("@")[0], email };
    res.redirect("/");
  } catch (err) {
    console.error("signup error", err);
    res.render("signup", { error: "เกิดข้อผิดพลาด กรุณาลองใหม่" });
  }
});

// Sign in (GET)
app.get("/signin", (req, res) => {
  res.render("signin", { error: null });
});

// Sign in (POST)
app.post("/signin", async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";

  try {
    const { rows } = await pool.query(
      "SELECT member_id, member_name, email, password_hash FROM member WHERE email=$1",
      [email]
    );
    if (rows.length === 0) {
      return res.render("signin", { error: "อีเมลไม่ถูกต้อง หรือยังไม่ได้สมัคร" });
    }
    const row = rows[0];
    if (!row.password_hash) {
      return res.render("signin", { error: "บัญชีนี้ยังไม่ได้ตั้งรหัสผ่าน กรุณาสมัครใหม่หรือตั้งรหัสผ่านใหม่" });
    }

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.render("signin", { error: "รหัสผ่านไม่ถูกต้อง" });

    req.session.user = {
      id: row.member_id,
      display_name: row.member_name || email,
      email: row.email,
    };
    res.redirect("/");
  } catch (err) {
    console.error("signin error", err);
    res.render("signin", { error: "เกิดข้อผิดพลาด กรุณาลองใหม่" });
  }
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

/* ------------------ PRODUCT / CART / ORDER ------------------ */
// Home
app.get("/", async (req, res) => {
  const { rows: products } = await pool.query(`
    SELECT 
      p.product_id AS id,
      p.name,
      p.price,
      p.image_url,
      COALESCE(i.stock, 0) AS stock
    FROM product p
    LEFT JOIN inventory i ON i.product_id = p.product_id
    ORDER BY p.product_id
  `);
  res.render("home", { products, ok: req.query.ok });
});

// Success page
app.get("/success", ensureAuth, (req, res) => {
  res.render("success", { checkoutId: req.query.ck || "" });
});

// Add to cart (no login required)
app.post("/cart/add/:id", async (req, res) => {
  const productId = String(req.params.id);
  const qty = Math.max(1, Number(req.body.qty || 1));

  const { rows } = await pool.query(
    `
    SELECT p.product_id AS id, p.name, p.price, p.image_url, COALESCE(i.stock,0) AS stock
    FROM product p
    LEFT JOIN inventory i ON i.product_id = p.product_id
    WHERE p.product_id = $1
  `,
    [productId]
  );

  if (!rows.length) return res.status(404).send("Product not found");
  const p = rows[0];
  if (Number(p.stock) < qty) return res.status(400).send("Not enough stock");

  const cart = getCart(req);
  const item = cart.find((i) => i.id === p.id);
  if (item) {
    item.qty += qty;
  } else {
    cart.push({ id: p.id, name: p.name, price: Number(p.price), qty, image_url: p.image_url });
  }

  const back = req.get("referer") || "/";
  const dest = back.includes("/cart") ? "/" : back;
  const url = dest + (dest.includes("?") ? "&" : "?") + "added=1";
  res.redirect(url);
});

// Cart page (login required)
app.get("/cart", ensureAuth, (req, res) => {
  const cart = getCart(req);
  const total = cart.reduce((sum, i) => sum + i.price * i.qty, 0);
  res.render("cart", { cart, total });
});

// Remove a line (login required)
app.post("/cart/remove/:id", ensureAuth, (req, res) => {
  const id = String(req.params.id);
  const cart = getCart(req);
  req.session.cart = cart.filter((item) => item.id !== id);
  res.redirect("/cart");
});

// Decrement 1 (login required)
app.post("/cart/decrement/:id", ensureAuth, (req, res) => {
  const id = String(req.params.id);
  const cart = getCart(req);
  const item = cart.find((i) => i.id === id);
  if (item) {
    item.qty -= 1;
    if (item.qty <= 0) {
      req.session.cart = cart.filter((i) => i.id !== id);
    }
  }
  res.redirect("/cart");
});

// Confirm order (login required)
app.post("/cart/confirm", ensureAuth, async (req, res) => {
  const cart = getCart(req);
  if (cart.length === 0) return res.redirect("/cart");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const checkoutId = "CK" + Math.floor(Math.random() * 1e8).toString().padStart(8, "0");
    const memberId = req.session.user?.id || null;
    const memberName = req.session.user?.display_name || req.session.user?.email || "Guest";

    for (const item of cart) {
      // Lock & check stock
      const inv = await client.query(
        "SELECT stock FROM inventory WHERE product_id = $1 FOR UPDATE",
        [item.id]
      );
      if (!inv.rows.length) throw new Error("No inventory record for product");
      if (Number(inv.rows[0].stock) < item.qty) throw new Error(`Not enough stock for ${item.id}`);

      // Decrease stock
      await client.query("UPDATE inventory SET stock = stock - $1 WHERE product_id = $2", [
        item.qty,
        item.id,
      ]);

      const paymentId = "PM" + Math.floor(Math.random() * 1e8).toString().padStart(6, "0");
      const lineAmount = item.qty * item.price;

      // ต้องมี column qty ใน payment ด้วย (ALTER TABLE เพิ่มแล้ว)
      await client.query(
        `
        INSERT INTO payment (payment_id, member_id, member_name, product_id, amount, qty, checkout_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `,
        [paymentId, memberId, memberName, item.id, lineAmount, item.qty, checkoutId]
      );
    }

    await client.query("COMMIT");
    req.session.cart = [];
    res.redirect(`/success?ck=${encodeURIComponent(checkoutId)}`);
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("confirm error:", e);
    res.status(400).send(e.message);
  } finally {
    client.release();
  }
});

/* ------------------ STATIC ต้องวางท้าย (ป้องกันชน route) ------------------ */
app.use(express.static(path.join(__dirname, "public")));
app.use('/favicon.ico', express.static(path.join(__dirname, 'public', 'images', 'logo.png')));
/* ------------------ HEALTH / 404 / 500 ------------------ */
app.get("/healthz", (req, res) => res.send("ok"));

app.use((req, res) => {
  res.status(404).send("Not Found");
});

app.use((err, req, res, next) => {
  console.error("Internal error:", err);
  res.status(500).send("Internal Server Error");
});

/* ------------------ START SERVER ------------------ */
app.listen(port, "0.0.0.0", () => {
  console.log(`Server running on port ${port}`);
});
