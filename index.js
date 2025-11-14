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
    : { user: "postgres", host: "localhost", database: "webstore", password: process.env.DB_PASSWORD, port: 5432 } // Local
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
    // กัน email ซ้ำ
    const exist = await pool.query("SELECT member_id FROM member WHERE email = $1", [email]);
    if (exist.rowCount > 0) {
      return res.render("signup", { error: "อีเมลนี้มีผู้ใช้แล้ว" });
    }

    const hash = await bcrypt.hash(password, 12);
    const memberId = Date.now().toString().slice(-10); // 10 หลัก

    
    await pool.query(
      `INSERT INTO member (member_id, member_name, point, email, password_hash)
       VALUES ($1, $2, 0, $3, $4)`,
      [memberId, name || email.split("@")[0], email, hash]
    );

    req.session.user = { id: memberId, display_name: name || email.split("@")[0], email };
    res.redirect("/");
  } catch (err) {
    console.error("signup error:", err); // ดู error จริงใน console
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
      "SELECT member_id, member_name, email, password_hash, is_active FROM member WHERE email=$1",
      [email]
    );

    // 1) ไม่มีอีเมลนี้ในระบบ
    if (rows.length === 0) {
      return res.render("signin", { error: "อีเมลไม่ถูกต้อง หรือยังไม่ได้สมัคร" });
    }

    const row = rows[0];

    // 2) บัญชีถูกปิดใช้งาน (soft delete)
    if (row.is_active === false) {
      return res.render("signin", { error: "บัญชีนี้ถูกปิดใช้งานแล้ว" });
    }

    // 3) ยังไม่มี password_hash (กันกรณีแปลก ๆ)
    if (!row.password_hash) {
      return res.render("signin", {
        error: "บัญชีนี้ยังไม่ได้ตั้งรหัสผ่าน กรุณาสมัครใหม่หรือตั้งรหัสผ่านใหม่",
      });
    }

    // 4) ตรวจรหัสผ่าน
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) {
      return res.render("signin", { error: "รหัสผ่านไม่ถูกต้อง" });
    }

    // 5) login สำเร็จ → เซ็ต session
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

/* ------------------ PROFILE (ต้องล็อกอิน) ------------------ */

// แสดงหน้าแก้ไขโปรไฟล์
app.get("/profile", ensureAuth, async (req, res) => {
  try {
    const memberId = req.session.user.id;

    const { rows } = await pool.query(
      "SELECT member_name, email FROM member WHERE member_id = $1",
      [memberId]
    );

    if (!rows.length) {
      return res.status(404).send("ไม่พบข้อมูลสมาชิก");
    }

    const member = rows[0];

    res.render("profile", {
      memberName: member.member_name,
      email: member.email,
      error: null,
      success: req.query.success || null,
    });
  } catch (err) {
    console.error("profile get error:", err);
    res.status(500).send("เกิดข้อผิดพลาด");
  }
});

// รับฟอร์มแก้ไขโปรไฟล์
app.post("/profile", ensureAuth, async (req, res) => {
  const memberId = req.session.user.id;
  const memberName = (req.body.member_name || "").trim();
  const email = (req.body.email || "").trim().toLowerCase();

  if (!memberName || !email) {
    return res.render("profile", {
      memberName,
      email,
      error: "กรุณากรอกชื่อและอีเมลให้ครบ",
      success: null,
    });
  }

  try {
    // ดึง email เดิมก่อน
    const { rows: currentRows } = await pool.query(
      "SELECT email FROM member WHERE member_id = $1",
      [memberId]
    );
    if (!currentRows.length) {
      return res.status(404).send("ไม่พบข้อมูลสมาชิก");
    }
    const currentEmail = currentRows[0].email;

    // ถ้าเปลี่ยนอีเมล ต้องเช็คว่าซ้ำกับคนอื่นไหม
    if (email !== currentEmail) {
      const { rowCount: countEmail } = await pool.query(
        "SELECT 1 FROM member WHERE email = $1 AND member_id <> $2",
        [email, memberId]
      );
      if (countEmail > 0) {
        return res.render("profile", {
          memberName,
          email,
          error: "อีเมลนี้มีผู้ใช้แล้ว",
          success: null,
        });
      }
    }

    // อัปเดต DB
    await pool.query(
      "UPDATE member SET member_name = $1, email = $2 WHERE member_id = $3",
      [memberName, email, memberId]
    );
    await pool.query(
      "UPDATE payment SET member_name = $1 WHERE member_id = $2",
      [memberName, memberId]
    );
    // อัปเดต session ด้วย (จะได้โชว์ชื่อใหม่บนเว็บทันที)
    req.session.user.display_name = memberName;
    req.session.user.email = email;

    // ใช้ PRG pattern: redirect พร้อม success message
    res.redirect("/profile?success=1");
  } catch (err) {
    console.error("profile post error:", err);
    res.render("profile", {
      memberName,
      email,
      error: "เกิดข้อผิดพลาด กรุณาลองใหม่",
      success: null,
    });
  }
});
app.post("/account/delete", ensureAuth, async (req, res) => {
  try {
    const memberId = req.session.user.id;

    // ตั้งค่า inactive (soft delete)
    await pool.query(
      "UPDATE member SET is_active = false WHERE member_id = $1",
      [memberId]
    );

    // เคลียร์ session
    req.session.destroy(() => {
      res.redirect("/signin?deleted=1");
    });

  } catch (err) {
    console.error("delete account error:", err);
    res.status(500).send("ไม่สามารถลบบัญชีได้");
  }
});
/* ------------------ PRODUCT / CART / ORDER ------------------ */
// Home
app.get("/", async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || "1"));
  const perPage = 16; // จำนวนสินค้าในแต่ละหน้า
  const offset = (page - 1) * perPage;
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
    LIMIT $1 OFFSET $2
  `, [perPage, offset]);

  const { rows: totalRows } = await pool.query(`SELECT COUNT(*)::int AS total FROM product`);
  const total = totalRows[0].total;
  const totalPages = Math.ceil(total / perPage);

  res.render("home", { products, page, totalPages, ok: req.query.ok });
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
app.get("/cart", ensureAuth, async (req, res) => {
  const cart = getCart(req);
  const total = cart.reduce((sum, i) => sum + i.price * i.qty, 0);

  // point ปัจจุบันของสมาชิก
  const { rows } = await pool.query(
    "SELECT point FROM member WHERE member_id=$1",
    [req.session.user.id]
  );
  const userPoint = rows[0]?.point ?? 0;

  // ใช้แต้มได้สูงสุดตามกติกา:
  // - ไม่เกินแต้มที่มี
  // - ไม่เกินเพดานที่คูณส่วนลดแล้วเกินยอด (1 point = 200 บาท)
  const maxUsablePoints = Math.min(userPoint, Math.floor(total / 200));

  // แสดงตัวอย่างถ้าใช้ทั้งหมด (เพื่อ preview)
  const discountPreview = maxUsablePoints * 200;
  const finalPreview = total - discountPreview;

  res.render("cart", {
    cart,
    total,
    userPoint,
    maxUsablePoints,
    discountPreview,
    finalPreview
  });
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
// Confirm order (login required)
app.post("/cart/confirm", ensureAuth, async (req, res) => {
  const cart = getCart(req);
  if (cart.length === 0) return res.redirect("/cart");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const memberId = req.session.user.id;

    // โหลด point ปัจจุบัน
    const r = await client.query("SELECT point FROM member WHERE member_id=$1 FOR UPDATE", [memberId]);
    let userPoint = r.rows[0]?.point ?? 0;

    // ยอดรวมในตะกร้า
    const total = cart.reduce((s, i) => s + i.price * i.qty, 0);

    // แต้มที่ผู้ใช้ขอใช้มาจากฟอร์ม
    const asked = parseInt(req.body.points_to_use || "0", 10) || 0;

    // จำกัดจำนวนแต้มที่จะใช้จริง
    const maxUsable = Math.min(userPoint, Math.floor(total / 200));
    const pointsUsed = Math.max(0, Math.min(asked, maxUsable));

    // ส่วนลดและยอดชำระจริง
    const discount = pointsUsed * 200;
    const finalTotal = total - discount;

    // แต้มที่ได้รับใหม่ (คำนวณจากยอดที่จ่ายจริง)
    const pointsEarned = Math.floor(finalTotal / 2000);

    // อัปเดตแต้ม: หักที่ใช้ + บวกที่ได้ใหม่
    const newPoints = userPoint - pointsUsed + pointsEarned;
    await client.query("UPDATE member SET point=$1 WHERE member_id=$2", [newPoints, memberId]);

    // สร้าง checkoutId และบันทึก payment + ตัดสต็อก
    const checkoutId = "CK" + Math.floor(Math.random() * 1e8).toString().padStart(8, "0");
    const memberName = req.session.user.display_name || req.session.user.email;

    for (const item of cart) {
      // เช็คและล๊อคสต็อก
      const inv = await client.query(
        "SELECT stock FROM inventory WHERE product_id=$1 FOR UPDATE",
        [item.id]
      );
      if (!inv.rows.length) throw new Error("No inventory record for product");
      if (Number(inv.rows[0].stock) < item.qty) throw new Error(`Not enough stock for ${item.id}`);

      await client.query("UPDATE inventory SET stock = stock - $1 WHERE product_id = $2", [item.qty, item.id]);

      const paymentId = "PM" + Math.floor(Math.random() * 1e8).toString().padStart(6, "0");
      const lineAmount = item.qty * item.price;

      await client.query(
        `INSERT INTO payment (payment_id, member_id, member_name, product_id, amount, qty, checkout_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
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
