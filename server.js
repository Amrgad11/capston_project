const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 4000;
const DATA_FILE = path.join(__dirname, "data.json");

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const seed = {
      users: [
        { id: "u-student-1", name: "محمد أحمد", email: "student@eduvision.ai", role: "student", passwordHash: hashPassword("12345678") },
        { id: "u-prof-1", name: "د. مروة علي", email: "prof@eduvision.ai", role: "professor", passwordHash: hashPassword("12345678") },
        { id: "u-admin-1", name: "مشرف النظام", email: "admin@eduvision.ai", role: "admin", passwordHash: hashPassword("12345678") },
      ],
      notifications: {
        student: ["تم تصحيح واجب قواعد البيانات", "تذكير: تسليم AI غدًا", "تم فتح محاضرة جديدة"],
        professor: ["5 submissions وصلت", "تنبيه: طالب بحاجة متابعة", "تم اعتماد مادة جديدة"],
        admin: ["نمو استخدام جديد في جامعة القاهرة", "23 شهادة بانتظار المراجعة"],
      },
      assignments: [
        { id: "a1", title: "AI Homework", subject: "AI", status: "pending", urgency: "high", due: "2026-04-28", role: "student" },
        { id: "a2", title: "SQL Report", subject: "DB", status: "soon", urgency: "mid", due: "2026-04-30", role: "student" },
        { id: "a3", title: "UML Model", subject: "SE", status: "completed", urgency: "low", due: "2026-04-24", role: "student" },
      ],
      sessions: {},
      uploads: [],
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(seed, null, 2), "utf8");
    return seed;
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
}

let db = loadData();

function saveData() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), "utf8");
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,OPTIONS",
  });
  res.end(JSON.stringify(payload));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function getToken(req) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) return null;
  return auth.slice(7);
}

function authUser(req) {
  const token = getToken(req);
  if (!token || !db.sessions[token]) return null;
  const session = db.sessions[token];
  return db.users.find((u) => u.id === session.userId) || null;
}

function routeMatch(req, reqUrl, method, target) {
  return reqUrl.pathname === target && req.method === method;
}

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === "OPTIONS") return sendJson(res, 200, { ok: true });

  try {
    if (routeMatch(req, reqUrl, "GET", "/api/health")) {
      return sendJson(res, 200, { ok: true, service: "EduVision API", now: new Date().toISOString() });
    }

    if (routeMatch(req, reqUrl, "POST", "/api/auth/register")) {
      const body = await parseBody(req);
      const { name, email, password, role = "student" } = body;
      if (!name || !email || !password) return sendJson(res, 400, { message: "name, email, password required" });
      if (db.users.some((u) => u.email.toLowerCase() === String(email).toLowerCase())) {
        return sendJson(res, 409, { message: "Email already exists" });
      }
      const user = {
        id: "u-" + crypto.randomUUID(),
        name,
        email,
        role,
        passwordHash: hashPassword(password),
      };
      db.users.push(user);
      saveData();
      return sendJson(res, 201, { user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    }

    if (routeMatch(req, reqUrl, "POST", "/api/auth/login")) {
      const body = await parseBody(req);
      const { email, password, role } = body;
      const user = db.users.find((u) => u.email.toLowerCase() === String(email || "").toLowerCase());
      if (!user || user.passwordHash !== hashPassword(String(password || ""))) {
        return sendJson(res, 401, { message: "Invalid credentials" });
      }
      if (role && user.role !== role) return sendJson(res, 403, { message: "Role mismatch" });
      const token = crypto.randomUUID();
      db.sessions[token] = { userId: user.id, createdAt: Date.now() };
      saveData();
      return sendJson(res, 200, { token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    }

    if (routeMatch(req, reqUrl, "GET", "/api/auth/me")) {
      const user = authUser(req);
      if (!user) return sendJson(res, 401, { message: "Unauthorized" });
      return sendJson(res, 200, { user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    }

    if (routeMatch(req, reqUrl, "GET", "/api/notifications")) {
      const user = authUser(req);
      if (!user) return sendJson(res, 401, { message: "Unauthorized" });
      return sendJson(res, 200, { items: db.notifications[user.role] || [] });
    }

    if (routeMatch(req, reqUrl, "GET", "/api/assignments")) {
      const user = authUser(req);
      if (!user) return sendJson(res, 401, { message: "Unauthorized" });
      const items = db.assignments.filter((a) => a.role === user.role || user.role === "professor" || user.role === "admin");
      return sendJson(res, 200, { items });
    }

    if (req.method === "PATCH" && reqUrl.pathname.startsWith("/api/assignments/")) {
      const user = authUser(req);
      if (!user) return sendJson(res, 401, { message: "Unauthorized" });
      const id = reqUrl.pathname.split("/").pop();
      const body = await parseBody(req);
      const item = db.assignments.find((a) => a.id === id);
      if (!item) return sendJson(res, 404, { message: "Assignment not found" });
      item.status = body.status || item.status;
      saveData();
      return sendJson(res, 200, { item });
    }

    if (routeMatch(req, reqUrl, "POST", "/api/assignments/upload")) {
      const user = authUser(req);
      if (!user) return sendJson(res, 401, { message: "Unauthorized" });
      const body = await parseBody(req);
      const upload = {
        id: "up-" + crypto.randomUUID(),
        fileName: body.fileName || "unknown",
        size: body.size || 0,
        ownerId: user.id,
        uploadedAt: Date.now(),
      };
      db.uploads.push(upload);
      saveData();
      return sendJson(res, 201, { upload });
    }

    if (routeMatch(req, reqUrl, "GET", "/api/analytics/student")) {
      const user = authUser(req);
      if (!user) return sendJson(res, 401, { message: "Unauthorized" });
      return sendJson(res, 200, { weeklyProgress: [58, 64, 72, 70, 79, 84, 88], focusMinutes: 65, streakDays: 12, rank: 2 });
    }

    if (routeMatch(req, reqUrl, "GET", "/api/analytics/professor")) {
      const user = authUser(req);
      if (!user) return sendJson(res, 401, { message: "Unauthorized" });
      return sendJson(res, 200, { classTrend: [66, 70, 74, 78, 81, 84, 86], riskStudents: 7, submissionRate: 91 });
    }

    if (routeMatch(req, reqUrl, "GET", "/api/admin/overview")) {
      const user = authUser(req);
      if (!user) return sendJson(res, 401, { message: "Unauthorized" });
      if (user.role !== "admin") return sendJson(res, 403, { message: "Forbidden" });
      return sendJson(res, 200, {
        universities: 200,
        students: 50000,
        professors: 2000,
        health: 91,
        distribution: [32, 24, 20, 14, 10],
      });
    }

    if (routeMatch(req, reqUrl, "POST", "/api/chat")) {
      const user = authUser(req);
      if (!user) return sendJson(res, 401, { message: "Unauthorized" });
      const body = await parseBody(req);
      const text = String(body.message || "").trim();
      return sendJson(res, 200, {
        reply: text ? `اقتراح ذكي: ركّز على "${text}" ثم طبّق مثالين عمليين.` : "اسألني أي سؤال أكاديمي.",
      });
    }

    if (routeMatch(req, reqUrl, "POST", "/api/certificates/generate")) {
      const user = authUser(req);
      if (!user) return sendJson(res, 401, { message: "Unauthorized" });
      const code = "EV-" + Date.now().toString().slice(-8);
      return sendJson(res, 201, { code, issuedTo: user.name, issuedAt: new Date().toISOString() });
    }

    return sendJson(res, 404, { message: "Not found" });
  } catch (error) {
    return sendJson(res, 500, { message: error.message || "Internal server error" });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("Server running");
});

