// Huquqshunoslik platformasi: umumiy baza (Supabase) va server tomonidagi kirish.
// Maxfiy kalit faqat Vercel'dagi SUPABASE_SERVICE_KEY o'zgaruvchisida turadi.

const crypto = require("crypto");

const BASE = "https://mchlzrcsgldmaxruhsnl.supabase.co/rest/v1";
const KEY = process.env.SUPABASE_SERVICE_KEY;
const H = {
  apikey: KEY,
  "Content-Type": "application/json",
  ...(KEY && KEY.startsWith("sb_") ? {} : { Authorization: "Bearer " + KEY }),
};

async function getRow(id, def) {
  const r = await fetch(`${BASE}/app_data?id=eq.${id}&select=data`, { headers: H });
  if (!r.ok) throw new Error("Bazadan o'qib bo'lmadi (" + r.status + ")");
  const a = await r.json();
  return a[0] ? a[0].data : def;
}
async function putRow(id, data) {
  const r = await fetch(`${BASE}/app_data?on_conflict=id`, {
    method: "POST",
    headers: { ...H, Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify({ id, data, updated_at: new Date().toISOString() }),
  });
  if (!r.ok) throw new Error("Bazaga yozib bo'lmadi (" + r.status + ")");
}


// Xabarlar, materiallar va fayllar: har biri alohida qator (ID oralig'i bo'yicha).
const MSG0 = 100000000, MSG1 = 800000000, MAT0 = 800000000, MAT1 = 900000000, ATT0 = 900000000, ATT1 = 2000000000;
const rnd = (a, b) => a + Math.floor(Math.random() * (b - a));
async function insertRow(a, b, data) {
  for (let i = 0; i < 4; i++) {
    const id = rnd(a, b);
    const r = await fetch(`${BASE}/app_data`, { method: "POST", headers: { ...H, Prefer: "return=minimal" }, body: JSON.stringify({ id, data }) });
    if (r.ok) return id;
    if (r.status !== 409) throw new Error("Bazaga yozib bo'lmadi (" + r.status + ")");
  }
  throw new Error("Bazaga yozib bo'lmadi");
}
async function listRows(a, b, extra) {
  const r = await fetch(`${BASE}/app_data?id=gte.${a}&id=lt.${b}${extra || ""}&select=id,data&order=data->>ts.desc&limit=1000`, { headers: H });
  if (!r.ok) throw new Error("Bazadan o'qib bo'lmadi (" + r.status + ")");
  return r.json();
}
const liveRows = (rows) => rows.filter((r) => r.data && !r.data.deleted).map((r) => ({ id: r.id, ...r.data }));
async function makeAtt(a, owner) {
  if (!a || typeof a.data !== "string" || !a.data.startsWith("data:") || a.data.length > 2900000) return null;
  const meta = { name: String(a.name || "fayl").slice(0, 120), type: String(a.type || "").slice(0, 80) };
  const id = await insertRow(ATT0, ATT1, { owner, ...meta, data: a.data });
  return { id, ...meta, size: Math.round(a.data.length * 0.75) };
}

const sign = (p) => {
  const body = Buffer.from(JSON.stringify(p)).toString("base64url");
  return body + "." + crypto.createHmac("sha256", KEY).update(body).digest("base64url");
};
const verify = (t) => {
  try {
    const [body, sig] = String(t).split(".");
    const ok = crypto.createHmac("sha256", KEY).update(body).digest("base64url");
    if (sig.length !== ok.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(ok))) return null;
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() ? p : null;
  } catch (e) {
    return null;
  }
};
const eq = (a, b) => {
  a = Buffer.from(String(a));
  b = Buffer.from(String(b));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const pbkdf2 = (pw, salt) => crypto.pbkdf2Sync(pw, salt, 150000, 32, "sha256").toString("hex");
const idOk = (x) => /^[A-Za-z0-9_.-]{2,30}$/.test(x);

const noDet = ({ det, ...r }) => r;
const noPass = ({ pass, ...s }) => s;
const stub = (t) => ({ ...t, qs: (t.qs || []).map((q) => ({ holat: q.holat })) });

const forTeacher = (d) => ({ teacher: d.teacher, students: d.students, tests: d.tests, results: d.results });
const forStudent = (d, id) => ({
  hasTeacher: !!d.teacher,
  students: d.students.map(noPass),
  tests: d.tests,
  results: d.results.map((r) => (r.sid === id ? r : noDet(r))),
});
const forPublic = (d) => ({
  hasTeacher: !!d.teacher,
  students: d.students.map(noPass),
  tests: d.tests.map(stub),
  results: d.results.map(noDet),
});

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "Faqat POST" });
  if (!KEY) return res.status(500).json({ error: "Server sozlanmagan (SUPABASE_SERVICE_KEY yo'q)" });

  const b = req.body || {};
  const exp = () => Date.now() + 12 * 3600 * 1000;
  try {
    if (["sync", "sendMsg", "markRead", "addMat", "delMat", "getAtt"].includes(b.action)) {
      const p = verify(b.token);
      if (!p) return res.status(401).json({ error: "Seans tugagan. Qayta kiring." });
      const T = p.role === "teacher";
      if (b.action === "sync") {
        const own = T ? "" : `&data->>sid=eq.${encodeURIComponent(p.id)}`;
        const [m, t] = await Promise.all([listRows(MSG0, MSG1, own), listRows(MAT0, MAT1)]);
        return res.json({ msgs: liveRows(m), mats: liveRows(t) });
      }
      if (b.action === "sendMsg") {
        const text = String(b.text || "").slice(0, 4000);
        const sid = T ? String(b.sid || "") : p.id;
        if (!sid || (!text && !b.att)) return res.status(400).json({ error: "Matn yozing yoki fayl biriktiring." });
        const att = b.att ? await makeAtt(b.att, sid) : null;
        if (b.att && !att) return res.status(400).json({ error: "Fayl juda katta yoki noto'g'ri." });
        const msg = { sid, by: T ? "teacher" : "student", text, ts: Date.now(), read: false, att };
        const id = await insertRow(MSG0, MSG1, msg);
        return res.json({ msg: { id, ...msg } });
      }
      if (b.action === "markRead") {
        const sid = T ? String(b.sid || "") : p.id;
        const by = T ? "student" : "teacher";
        const rows = await listRows(MSG0, MSG1, `&data->>sid=eq.${encodeURIComponent(sid)}&data->>by=eq.${by}&data->>read=eq.false`);
        await Promise.all(rows.map((r) => putRow(r.id, { ...r.data, read: true })));
        return res.json({ ok: true });
      }
      if (b.action === "addMat") {
        if (!T) return res.status(403).json({ error: "Faqat o'qituvchi." });
        const att = await makeAtt(b.att, "mat");
        if (!att) return res.status(400).json({ error: "Fayl juda katta yoki noto'g'ri." });
        const mat = {
          kind: ["dars", "mash", "audio"].includes(b.kind) ? b.kind : "dars",
          title: String(b.title || "").slice(0, 200),
          desc: String(b.desc || "").slice(0, 500),
          ts: Date.now(),
          att,
        };
        const id = await insertRow(MAT0, MAT1, mat);
        return res.json({ mat: { id, ...mat } });
      }
      if (b.action === "delMat") {
        if (!T) return res.status(403).json({ error: "Faqat o'qituvchi." });
        const id = Number(b.id);
        if (!(id >= MAT0 && id < MAT1)) return res.status(400).json({ error: "Noto'g'ri ID." });
        const row = await getRow(id, null);
        if (row && row.att) await putRow(row.att.id, { deleted: true });
        await putRow(id, { deleted: true });
        return res.json({ ok: true });
      }
      if (b.action === "getAtt") {
        const id = Number(b.id);
        if (!(id >= ATT0 && id < ATT1)) return res.status(400).json({ error: "Noto'g'ri ID." });
        const a = await getRow(id, null);
        if (!a || a.deleted) return res.status(404).json({ error: "Fayl topilmadi." });
        if (a.owner !== "mat" && !T && a.owner !== p.id) return res.status(403).json({ error: "Ruxsat yo'q." });
        return res.json({ name: a.name, type: a.type, data: a.data });
      }
    }

    const d0 = await getRow(1, {});
    const d = {
      teacher: d0.teacher || null,
      students: d0.students || [],
      tests: d0.tests || [],
      results: d0.results || [],
    };

    if (b.action === "pub") return res.json(forPublic(d));

    if (b.action === "setup") {
      if (d.teacher) return res.status(403).json({ error: "O'qituvchi akkaunti allaqachon yaratilgan." });
      const c = b.cred || {};
      if (!idOk(String(b.id)) || !c.salt || !c.hash) return res.status(400).json({ error: "Ma'lumot noto'g'ri." });
      d.teacher = { id: String(b.id), salt: String(c.salt), hash: String(c.hash) };
      await putRow(1, d);
      return res.json({ token: sign({ role: "teacher", id: d.teacher.id, exp: exp() }), data: forTeacher(d) });
    }

    if (b.action === "login") {
      const role = b.role === "teacher" ? "teacher" : "student";
      const id = String(b.id || "");
      const pw = String(b.pw || "");
      const lkey = role + ":" + id.toLowerCase();
      const fails = await getRow(2, {});
      const f = fails[lkey] || { n: 0, until: 0 };
      if (f.until > Date.now()) {
        const s = Math.ceil((f.until - Date.now()) / 1000);
        return res.status(429).json({ error: `Juda ko'p xato urinish. ${s} soniyadan so'ng qayta urinib ko'ring.` });
      }
      let ok = false;
      if (role === "teacher") {
        ok = !!d.teacher && eq(d.teacher.id, id) && eq(pbkdf2(pw, d.teacher.salt), d.teacher.hash);
      } else {
        const s = d.students.find((x) => x.id === id);
        ok = !!s && eq(s.pass, pw);
      }
      if (!ok) {
        f.n += 1;
        if (f.n >= 5) f.until = Date.now() + 60000 * Math.min(10, f.n - 4);
        fails[lkey] = f;
        await putRow(2, fails);
        return res.status(401).json({ error: "ID yoki parol noto'g'ri. Qayta tekshiring." });
      }
      if (fails[lkey]) {
        delete fails[lkey];
        await putRow(2, fails);
      }
      const token = sign({ role, id, exp: exp() });
      return res.json({ token, data: role === "teacher" ? forTeacher(d) : forStudent(d, id) });
    }

    if (b.action === "save") {
      const p = verify(b.token);
      if (!p || p.role !== "teacher") return res.status(401).json({ error: "Seans tugagan. Qayta kiring." });
      const n = b.data || {};
      const students = Array.isArray(n.students) ? n.students : d.students;
      const tests = Array.isArray(n.tests) ? n.tests : d.tests;
      const sids = new Set(students.map((s) => s.id));
      const tids = new Set(tests.map((t) => t.id));
      const seen = new Set();
      const results = [];
      for (const r of [...(Array.isArray(n.results) ? n.results : []), ...d.results]) {
        const k = r.sid + "|" + r.tid + "|" + r.date;
        if (seen.has(k) || !sids.has(r.sid) || !tids.has(r.tid)) continue;
        seen.add(k);
        results.push(r);
      }
      const t = n.teacher;
      const teacher = t && t.id && t.salt && t.hash ? { id: t.id, salt: t.salt, hash: t.hash } : d.teacher;
      await putRow(1, { teacher, students, tests, results });
      return res.json({ ok: true, results });
    }

    if (b.action === "addResult") {
      const p = verify(b.token);
      if (!p || p.role !== "student") return res.status(401).json({ error: "Seans tugagan. Qayta kiring." });
      const r = { ...(b.r || {}), sid: p.id };
      if (!d.tests.some((t) => t.id === r.tid)) return res.status(400).json({ error: "Test topilmadi." });
      const rr = await fetch(`${BASE}/rpc/append_result`, { method: "POST", headers: H, body: JSON.stringify({ r }) });
      if (!rr.ok) throw new Error("Natijani saqlab bo'lmadi (" + rr.status + ")");
      return res.json({ ok: true });
    }

    return res.status(400).json({ error: "Noma'lum amal" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message || "Server xatosi" });
  }
};
