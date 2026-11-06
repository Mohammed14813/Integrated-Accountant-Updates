const SESSION_SECONDS = 30 * 24 * 60 * 60;
const enc = new TextEncoder();
const attempts = new Map();
const DATA_KEY = "main";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,PATCH,PUT,DELETE,OPTIONS",
    "access-control-allow-headers": "authorization,content-type,x-admin-key",
    "access-control-max-age": "86400", "cache-control": "no-store",
  }});
}
function fail(message, status = 400) { return json({ ok: false, error: message }, status); }
async function sha256(value) {
  const bytes = await crypto.subtle.digest("SHA-256", enc.encode(String(value)));
  return [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, "0")).join("");
}
function b64u(bytes) {
  let s = ""; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function unb64u(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
function failWith(message, status) { return Object.assign(new Error(message), { status }); }
function isoNow() { return new Date().toISOString(); }
async function signSession(userId, env) {
  if (!env.SESSION_SIGNING_KEY) throw new Error("إعداد توقيع الجلسات غير مكتمل");
  const now = Math.floor(Date.now() / 1000);
  const input = `${b64u(enc.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })))}.${b64u(enc.encode(JSON.stringify({ sub: userId, iat: now, exp: now + SESSION_SECONDS, jti: crypto.randomUUID() })))}`;
  const key = await crypto.subtle.importKey("raw", enc.encode(env.SESSION_SIGNING_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return `${input}.${b64u(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(input))))}`;
}
async function verifySession(req, env) {
  const match = (req.headers.get("authorization") || "").match(/^Bearer\s+(.+)$/i);
  if (!match || !env.SESSION_SIGNING_KEY) return null;
  try {
    const parts = match[1].split("."); if (parts.length !== 3) return null;
    const key = await crypto.subtle.importKey("raw", enc.encode(env.SESSION_SIGNING_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    if (!await crypto.subtle.verify("HMAC", key, unb64u(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`))) return null;
    const payload = JSON.parse(new TextDecoder().decode(unb64u(parts[1])));
    if (!payload.sub || !payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    const tokenHash = await sha256(match[1]);
    const session = await env.DB.prepare("SELECT user_id FROM sessions WHERE token_hash=? AND user_id=? AND revoked_at IS NULL AND expires_at > ?").bind(tokenHash, payload.sub, isoNow()).first();
    if (!session) return null;
    return { userId: String(payload.sub), token: match[1], tokenHash };
  } catch { return null; }
}
function rateLimit(req, key) {
  const now = Date.now(), ip = req.headers.get("cf-connecting-ip") || "unknown", id = `${ip}:${key}`;
  let state = attempts.get(id) || { since: now, count: 0 };
  if (now - state.since > 10 * 60 * 1000) state = { since: now, count: 0 };
  state.count++; attempts.set(id, state);
  if (attempts.size > 5000) for (const [k, v] of attempts) if (now - v.since > 20 * 60 * 1000) attempts.delete(k);
  return state.count <= 12;
}
async function bodyJSON(req) {
  try { const value = await req.json(); if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(); return value; }
  catch { throw new Error("صيغة JSON غير صالحة"); }
}
function parseJSON(value, fallback) { try { return value ? JSON.parse(value) : fallback; } catch { return fallback; } }
function publicProfile(row) {
  return { id: row.id, email: row.email, name: row.name, phone: row.phone || "", plan: row.plan || "free", quota: row.quota_expr, allowed: Boolean(row.allowed), created: row.created_at,
    revoked: parseJSON(row.revoked_devices_json, []) };
}
async function profileFor(env, row) {
  const profile=publicProfile(row);
  const devices=await env.DB.prepare("SELECT value_json FROM user_data WHERE user_id=? AND data_key='__devices'").bind(row.id).first();
  profile.devices=devices ? parseJSON(devices.value_json,[]) : [];
  return profile;
}
function entryFor(row) { return { email: row.email, plan: row.plan || "free", expr: String(row.quota_expr ?? "500") }; }
async function userByEmail(env, email) {
  return env.DB.prepare("SELECT id,email,name,phone,password_hash,second_factor_hash,plan,quota_expr,allowed,created_at,updated_at,disabled_at,revoked_devices_json FROM users WHERE email=?").bind(email).first();
}
async function userById(env, id) {
  return env.DB.prepare("SELECT id,email,name,phone,password_hash,second_factor_hash,plan,quota_expr,allowed,created_at,updated_at,disabled_at,revoked_devices_json FROM users WHERE id=?").bind(id).first();
}
async function requireAuth(req, env) {
  const session = await verifySession(req, env);
  if (!session) throw failWith("الجلسة غير صالحة أو منتهية؛ سجّل الدخول مجددًا", 401);
  const row = await userById(env, session.userId);
  if (!row || row.disabled_at || !row.allowed) throw failWith("الحساب غير متاح", 401);
  return { session, row };
}
async function issueSession(env, row) {
  const token = await signSession(row.id, env), now = isoNow();
  await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,created_at,expires_at,revoked_at) VALUES(?,?,?,?,NULL)").bind(await sha256(token), row.id, now, new Date(Date.now() + SESSION_SECONDS * 1000).toISOString()).run();
  return token;
}
async function login(body, req, env) {
  const email = String(body.email || "").trim().toLowerCase(), password = String(body.password || ""), code = String(body.code || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password) throw failWith("تحقق من البريد الإلكتروني وكلمة المرور", 401);
  if (!rateLimit(req, email)) throw failWith("محاولات كثيرة؛ حاول لاحقًا", 429);
  const row = await userByEmail(env, email);
  if (!row || row.disabled_at || !row.allowed || row.password_hash !== await sha256("acc|" + password)) throw failWith("بيانات الدخول غير صحيحة", 401);
  if (!body.viewer && (!code || row.second_factor_hash !== await sha256("acc-sc|" + code))) throw failWith("رمز التحقق غير صحيح", 401);
  const session = await issueSession(env, row);
  // نُرجع الملف والبيانات مع الدخول في طلب واحد (بدل 3 طلبات) لتسريع الدخول على الشبكات البطيئة.
  const saved = await env.DB.prepare("SELECT value_json FROM user_data WHERE user_id=? AND data_key=?").bind(row.id, DATA_KEY).first();
  const data = saved ? parseJSON(saved.value_json, {}) : {};
  return { session, rec: publicProfile(row), entry: entryFor(row), server: data || {}, bundled: true };
}
async function register(body, req, env) {
  const email = String(body.email || "").trim().toLowerCase(), name = String(body.name || "").trim(), phone = String(body.phone || ""), password = String(body.password || ""), code = String(body.code || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("البريد الإلكتروني غير صالح");
  if (!name || !password || !code) throw new Error("الاسم وكلمة المرور والرمز مطلوبة");
  if (password.length < 4) throw new Error("كلمة المرور قصيرة جدًا");
  if (!rateLimit(req, email)) throw failWith("محاولات كثيرة؛ حاول لاحقًا", 429);
  const now = isoNow(), id = crypto.randomUUID();
  const pwHash = await sha256("acc|"+password), codeHash = await sha256("acc-sc|"+code);
  // إعادة محاولة بعد انقطاع الرد (شبكة بطيئة): إن كان الحساب موجودًا ببيانات مطابقة تمامًا نكمل كأنه دخول.
  const existing = await userByEmail(env, email);
  if (existing) {
    if (!existing.disabled_at && existing.allowed && existing.password_hash === pwHash && existing.second_factor_hash === codeHash) {
      return { session: await issueSession(env, existing), rec: publicProfile(existing), entry: entryFor(existing), server: {} };
    }
    throw new Error("البريد الإلكتروني مسجل بالفعل");
  }
  // INSERT عادي (بدل INSERT OR IGNORE الذي كان يبتلع أي خطأ ويُظهره كأنه "مسجل بالفعل").
  try {
    await env.DB.prepare("INSERT INTO users(id,email,name,phone,password_hash,second_factor_hash,plan,quota_expr,allowed,created_at,updated_at,revoked_devices_json) VALUES(?,?,?,?,?,?,'free','500',1,?,?, '[]')").bind(id,email,name,phone,pwHash,codeHash,now,now).run();
  } catch (e) {
    const msg = String(e?.message || e);
    if (/UNIQUE.*users\.email/i.test(msg)) throw new Error("البريد الإلكتروني مسجل بالفعل");
    console.error("register insert failed:", msg);
    throw failWith("تعذر إنشاء الحساب: " + msg.slice(0, 160), 500);
  }
  const row = await userById(env, id), session = await issueSession(env, row);
  return { session, rec: publicProfile(row), entry: entryFor(row), server: {} };
}

// ---- قناة GitHub: ملفات .txt = إشعارات، وملفات .otf/.ttf = خطوط. ضع الملفات في جذر المستودع العام. ----
const GH_REPO_DEFAULT = "Mohammed14813/Integrated-Accountant-Updates";
const NOTE_TARGET_RE = /^\s*\(?\s*(?:بريد|بري)?\s*[:：]?\s*([A-Za-z0-9._+\-]+@gmail\.com)\)?[\s:،,\-]*([\s\S]*)$/i;
const FONT_FILE_RE = /^[^\/\\\s]{1,60}\.(otf|ttf)$/i;
async function ghGet(env, url, ttl, binary) {
  const cache = caches.default, key = new Request(url);
  let res = await cache.match(key);
  if (!res) {
    const headers = { "User-Agent": "integrated-accountant-worker", Accept: "application/vnd.github+json" };
    if (env.GITHUB_TOKEN) headers.Authorization = "Bearer " + env.GITHUB_TOKEN;
    const r = await fetch(url, { headers });
    if (!r.ok) throw failWith("تعذر قراءة قناة التحديثات", 502);
    res = new Response(r.body, { status: 200, headers: { "content-type": binary ? "application/octet-stream" : (r.headers.get("content-type") || "text/plain"), "cache-control": "public, max-age=" + ttl } });
    await cache.put(key, res.clone());
  }
  return res;
}
async function channelFiles(env) {
  const repo = env.GITHUB_REPO || GH_REPO_DEFAULT, branch = env.GITHUB_BRANCH || "main";
  const list = await (await ghGet(env, `https://api.github.com/repos/${repo}/contents/?ref=${encodeURIComponent(branch)}`, 120)).json();
  const files = (Array.isArray(list) ? list : []).filter(f => f.type === "file" && !/^(readme|license|[._])/i.test(f.name));
  return { repo, branch, files };
}
const rawUrl = (c, f) => `https://raw.githubusercontent.com/${c.repo}/${encodeURIComponent(c.branch)}/${encodeURIComponent(f.name)}?v=${f.sha}`;
// ملف الإشعارات: كل كتلة بين ( ) إشعار مستقل. ملف لا يبدأ بقوس = إشعار واحد.
function splitBlocks(text) {
  const t = text.replace(/^﻿/, "").trim();
  if (!t.startsWith("(")) return t ? [t] : [];
  const out = []; let depth = 0, cur = "";
  for (const ch of t) {
    if (ch === "(") { if (depth++ === 0) { cur = ""; continue; } }
    else if (ch === ")" && depth > 0) { if (--depth === 0) { if (cur.trim()) out.push(cur.trim()); cur = ""; continue; } }
    if (depth > 0) cur += ch;
  }
  if (depth > 0 && cur.trim()) out.push(cur.trim());   // قوس لم يُغلق بعد
  return out;
}
async function channelFor(env, row) {
  const c = await channelFiles(env), email = String(row.email || "").trim().toLowerCase();
  const txt = c.files.filter(f => /\.txt$/i.test(f.name) && f.size > 0 && f.size <= 20000).sort((a, b) => a.name.localeCompare(b.name)).slice(-10);
  const per = await Promise.all(txt.map(async f => splitBlocks(await (await ghGet(env, rawUrl(c, f), 600)).text()).map(text => ({ file: f.name, text }))));
  const all = [];
  for (const n of per.flat()) all.push({ id: n.file + "#" + (await sha256(n.text)).slice(0, 12), text: n.text });
  const notes = all.slice(-60).filter(n => {
    const m = n.text.match(NOTE_TARGET_RE);
    return !(m && m[2].trim()) || m[1].toLowerCase() === email;   // رسالة خاصة تصل صاحب البريد فقط
  });
  const fonts = c.files.filter(f => FONT_FILE_RE.test(f.name) && f.name.toLowerCase() !== "font.otf" && f.size > 1000 && f.size <= 8 * 1024 * 1024).map(f => ({ name: f.name, size: f.size }));
  return { notes, fonts };
}
async function handle(req, env) {
  const url = new URL(req.url), path = url.pathname;
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,PATCH,PUT,DELETE,OPTIONS", "access-control-allow-headers": "authorization,content-type,x-admin-key", "access-control-max-age": "86400" } });
  if (!env.DB) return fail("قاعدة البيانات غير مهيأة", 503);
  try {
    if (path === "/health" && req.method === "GET") { await env.DB.prepare("SELECT 1").first(); return json({ ok: true }); }
    if (path === "/v1/auth/register" && req.method === "POST") return json({ ok: true, result: await register(await bodyJSON(req), req, env) });
    if (path === "/v1/auth/login" && req.method === "POST") return json({ ok: true, result: await login(await bodyJSON(req), req, env) });
    if (path === "/v1/auth/logout" && req.method === "POST") {
      const session = await verifySession(req, env);
      if (!session) throw failWith("الجلسة غير صالحة أو منتهية", 401);
      await env.DB.prepare("UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL").bind(isoNow(), session.tokenHash).run();
      return json({ ok: true });
    }
    if (path === "/v1/app/profile" && req.method === "GET") {
      const { row } = await requireAuth(req, env); return json({ profile: await profileFor(env,row), entry: entryFor(row) });
    }
    if (path === "/v1/app/profile" && req.method === "PATCH") {
      const { session, row } = await requireAuth(req, env), body = await bodyJSON(req);
      if (Object.hasOwn(body,"plan") || Object.hasOwn(body,"quota") || Object.hasOwn(body,"quota_expr") || Object.hasOwn(body,"allowed")) throw failWith("تغيير الخطة أو الحصة متاح للإدارة فقط", 403);
      const fields = [], values = [];
      if (Object.hasOwn(body,"name")) { const v=String(body.name).trim(); if(!v) throw new Error("الاسم لا يمكن أن يكون فارغًا"); fields.push("name=?"); values.push(v); }
      if (Object.hasOwn(body,"phone")) { fields.push("phone=?"); values.push(String(body.phone)); }
      if (Object.hasOwn(body,"password")) {
        if (!body.old_password || row.password_hash !== await sha256("acc|"+body.old_password)) throw failWith("كلمة المرور الحالية غير صحيحة", 403);
        const v=String(body.password); if(v.length<4) throw new Error("كلمة المرور قصيرة جدًا"); fields.push("password_hash=?"); values.push(await sha256("acc|"+v));
      }
      if (Object.hasOwn(body,"code")) {
        if (!body.old_code || row.second_factor_hash !== await sha256("acc-sc|"+body.old_code)) throw failWith("الرمز الحالي غير صحيح", 403);
        const v=String(body.code); if(!v) throw new Error("الرمز لا يمكن أن يكون فارغًا"); fields.push("second_factor_hash=?"); values.push(await sha256("acc-sc|"+v));
      }
      if (Object.hasOwn(body,"devices")) {
        if (!Array.isArray(body.devices) || body.devices.length>8 || body.devices.some(d=>!d || typeof d.id!=="string")) throw new Error("قائمة الأجهزة غير صالحة");
        await env.DB.prepare("INSERT INTO user_data(user_id,data_key,value_json,version,updated_at) VALUES(?,?,?,1,?) ON CONFLICT(user_id,data_key) DO UPDATE SET value_json=excluded.value_json,version=user_data.version+1,updated_at=excluded.updated_at").bind(row.id,"__devices",JSON.stringify(body.devices),isoNow()).run();
        fields.push("updated_at=?"); values.push(isoNow());
      }
      if (Object.hasOwn(body,"revoked")) {
        if (!Array.isArray(body.revoked) || body.revoked.length>100 || body.revoked.some(x=>typeof x!=="string")) throw new Error("قائمة الأجهزة الملغاة غير صالحة");
        fields.push("revoked_devices_json=?"); values.push(JSON.stringify(body.revoked));
      }
      if (!fields.length) throw new Error("لا توجد تغييرات صالحة");
      fields.push("updated_at=?"); values.push(isoNow()); values.push(row.id);
      await env.DB.prepare(`UPDATE users SET ${fields.join(",")} WHERE id=?`).bind(...values).run();
      const latest=await userById(env,row.id); return json({ profile: await profileFor(env,latest), entry: entryFor(latest) });
    }
    if (path === "/v1/app/profile" && req.method === "DELETE") {
      const { session, row } = await requireAuth(req, env), body=await bodyJSON(req), code=String(body.code||"");
      if (!code || row.second_factor_hash !== await sha256("acc-sc|"+code)) throw failWith("رمز التحقق غير صحيح", 403);
      await env.DB.batch([
        env.DB.prepare("DELETE FROM notifications WHERE user_id=?").bind(row.id),
        env.DB.prepare("DELETE FROM user_data WHERE user_id=?").bind(row.id),
        env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(row.id),
        env.DB.prepare("DELETE FROM files WHERE user_id=?").bind(row.id),
        env.DB.prepare("DELETE FROM users WHERE id=?").bind(row.id),
      ]);
      return json({ ok: true });
    }
    if (path === "/v1/app/data" && req.method === "GET") {
      const { row }=await requireAuth(req,env), saved=await env.DB.prepare("SELECT value_json,version FROM user_data WHERE user_id=? AND data_key=?").bind(row.id,DATA_KEY).first();
      const data=saved ? parseJSON(saved.value_json,null) : {};
      if (data===null) throw new Error("بيانات الحساب المخزنة تالفة");
      return json({ data, version:Number(saved?.version||0) });
    }
    if (path === "/v1/app/data" && req.method === "PUT") {
      const { row }=await requireAuth(req,env), body=await bodyJSON(req);
      if (!Object.hasOwn(body,"data")) throw new Error("حقل البيانات مطلوب");
      const serialized=JSON.stringify(body.data); if(serialized===undefined || serialized.length>5_000_000) throw new Error("حجم البيانات غير صالح");
      const old=await env.DB.prepare("SELECT version FROM user_data WHERE user_id=? AND data_key=?").bind(row.id,DATA_KEY).first(), version=Number(old?.version||0)+1, now=isoNow();
      await env.DB.prepare("INSERT INTO user_data(user_id,data_key,value_json,version,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(user_id,data_key) DO UPDATE SET value_json=excluded.value_json,version=excluded.version,updated_at=excluded.updated_at").bind(row.id,DATA_KEY,serialized,version,now).run();
      return json({ data:body.data, version });
    }
    if (path === "/v1/app/quota/consume" && req.method === "POST") {
      const { row }=await requireAuth(req,env), body=await bodyJSON(req), count=Number(body.count);
      if(!Number.isSafeInteger(count)||count<1) throw new Error("عدد الاستهلاك غير صالح");
      const current=Number(row.quota_expr);
      if(!Number.isSafeInteger(current)||current<count) throw failWith("الرصيد غير كافٍ",409);
      await env.DB.prepare("UPDATE users SET quota_expr=?,updated_at=? WHERE id=? AND quota_expr=?").bind(String(current-count),isoNow(),row.id,String(current)).run();
      const updated=await userById(env,row.id);
      if(Number(updated.quota_expr)!==current-count) throw failWith("تعذر تحديث الرصيد؛ أعد المحاولة",409);
      return json({ quota:Number(updated.quota_expr), rec:publicProfile(updated), entry:entryFor(updated) });
    }
    if (path === "/v1/app/notifications" && req.method === "GET") {
      const { row }=await requireAuth(req,env); const after=Number(url.searchParams.get("after")||0);
      if(!Number.isSafeInteger(after)||after<0) throw new Error("معرّف الإشعار غير صالح");
      const rows=await env.DB.prepare("SELECT id,title,body,created_at,read_at FROM notifications WHERE user_id=? AND id>? ORDER BY id LIMIT 100").bind(row.id,after).all();
      return json({ notifications:(rows.results||[]).map(n=>({id:n.id,title:n.title,body:n.body,created_at:n.created_at,read_at:n.read_at})) });
    }
    if (path === "/v1/app/channel" && req.method === "GET") {
      const { row } = await requireAuth(req, env);
      return json(await channelFor(env, row));
    }
    if (path === "/v1/app/font" && req.method === "GET") {
      await requireAuth(req, env);
      const name = String(url.searchParams.get("name") || ""), c = await channelFiles(env);
      const f = c.files.find(x => x.name === name && FONT_FILE_RE.test(x.name) && x.size <= 8 * 1024 * 1024);
      if (!f) throw failWith("الخط غير موجود", 404);
      const bytes = await (await ghGet(env, rawUrl(c, f), 3600, true)).arrayBuffer();
      return new Response(bytes, { status: 200, headers: { "content-type": "application/octet-stream", "cache-control": "no-store", "access-control-allow-origin": "*" } });
    }
    if (path === "/v1/admin/users" && req.method === "PATCH") {
      if(!env.ADMIN_API_KEY || req.headers.get("x-admin-key")!==env.ADMIN_API_KEY) throw failWith("غير مصرح",403);
      const body=await bodyJSON(req), id=String(body.id||""), fields=[], values=[];
      if(!id) throw new Error("معرّف المستخدم مطلوب");
      if(Object.hasOwn(body,"plan")){ if(!/^[a-z0-9_-]{1,32}$/i.test(String(body.plan))) throw new Error("الخطة غير صالحة"); fields.push("plan=?"); values.push(String(body.plan)); }
      if(Object.hasOwn(body,"quota_expr")){ const q=String(body.quota_expr); if(!/^\d{1,12}$/.test(q)) throw new Error("الحصة غير صالحة"); fields.push("quota_expr=?"); values.push(q); }
      if(Object.hasOwn(body,"allowed")){ if(typeof body.allowed!=="boolean") throw new Error("قيمة السماح غير صالحة"); fields.push("allowed=?"); values.push(body.allowed?1:0); }
      if(!fields.length) throw new Error("لا توجد تغييرات إدارية"); fields.push("updated_at=?"); values.push(isoNow()); values.push(id);
      const result=await env.DB.prepare(`UPDATE users SET ${fields.join(",")} WHERE id=?`).bind(...values).run();
      if(!result.meta?.changes) throw failWith("المستخدم غير موجود",404);
      return json({ profile:await profileFor(env,await userById(env,id)) });
    }
    return fail("المسار غير موجود",404);
  } catch(e) { return fail(e?.message||"حدث خطأ في الطلب",e?.status||(e instanceof SyntaxError?400:400)); }
}
// منبّه دوري (Cron Trigger مجاني) يمنع إيقاف مشروع Supabase المجاني بسبب عدم النشاط.
// يطلب /rest/v1/ من Supabase (طلب قراءة فقط، لا يكتب ولا يستهلك مساحة). اضبط SUPABASE_URL و SUPABASE_ANON_KEY كأسرار في Cloudflare.
async function keepSupabaseAwake(env) {
  if (!env.SUPABASE_URL || !env.SUPABASE_ANON_KEY) return;
  try { await fetch(env.SUPABASE_URL.replace(/\/+$/, "") + "/rest/v1/", { headers: { apikey: env.SUPABASE_ANON_KEY, authorization: "Bearer " + env.SUPABASE_ANON_KEY } }); }
  catch (e) { console.error("keepalive failed:", e?.message || e); }
}
export default { fetch: handle, scheduled: (event, env, ctx) => { ctx.waitUntil(keepSupabaseAwake(env)); } };
