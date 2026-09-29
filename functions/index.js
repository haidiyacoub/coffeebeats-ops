const { onCall, HttpsError }     = require("firebase-functions/v2/https");
const { onSchedule }             = require("firebase-functions/v2/scheduler");
const { onDocumentUpdated }      = require("firebase-functions/v2/firestore");
const { defineSecret }           = require("firebase-functions/params");
const admin      = require("firebase-admin");
const bcrypt     = require("bcryptjs");
const crypto     = require("crypto");
const nodemailer = require("nodemailer");

// Gmail app-password credentials (set via: firebase functions:secrets:set <NAME>)
const GMAIL_USER = defineSecret("GMAIL_USER");   // your Gmail address
const GMAIL_PASS = defineSecret("GMAIL_PASS");   // Gmail app password (16-char)
const NOTIFY_TO  = defineSecret("NOTIFY_TO");    // recipient email (can be same as GMAIL_USER)

// Symmetric key used to store staff PINs in a form the owner can recover
// (set via: firebase functions:secrets:set PIN_ENC_KEY). Login itself still
// checks the bcrypt hash below — this encrypted copy exists only so the
// owner can look a PIN back up from Team & Barista Management.
const PIN_ENC_KEY = defineSecret("PIN_ENC_KEY");

// Initialize Admin SDK at module load time (correct pattern for Gen2 functions)
admin.initializeApp();

function getDb()   { return admin.firestore(); }
function getAuth() { return admin.auth(); }


// ─── verifyPin ────────────────────────────────────────────────────────────────
exports.verifyPin = onCall(async (request) => {
  const { staffId, pin } = request.data;
  if (!staffId || !pin) throw new HttpsError("invalid-argument", "staffId and pin are required.");

  const db   = getDb();
  const snap = await db.collection("staff").doc(staffId).get();
  if (!snap.exists) throw new HttpsError("not-found", "Staff member not found.");

  const staff = snap.data();
  if (!staff.active) throw new HttpsError("permission-denied", "Account is inactive.");

  let match     = await bcrypt.compare(String(pin), staff.pin_hash);
  let viaMaster = false;

  // Fall back to the owner's master PIN, which unlocks any active profile.
  if (!match) {
    const secSnap    = await db.collection("config").doc("security").get();
    const masterHash = secSnap.exists ? secSnap.data().master_pin_hash : null;
    if (masterHash && await bcrypt.compare(String(pin), masterHash)) {
      match     = true;
      viaMaster = true;
    }
  }

  if (!match) throw new HttpsError("unauthenticated", "Incorrect PIN.");

  if (viaMaster) {
    console.log(`Master PIN sign-in as "${staff.name}" (${staffId})`);
  }

  const token = await getAuth().createCustomToken(staffId, {
    role:     staff.role,
    branches: staff.branches || [],
  });

  return { token };
});

// ─── setMasterPin ─────────────────────────────────────────────────────────────
// Owner-only. Lets the owner sign in as any active staff profile using this PIN
// instead of that person's individual PIN. Pass newPin: null to disable it.
exports.setMasterPin = onCall(async (request) => {
  _requireOwner(request);
  const { newPin } = request.data;

  if (newPin === null || newPin === "" || newPin === undefined) {
    await getDb().collection("config").doc("security").set({
      master_pin_hash: admin.firestore.FieldValue.delete(),
      updated_at:      admin.firestore.FieldValue.serverTimestamp(),
      updated_by:      request.auth.uid,
    }, { merge: true });
    return { ok: true, enabled: false };
  }

  if (!/^\d{4,8}$/.test(String(newPin))) {
    throw new HttpsError("invalid-argument", "Master PIN must be 4-8 digits.");
  }

  const pin_hash = await bcrypt.hash(String(newPin), 12);
  await getDb().collection("config").doc("security").set({
    master_pin_hash: pin_hash,
    updated_at:      admin.firestore.FieldValue.serverTimestamp(),
    updated_by:      request.auth.uid,
  }, { merge: true });

  return { ok: true, enabled: true };
});

// ─── getMasterPinStatus ───────────────────────────────────────────────────────
// Owner-only. Reports whether a master PIN is currently set, without exposing it.
exports.getMasterPinStatus = onCall(async (request) => {
  _requireOwner(request);
  const snap    = await getDb().collection("config").doc("security").get();
  const enabled = !!(snap.exists && snap.data().master_pin_hash);
  return { enabled };
});

// ─── createStaffUser ──────────────────────────────────────────────────────────
exports.createStaffUser = onCall({ secrets: [PIN_ENC_KEY] }, async (request) => {
  _requireOwner(request);
  return _createUser(request.data);
});

// ─── migrateUser ──────────────────────────────────────────────────────────────
exports.migrateUser = onCall({ secrets: [PIN_ENC_KEY] }, async (request) => {
  _requireOwner(request);
  return _createUser(request.data);
});

// ─── updateStaffPin ───────────────────────────────────────────────────────────
exports.updateStaffPin = onCall({ secrets: [PIN_ENC_KEY] }, async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Must be signed in.");

  const { targetUid, newPin, currentPin } = request.data;
  const callerUid = request.auth.uid;
  const isOwner   = request.auth.token.role === "owner";
  const isSelf    = callerUid === targetUid;

  if (!isOwner && !isSelf) throw new HttpsError("permission-denied", "Not authorised.");

  if (!isOwner && isSelf) {
    if (!currentPin) throw new HttpsError("invalid-argument", "currentPin is required.");
    const snap = await getDb().collection("staff").doc(targetUid).get();
    const ok = await bcrypt.compare(String(currentPin), snap.data().pin_hash);
    if (!ok) throw new HttpsError("unauthenticated", "Current PIN is incorrect.");
  }

  const pin_hash = await bcrypt.hash(String(newPin), 12);
  const pin_enc  = _encryptPin(newPin);
  await getDb().collection("staff").doc(targetUid).update({ pin_hash, pin_enc });
  return { ok: true };
});

// ─── getStaffPin ──────────────────────────────────────────────────────────────
// Owner-only. Decrypts and returns a staff member's current PIN so it can be
// shown in Team & Barista Management. Staff created before this feature only
// have a bcrypt hash (not recoverable) until their PIN is next reset.
exports.getStaffPin = onCall({ secrets: [PIN_ENC_KEY] }, async (request) => {
  _requireOwner(request);
  const { targetUid } = request.data;
  if (!targetUid) throw new HttpsError("invalid-argument", "targetUid is required.");

  const snap = await getDb().collection("staff").doc(targetUid).get();
  if (!snap.exists) throw new HttpsError("not-found", "Staff member not found.");

  const { pin_enc } = snap.data();
  if (!pin_enc) {
    throw new HttpsError("failed-precondition", "This PIN was set before PIN lookup was added — reset it to make it viewable.");
  }

  try {
    return { pin: _decryptPin(pin_enc) };
  } catch (e) {
    throw new HttpsError("internal", "Failed to decrypt PIN.");
  }
});

// ─── setStaffRole ─────────────────────────────────────────────────────────────
exports.setStaffRole = onCall(async (request) => {
  _requireOwner(request);
  const { targetUid, role, branches } = request.data;
  if (!targetUid || !role) throw new HttpsError("invalid-argument", "targetUid and role are required.");

  await getAuth().setCustomUserClaims(targetUid, { role, branches: branches || [] });
  await getDb().collection("staff").doc(targetUid).update({ role, branches: branches || [] });
  await getDb().collection("staff_public").doc(targetUid).update({ role, branches: branches || [] });
  return { ok: true };
});

// ─── setStaffActive ───────────────────────────────────────────────────────────
exports.setStaffActive = onCall(async (request) => {
  _requireOwner(request);
  const { targetUid, active } = request.data;
  if (!targetUid) throw new HttpsError("invalid-argument", "targetUid is required.");

  // Try to update Firebase Auth — may not exist for legacy/migrated users
  try {
    await getAuth().updateUser(targetUid, { disabled: !active });
  } catch (e) {
    if (e.code !== "auth/user-not-found") throw e;
    // Legacy user has no Firebase Auth account — just update Firestore below
  }

  const db = getDb();
  await db.collection("staff").doc(targetUid).update({ active });
  await db.collection("staff_public").doc(targetUid).update({ active });
  return { ok: true };
});

// ─── updateStaffProfile ───────────────────────────────────────────────────────
// Any signed-in user can update their own emergency_number.
// Owners can additionally update name, role, branches, active, and emergency_number for anyone.
exports.updateStaffProfile = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Must be signed in.");

  const { targetUid, name, role, branches, active, emergency_number } = request.data;
  const callerUid = request.auth.uid;
  const isOwner   = request.auth.token.role === "owner";
  const isSelf    = callerUid === targetUid;

  if (!isOwner && !isSelf) throw new HttpsError("permission-denied", "Not authorised.");

  const db = getDb();

  if (isOwner) {
    // Owner can update everything
    const staffUpdate   = {};
    const publicUpdate  = {};
    if (name              != null) { staffUpdate.name              = name;              publicUpdate.name      = name; }
    if (role              != null) { staffUpdate.role              = role;              publicUpdate.role      = role; }
    if (branches          != null) { staffUpdate.branches          = branches;          publicUpdate.branches  = branches; }
    if (active            != null) { staffUpdate.active            = active;            publicUpdate.active    = active; }
    if (emergency_number  != null) { staffUpdate.emergency_number  = emergency_number; }

    if (Object.keys(staffUpdate).length) {
      await db.collection("staff").doc(targetUid).update(staffUpdate);
    }
    if (Object.keys(publicUpdate).length) {
      await db.collection("staff_public").doc(targetUid).update(publicUpdate);
    }
    if (role != null && branches != null) {
      try { await getAuth().setCustomUserClaims(targetUid, { role, branches }); }
      catch (e) { if (e.code !== "auth/user-not-found") throw e; }
    }
    if (active != null) {
      try { await getAuth().updateUser(targetUid, { disabled: !active }); }
      catch (e) { if (e.code !== "auth/user-not-found") throw e; }
    }

  } else {
    // Self — only emergency_number allowed
    if (emergency_number != null) {
      await db.collection("staff").doc(targetUid).update({ emergency_number });
    }
  }

  return { ok: true };
});


// ─── shared helpers ───────────────────────────────────────────────────────────
function _sumPayments(closes) {
  return closes.reduce(
    (s, c) => ({
      cash:           s.cash           + (Number(c.cash)           || 0),
      instapay:       s.instapay       + (Number(c.instapay)       || 0),
      cc:             s.cc             + (Number(c.cc)             || 0),
      talabat_credit: s.talabat_credit + (Number(c.talabat_credit) || 0),
      talabat_cash:   s.talabat_cash   + (Number(c.talabat_cash)   || 0),
    }),
    { cash: 0, instapay: 0, cc: 0, talabat_credit: 0, talabat_cash: 0 }
  );
}
function _rowTotal(s) { return s.cash + s.instapay + s.cc + s.talabat_credit + s.talabat_cash; }
function _fmt(n)      { return `EGP ${Number(n).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`; }
function _cap(s)      { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }

async function _sendEmail(subject, text) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: GMAIL_USER.value(), pass: GMAIL_PASS.value() },
  });
  await transporter.sendMail({
    from: `"Coffee Beats" <${GMAIL_USER.value()}>`,
    to:   NOTIFY_TO.value(),
    subject,
    text,
  });
}

// ─── sendDailyShiftSummary ────────────────────────────────────────────────────
// Runs at 23:30 Cairo time (UTC+2 = 21:30 UTC) every day.
exports.sendDailyShiftSummary = onSchedule(
  { schedule: "30 21 * * *", timeZone: "UTC", secrets: [GMAIL_USER, GMAIL_PASS, NOTIFY_TO] },
  async () => {
    const db = getDb();
    const today = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString().slice(0, 10);

    const opSnap      = await db.collection("state").doc("operations").get();
    const allCloses   = (opSnap.exists ? opSnap.data().shift_closes : null) || [];
    const todayCloses = allCloses.filter(c => c.date === today);

    const lines = [];
    lines.push("☕ *Coffee Beats — Daily Shift Summary*");
    lines.push(`📅 ${today}`);
    lines.push("──────────────────────");

    if (todayCloses.length === 0) {
      lines.push("⚠️ No shift closes recorded today.");
    } else {
      const branches = [...new Set(todayCloses.map(c => c.branch))].sort();
      for (const branch of branches) {
        const bSums  = _sumPayments(todayCloses.filter(c => c.branch === branch));
        const bTotal = _rowTotal(bSums);
        lines.push(`📍 ${_cap(branch)}: *${_fmt(bTotal)}*`);
        if (bSums.cash                             > 0) lines.push(`   💵 Cash: ${_fmt(bSums.cash)}`);
        if (bSums.instapay                         > 0) lines.push(`   📲 Instapay: ${_fmt(bSums.instapay)}`);
        if (bSums.cc                               > 0) lines.push(`   💳 Card: ${_fmt(bSums.cc)}`);
        if (bSums.talabat_credit + bSums.talabat_cash > 0)
          lines.push(`   🛵 Talabat: ${_fmt(bSums.talabat_credit + bSums.talabat_cash)}`);
      }
      lines.push("──────────────────────");
      lines.push(`✅ *TOTAL TODAY: ${_fmt(_rowTotal(_sumPayments(todayCloses)))}*`);
    }

    await _sendEmail(`☕ Shift Summary — ${today}`, lines.join("\n"));
    console.log("Daily email sent for", today);
  }
);

// ─── Owner-paid expenses report ───────────────────────────────────────────────
// Weekly email listing every expense the owner paid from personal funds
// ("Paid personally — reimburse me later" = paid_by / paid_from "owner_personal")
// dated within the last 45 days. Trashed / tombstoned / test records are excluded.
// The machine-readable JSON block at the bottom is meant to be parsed by a
// downstream reconciler — an EMPTY list is still sent so deletions reconcile.
const OWNER_PAID_VALUES   = new Set(["owner_personal"]);
const OWNER_PAID_WINDOW_D = 45;

// Cairo-time YYYY-MM-DD (server counterpart of the app's localISODate()).
function localISODate(d) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Africa/Cairo", year: "numeric", month: "2-digit", day: "2-digit",
  }).format(d);
}

const OVERHEAD_CAT_LABELS = {
  electricity: "Electricity bill", internet: "Internet bill", cleaner_salary: "Cleaner salary",
  accountant_salary: "Accountant salary", pos_fees: "POS fees", gardener_salary: "Gardener salary",
  loan_payment: "Loan payment", marketing_fees: "Marketing fees", sponsorship: "Sponsorship",
  uniforms: "Uniforms", software: "Software / subscriptions", agency_design: "Agency / design",
  legal_fees: "Legal fees", equipment_repair: "Equipment repair", misc: "Miscellaneous",
  maintenance_1: "Maintenance — Cooling", maintenance_2: "Maintenance — Machines",
  insect_control: "Insect / pest control", maintenance_emergency: "Maintenance — Emergency",
};

async function _collectOwnerPaid() {
  const db = getDb();
  const names = ["purchases", "overhead", "equipment", "hr", "tombstones"];
  const snaps = await Promise.all(names.map(n => db.collection("state").doc(n).get()));
  const d = {};
  names.forEach((n, i) => { d[n] = snaps[i].exists ? (snaps[i].data() || {}) : {}; });
  const arr = (doc, k) => (Array.isArray(doc[k]) ? doc[k] : []);

  const tomb = new Set(arr(d.tombstones, "deleted_ids").map(t => (t && typeof t === "object" ? t.id : t)));
  const live = r => r && r.id != null && !r.is_test && !r.deleted && !r.deleted_at && !tomb.has(r.id);
  const isOwner = v => OWNER_PAID_VALUES.has(v);

  const now         = new Date();
  const today       = localISODate(now);
  const windowStart = localISODate(new Date(now.getTime() - OWNER_PAID_WINDOW_D * 86400000));
  const rows = [];
  const add = (r, o) => {
    if (!o.date || o.date < windowStart) return;
    rows.push({
      id: String(r.id), date: o.date,
      amount: Math.round((Number(o.amount) || 0) * 100) / 100,
      category: o.category || "", supplier: o.supplier || "",
      branch: o.branch ? String(o.branch).charAt(0).toUpperCase() + String(o.branch).slice(1).toLowerCase() : "",
      note: o.note || "", logged_by: r.by_name || o.by_name || "",
    });
  };

  for (const p of arr(d.purchases, "purchases")) {
    if (!live(p) || !isOwner(p.paid_by)) continue;
    const cats = [...new Set((p.lines || []).map(l => l.category || (l.kind === "inventory" ? "Inventory" : (l.description || "Other"))))];
    add(p, { date: p.date, amount: p.total, category: cats.join(", ") || "Purchase", supplier: p.supplier, branch: p.branch, note: p.note || "" });
  }
  for (const o of arr(d.overhead, "overheads")) {
    if (!live(o) || o.paid === false || !isOwner(o.paid_from)) continue;
    add(o, { date: o.paid_on || o.date, amount: o.amount, category: OVERHEAD_CAT_LABELS[o.category] || o.category,
             supplier: o.supplier || "", branch: o.branch, note: [o.label, o.note].filter(Boolean).join(" — ") });
  }
  // Petty-cash top-ups/corrections funded personally are recorded on owner_account with
  // ref = the petty_cash entry id; report the petty_cash record itself (and only if it still exists).
  const pettyById = new Map(arr(d.purchases, "petty_cash").filter(live).map(r => [r.id, r]));
  for (const e of arr(d.purchases, "owner_account")) {
    if (!live(e) || e.source !== "petty_cash") continue;
    const pc = pettyById.get(e.ref);
    if (!pc) continue;
    add(pc, { date: pc.date || e.date, amount: e.amount, category: "Petty cash top-up", supplier: "Petty cash",
              branch: pc.branch || e.branch, note: pc.note || e.label, by_name: e.by_name });
  }
  for (const l of arr(d.hr, "salary_loans")) {
    if (!live(l) || !isOwner(l.paid_from)) continue;
    add(l, { date: l.date, amount: l.amount, category: "Loan advance", supplier: l.barista, branch: l.branch, note: l.note });
  }
  for (const sp of arr(d.hr, "salaries")) {
    if (!live(sp) || !isOwner(sp.paid_from)) continue;
    add(sp, { date: sp.date, amount: sp.amount, category: "Salary", supplier: sp.recipient, branch: sp.branch, note: sp.note });
  }
  for (const a of arr(d.equipment, "equipment")) {
    if (!live(a) || !isOwner(a.paid_from)) continue;
    add(a, { date: a.purchase_date || a.date, amount: a.cost, category: "Equipment" + (a.category ? ` — ${a.category}` : ""),
             supplier: a.supplier || a.name, branch: a.branch, note: a.name });
  }

  rows.sort((x, y) => x.date.localeCompare(y.date) || x.id.localeCompare(y.id));
  return { rows, today, windowStart };
}

async function _sendOwnerPaidReport() {
  const { rows, today, windowStart } = await _collectOwnerPaid();
  const total = Math.round(rows.reduce((s, r) => s + r.amount, 0) * 100) / 100;
  const lines = [];
  lines.push(`Owner-paid expenses — last ${OWNER_PAID_WINDOW_D} days (${windowStart} to ${today})`);
  lines.push("");
  if (!rows.length) lines.push("(none)");
  for (const r of rows) {
    lines.push(`${r.date} | ${r.amount} EGP | ${r.category || "-"} | ${r.supplier || "-"} | ${r.branch || "-"} | ${r.note || "-"} | by ${r.logged_by || "-"}`);
  }
  lines.push("");
  lines.push(`TOTAL: ${total} EGP (${rows.length} record${rows.length === 1 ? "" : "s"})`);
  lines.push("");
  lines.push(`WINDOW_START=${windowStart}`);
  lines.push("OWNER_PAID_JSON_START");
  lines.push(JSON.stringify(rows));
  lines.push("OWNER_PAID_JSON_END");
  await _sendEmail(`Owner-paid expenses – ${today}`, lines.join("\n"));
  console.log(`Owner-paid report sent for ${today}: ${rows.length} records, ${total} EGP`);
  return { count: rows.length, total, windowStart, date: today };
}

// Every Sunday 21:00 Cairo time.
exports.sendOwnerPaidReport = onSchedule(
  { schedule: "0 21 * * 0", timeZone: "Africa/Cairo", secrets: [GMAIL_USER, GMAIL_PASS, NOTIFY_TO] },
  async () => { await _sendOwnerPaidReport(); }
);

// Owner-only manual trigger (Settings → "Send owner-paid report now").
exports.sendOwnerPaidReportNow = onCall(
  { secrets: [GMAIL_USER, GMAIL_PASS, NOTIFY_TO] },
  async (request) => {
    _requireOwner(request);
    return { ok: true, ...(await _sendOwnerPaidReport()) };
  }
);

// ─── salesReconciliation ──────────────────────────────────────────────────────
// Fires whenever sales data is saved to Firestore (i.e. when you upload a sales file).
// Compares each month present in the new sales data against shift closes totals.
exports.salesReconciliation = onDocumentUpdated(
  { document: "state/sales", secrets: [GMAIL_USER, GMAIL_PASS, NOTIFY_TO] },
  async (event) => {
    const db       = getDb();
    const newSales = (event.data.after.data().sales) || [];

    if (newSales.length === 0) return;

    // Detect which months are represented in the uploaded sales
    const months = [...new Set(newSales.filter(s => s.date).map(s => s.date.slice(0, 7)))].sort();

    const opSnap    = await db.collection("state").doc("operations").get();
    const allCloses = (opSnap.exists ? opSnap.data().shift_closes : null) || [];

    const lines = [];
    lines.push("📊 *Coffee Beats — Sales Reconciliation*");
    lines.push(`Triggered by sales file upload`);

    for (const ym of months) {
      const monthSales      = newSales.filter(s => s.date && s.date.startsWith(ym));
      const dashboardRevenue = monthSales.reduce((s, r) => s + (Number(r.net_sales) || 0), 0);
      const monthCloses     = allCloses.filter(c => c.date && c.date.startsWith(ym));
      const monthShiftTotal = _rowTotal(_sumPayments(monthCloses));
      const diff    = monthShiftTotal - dashboardRevenue;
      const absDiff = Math.abs(diff);
      const pct     = dashboardRevenue > 0 ? (absDiff / dashboardRevenue * 100).toFixed(1) : "N/A";

      lines.push("");
      lines.push(`📅 *${ym}*`);
      lines.push(`🔒 Shift closes:     ${_fmt(monthShiftTotal)}`);
      lines.push(`📈 Dashboard revenue: ${_fmt(dashboardRevenue)}`);
      lines.push(`Δ Difference:        ${_fmt(absDiff)} (${pct}%)`);

      if (absDiff < 100) {
        lines.push("✅ Match — within tolerance.");
      } else {
        lines.push("⚠️ *DISCREPANCY*");
        if (diff > 0) {
          lines.push(`   Shift closes exceed dashboard by ${_fmt(absDiff)}.`);
          lines.push(`   Possible cause: sales data incomplete for this month.`);
        } else {
          lines.push(`   Dashboard exceeds shift closes by ${_fmt(absDiff)}.`);
          lines.push(`   Possible cause: a shift close was skipped or misrecorded.`);
        }
      }
    }

    await _sendEmail(`📊 Sales Reconciliation — ${months.join(", ")}`, lines.join("\n"));
    console.log("Reconciliation email sent for months:", months.join(", "));
  }
);

// ─── helpers ──────────────────────────────────────────────────────────────────
function _requireOwner(request) {
  if (!request.auth || request.auth.token.role !== "owner") {
    throw new HttpsError("permission-denied", "Owner access required.");
  }
}

function _pinEncKey() {
  return crypto.createHash("sha256").update(PIN_ENC_KEY.value()).digest();
}
function _encryptPin(pin) {
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", _pinEncKey(), iv);
  const enc    = Buffer.concat([cipher.update(String(pin), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString("base64");
}
function _decryptPin(b64) {
  const data = Buffer.from(b64, "base64");
  const iv   = data.subarray(0, 12);
  const tag  = data.subarray(12, 28);
  const enc  = data.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", _pinEncKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
}

async function _createUser({ name, role, branches, pin, legacyId, emergency_number }) {
  if (!name || !role || !pin) throw new HttpsError("invalid-argument", "name, role, and pin are required.");

  const validRoles = ["owner", "head_barista", "barista", "accountant", "manager", "helper"];
  if (!validRoles.includes(role)) throw new HttpsError("invalid-argument", "Invalid role.");

  const userRecord = await getAuth().createUser({ displayName: name });
  const uid = userRecord.uid;

  await getAuth().setCustomUserClaims(uid, { role, branches: branches || [] });

  const pin_hash = await bcrypt.hash(String(pin), 12);
  const pin_enc  = _encryptPin(pin);

  await getDb().collection("staff").doc(uid).set({
    name, role,
    branches:         branches || [],
    active:           true,
    pin_hash,
    pin_enc,
    deny_access:      [],
    extra_access:     [],
    legacy_id:        legacyId || null,
    emergency_number: emergency_number || null,
    created_at:       admin.firestore.FieldValue.serverTimestamp(),
  });

  await getDb().collection("staff_public").doc(uid).set({
    uid, name, role,
    branches: branches || [],
    active:   true,
  });

  return { uid };
}
