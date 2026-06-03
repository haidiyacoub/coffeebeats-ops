const { onCall, HttpsError }     = require("firebase-functions/v2/https");
const { onSchedule }             = require("firebase-functions/v2/scheduler");
const { onDocumentUpdated }      = require("firebase-functions/v2/firestore");
const { defineSecret }           = require("firebase-functions/params");
const admin      = require("firebase-admin");
const bcrypt     = require("bcryptjs");
const nodemailer = require("nodemailer");

// Gmail app-password credentials (set via: firebase functions:secrets:set <NAME>)
const GMAIL_USER = defineSecret("GMAIL_USER");   // your Gmail address
const GMAIL_PASS = defineSecret("GMAIL_PASS");   // Gmail app password (16-char)
const NOTIFY_TO  = defineSecret("NOTIFY_TO");    // recipient email (can be same as GMAIL_USER)

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

  const match = await bcrypt.compare(String(pin), staff.pin_hash);
  if (!match) throw new HttpsError("unauthenticated", "Incorrect PIN.");

  const token = await getAuth().createCustomToken(staffId, {
    role:     staff.role,
    branches: staff.branches || [],
  });

  return { token };
});

// ─── createStaffUser ──────────────────────────────────────────────────────────
exports.createStaffUser = onCall(async (request) => {
  _requireOwner(request);
  return _createUser(request.data);
});

// ─── migrateUser ──────────────────────────────────────────────────────────────
exports.migrateUser = onCall(async (request) => {
  _requireOwner(request);
  return _createUser(request.data);
});

// ─── updateStaffPin ───────────────────────────────────────────────────────────
exports.updateStaffPin = onCall(async (request) => {
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
  await getDb().collection("staff").doc(targetUid).update({ pin_hash });
  return { ok: true };
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

async function _createUser({ name, role, branches, pin, legacyId, emergency_number }) {
  if (!name || !role || !pin) throw new HttpsError("invalid-argument", "name, role, and pin are required.");

  const validRoles = ["owner", "head_barista", "barista", "accountant", "manager", "helper"];
  if (!validRoles.includes(role)) throw new HttpsError("invalid-argument", "Invalid role.");

  const userRecord = await getAuth().createUser({ displayName: name });
  const uid = userRecord.uid;

  await getAuth().setCustomUserClaims(uid, { role, branches: branches || [] });

  const pin_hash = await bcrypt.hash(String(pin), 12);

  await getDb().collection("staff").doc(uid).set({
    name, role,
    branches:         branches || [],
    active:           true,
    pin_hash,
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
