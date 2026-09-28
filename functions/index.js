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

// ─── Owner-paid expenses report ───────────────────────────────────────────────
// Every record paid from the owner — "Company bank / owner transfer" (owner_bank) or
// "Paid personally — reimburse me later" (owner_personal) — dated within the last
// OWNER_PAID_WINDOW_DAYS days (Cairo time). Sent weekly, and on demand from Settings.
// The email always goes out, even with an empty list, so the machine-readable JSON
// block lets the receiving side reconcile deletions.
//
// Sources, all in the state/<chunk> docs the app syncs (see STATE_CHUNKS in index.html):
//   purchases.purchases         paid_by
//   overhead.overheads          paid_from   (incl. maintenance / pest control)
//   equipment.equipment         paid_from
//   hr.salaries, hr.salary_loans paid_from
//   purchases.bank_ledger       outflows not tied to one of the records above
//                               (petty-cash top-ups funded from the bank, manual entries)
//   purchases.owner_account     personal payments not tied to one of the records above
//                               (petty-cash top-ups / corrections paid personally)
// Records tied to a primary record (same ref) are skipped so nothing is counted twice.
const OWNER_PAID_WINDOW_DAYS = 45;
const OWNER_PAY_METHODS = new Set(["owner_bank", "owner_personal"]);
// Bank-ledger outflows that are NOT owner-paid expenses: card payments, and the
// company repaying the owner (the original personal payment is already listed).
const BANK_TYPES_NOT_OWNER = new Set([
  "purchase_credit_card", "overhead_credit_card", "asset_credit_card", "personal_reimbursement",
]);
// Mirrors OVERHEAD_CATEGORIES / ASSET_CATEGORIES labels in index.html.
const OVERHEAD_LABELS = {
  electricity: "Electricity bill", internet: "Internet bill", cleaner_salary: "Cleaner salary",
  accountant_salary: "Accountant salary", pos_fees: "POS fees", gardener_salary: "Gardener salary",
  loan_payment: "Loan payment", marketing_fees: "Marketing fees", sponsorship: "Sponsorship",
  uniforms: "Uniforms", software: "Software / subscriptions", agency_design: "Agency / design",
  legal_fees: "Legal fees", equipment_repair: "Equipment repair", misc: "Miscellaneous",
  maintenance_1: "Maintenance — Cooling (fridges & ice maker)",
  maintenance_2: "Maintenance — Machines (coffee, water, grinders, blender)",
  insect_control: "Insect / pest control",
  maintenance_emergency: "Maintenance — Emergency (unscheduled)",
};
const ASSET_LABELS = {
  machines: "Machines", refrigeration: "Refrigeration", furniture: "Furniture & fixtures",
  fitout: "Fit-out & renovation", electronics: "Electronics & IT", smallwares: "Smallwares & tools",
  other: "Other",
};

// Format a Date as YYYY-MM-DD in Cairo time. Same name/contract as the app's
// localISODate(); the function runs in UTC, so the zone is set explicitly.
function localISODate(d) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Africa/Cairo", year: "numeric", month: "2-digit", day: "2-digit",
  }).format(d);
}

function _branchName(b) {
  const v = String(b || "").toLowerCase();
  return v === "maadi" ? "Maadi" : v === "zawya" ? "Zawya" : "";
}
function _amount(n) { return Math.round((Number(n) || 0) * 100) / 100; }
// First usable date: a plain YYYY-MM-DD as entered, or a full timestamp (e.g. the
// record's `at`) converted to its Cairo calendar day.
function _recDate(...cands) {
  for (const c of cands) {
    if (typeof c !== "string") continue;
    if (/^\d{4}-\d{2}-\d{2}$/.test(c)) return c;
    if (/^\d{4}-\d{2}-\d{2}T/.test(c)) {
      const d = new Date(c);
      if (!isNaN(d)) return localISODate(d);
    }
  }
  return "";
}

async function _buildOwnerPaidReport() {
  const db = getDb();
  const chunkNames = ["purchases", "overhead", "equipment", "hr", "tombstones", "admin_trash"];
  const snaps = await Promise.all(chunkNames.map(c => db.collection("state").doc(c).get()));
  const S = {};
  for (const s of snaps) if (s.exists) Object.assign(S, s.data());
  const arr = (k) => (Array.isArray(S[k]) ? S[k] : []).filter(r => r && typeof r === "object");

  // Deleted = tombstoned on any device, or sitting in a trash array.
  const deleted = new Set(arr("deleted_ids").map(t => t.id));
  for (const [k, v] of Object.entries(S)) {
    if (k.startsWith("deleted_") && k !== "deleted_ids" && Array.isArray(v)) {
      for (const r of v) if (r && r.id != null) deleted.add(r.id);
    }
  }
  const live = (r) => r.id != null && !deleted.has(r.id) && !r.is_test && !r._deleted;

  const today       = localISODate(new Date());
  const windowStart = localISODate(new Date(Date.now() - OWNER_PAID_WINDOW_DAYS * 86400000));
  const inWindow    = (d) => d && d >= windowStart && d <= today;

  const customCats = {};
  for (const c of arr("overhead_custom_cats")) if (c.value && c.label) customCats[c.value] = c.label;
  const catOverrides = (S.overhead_cat_overrides && typeof S.overhead_cat_overrides === "object") ? S.overhead_cat_overrides : {};
  const overheadLabel = (v) => customCats[v] || (catOverrides[v] || {}).label || OVERHEAD_LABELS[v] || v || "Overhead";

  const rows = [];
  // Every primary record id (owner-paid or not) — a ledger row pointing at one of
  // these is that record's mirror, never a separate expense.
  const primaryIds = new Set();
  const add = (r, fields) => {
    if (!inWindow(fields.date)) return;
    rows.push({
      id: String(r.id),
      date: fields.date,
      amount: _amount(fields.amount),
      category: fields.category || "",
      supplier: fields.supplier || "",
      branch: _branchName(fields.branch),
      note: fields.note || "",
      logged_by: r.by_name || r.by || "",
      _method: fields.method,
    });
  };

  for (const p of arr("purchases")) {
    primaryIds.add(p.id);
    if (!live(p) || !OWNER_PAY_METHODS.has(p.paid_by)) continue;
    const items = (p.lines || []).map(l => l.item_name || l.description).filter(Boolean);
    const noteParts = [];
    if (items.length) noteParts.push(items.join(", "));
    if (p.split_group) noteParts.push(`split ${p.split_pct}% with ${p.split_with}`);
    add(p, {
      date: _recDate(p.date, p.at), amount: p.total, category: "Purchase",
      supplier: p.supplier, branch: p.branch, note: noteParts.join(" · "), method: p.paid_by,
    });
  }

  for (const o of arr("overheads")) {
    primaryIds.add(o.id);
    if (!live(o) || o.paid === false || !OWNER_PAY_METHODS.has(o.paid_from)) continue;
    add(o, {
      date: _recDate(o.paid_on, o.date, o.at), amount: o.amount, category: overheadLabel(o.category),
      supplier: o.label || "", branch: o.branch, note: o.note || "", method: o.paid_from,
    });
  }

  for (const a of arr("equipment")) {
    primaryIds.add(a.id);
    if (!live(a) || !OWNER_PAY_METHODS.has(a.paid_from)) continue;
    const shared = a.branch === "shared";
    add(a, {
      date: _recDate(a.purchase_date, a.at), amount: a.cost,
      category: `Equipment — ${ASSET_LABELS[a.category] || a.category || "Other"}`,
      supplier: a.supplier || "", branch: a.branch,
      note: [a.name, shared ? "shared by both branches" : "", a.note].filter(Boolean).join(" · "),
      method: a.paid_from,
    });
  }

  for (const s of arr("salaries")) {
    primaryIds.add(s.id);
    if (!live(s) || !OWNER_PAY_METHODS.has(s.paid_from)) continue;
    add(s, {
      date: _recDate(s.date, s.at), amount: s.amount, category: "Salary",
      supplier: s.recipient || "", branch: s.branch,
      note: [s.month ? `for ${s.month}` : "", s.note].filter(Boolean).join(" · "), method: s.paid_from,
    });
  }

  for (const l of arr("salary_loans")) {
    primaryIds.add(l.id);
    if (!live(l) || !OWNER_PAY_METHODS.has(l.paid_from)) continue;
    add(l, {
      date: _recDate(l.date, l.at), amount: l.amount, category: "Loan advance",
      supplier: l.barista || "", branch: "",
      note: [l.month ? `deduct ${l.month}` : "", l.note].filter(Boolean).join(" · "), method: l.paid_from,
    });
  }

  // Bank outflows not already represented above (e.g. petty-cash top-ups, manual entries).
  for (const b of arr("bank_ledger")) {
    if (!live(b) || !(Number(b.amount) < 0) || BANK_TYPES_NOT_OWNER.has(b.type)) continue;
    if (b.ref && (primaryIds.has(b.ref) || deleted.has(b.ref))) continue;
    const pc = b.type === "petty_cash_topup";
    add(b, {
      date: _recDate(b.date, b.at), amount: Math.abs(Number(b.amount)),
      category: pc ? "Petty cash top-up" : "Bank payment",
      supplier: pc ? "" : (b.supplier || ""),
      branch: pc ? ((/\(([^)]+)\)/.exec(b.supplier || "") || [])[1] || "") : "",
      note: b.note || "", method: "owner_bank",
    });
  }

  // Personal payments not already represented above (petty-cash top-ups / corrections).
  for (const e of arr("owner_account")) {
    if (!live(e) || !(Number(e.amount) > 0)) continue;
    if (e.ref && (primaryIds.has(e.ref) || deleted.has(e.ref))) continue;
    add(e, {
      date: _recDate(e.date, e.at), amount: e.amount,
      category: e.source === "petty_cash" ? "Petty cash top-up" : "Personal payment",
      supplier: "", branch: e.branch,
      note: [e.label, e.reimbursed ? "reimbursed" : ""].filter(Boolean).join(" · "), method: "owner_personal",
    });
  }

  rows.sort((a, b) => a.date.localeCompare(b.date) || a.id.localeCompare(b.id));
  const total = _amount(rows.reduce((s, r) => s + r.amount, 0));

  const methodLabel = { owner_bank: "owner bank", owner_personal: "paid personally" };
  const lines = [];
  lines.push("Coffee Beats — Owner-paid expenses");
  lines.push(`Window: ${windowStart} to ${today} (last ${OWNER_PAID_WINDOW_DAYS} days, Cairo time)`);
  lines.push("");
  if (rows.length === 0) {
    lines.push("No owner-paid expenses in this window.");
  } else {
    rows.forEach((r, i) => {
      lines.push(`${i + 1}. ${r.date} · ${_fmt(r.amount)} · ${r.category}` +
        ` · ${r.supplier || "—"} · ${r.branch || "—"}` +
        ` · ${r.note || "—"} · logged by ${r.logged_by || "—"} (${methodLabel[r._method] || r._method})`);
    });
  }
  lines.push("");
  lines.push(`TOTAL: ${_fmt(total)} (${rows.length} record${rows.length === 1 ? "" : "s"})`);
  lines.push("");
  lines.push(`WINDOW_START=${windowStart}`);
  lines.push("OWNER_PAID_JSON_START");
  lines.push(JSON.stringify(rows.map(({ _method, ...r }) => r)));
  lines.push("OWNER_PAID_JSON_END");

  return { subject: `Owner-paid expenses – ${today}`, text: lines.join("\n"), count: rows.length, total, windowStart, today };
}

async function _sendOwnerPaidReport() {
  const r = await _buildOwnerPaidReport();
  await _sendEmail(r.subject, r.text);
  console.log(`Owner-paid report sent: ${r.count} record(s), total ${r.total}, window ${r.windowStart}..${r.today}`);
  return r;
}

// Every Sunday 21:00 Cairo.
exports.sendOwnerPaidReport = onSchedule(
  { schedule: "0 21 * * 0", timeZone: "Africa/Cairo", secrets: [GMAIL_USER, GMAIL_PASS, NOTIFY_TO] },
  async () => { await _sendOwnerPaidReport(); }
);

// Owner-only manual trigger (Settings → "Send owner-paid report now").
exports.sendOwnerPaidReportNow = onCall(
  { secrets: [GMAIL_USER, GMAIL_PASS, NOTIFY_TO] },
  async (request) => {
    _requireOwner(request);
    const r = await _sendOwnerPaidReport();
    return { ok: true, count: r.count, total: r.total, windowStart: r.windowStart };
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
