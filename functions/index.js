const { onCall, HttpsError } = require("firebase-functions/v2/https");
const admin  = require("firebase-admin");
const bcrypt = require("bcryptjs");

// Lazy initialization — Admin SDK is only initialized when a function executes,
// not at module load time. This lets the Firebase CLI analyze the exports without
// needing local credentials.
function getDb() {
  if (!admin.apps.length) admin.initializeApp();
  return admin.firestore();
}

function getAuth() {
  if (!admin.apps.length) admin.initializeApp();
  return admin.auth();
}

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
  await getAuth().updateUser(targetUid, { disabled: !active });
  await getDb().collection("staff").doc(targetUid).update({ active });
  await getDb().collection("staff_public").doc(targetUid).update({ active });
  return { ok: true };
});

// ─── helpers ──────────────────────────────────────────────────────────────────
function _requireOwner(request) {
  if (!request.auth || request.auth.token.role !== "owner") {
    throw new HttpsError("permission-denied", "Owner access required.");
  }
}

async function _createUser({ name, role, branches, pin, legacyId }) {
  if (!name || !role || !pin) throw new HttpsError("invalid-argument", "name, role, and pin are required.");

  const validRoles = ["owner", "head_barista", "barista", "accountant", "manager", "helper"];
  if (!validRoles.includes(role)) throw new HttpsError("invalid-argument", "Invalid role.");

  const userRecord = await getAuth().createUser({ displayName: name });
  const uid = userRecord.uid;

  await getAuth().setCustomUserClaims(uid, { role, branches: branches || [] });

  const pin_hash = await bcrypt.hash(String(pin), 12);

  await getDb().collection("staff").doc(uid).set({
    name, role,
    branches:     branches || [],
    active:       true,
    pin_hash,
    deny_access:  [],
    extra_access: [],
    legacy_id:    legacyId || null,
    created_at:   admin.firestore.FieldValue.serverTimestamp(),
  });

  await getDb().collection("staff_public").doc(uid).set({
    uid, name, role,
    branches: branches || [],
    active:   true,
  });

  return { uid };
}
