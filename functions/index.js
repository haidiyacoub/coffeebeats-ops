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
