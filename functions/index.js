const functions = require("firebase-functions");
const admin     = require("firebase-admin");
const bcrypt    = require("bcrypt");

admin.initializeApp();
const db = admin.firestore();

// ─── verifyPin ────────────────────────────────────────────────────────────────
// Called from the login screen. Verifies a staff member's PIN server-side and
// returns a Firebase custom token if correct.
//
// Input:  { staffId: string, pin: string }  (staffId = Firebase Auth UID)
// Output: { token: string }
exports.verifyPin = functions.https.onCall(async (data) => {
  const { staffId, pin } = data;
  if (!staffId || !pin) {
    throw new functions.https.HttpsError("invalid-argument", "staffId and pin are required.");
  }

  const snap = await db.collection("staff").doc(staffId).get();
  if (!snap.exists) {
    throw new functions.https.HttpsError("not-found", "Staff member not found.");
  }

  const staff = snap.data();
  if (!staff.active) {
    throw new functions.https.HttpsError("permission-denied", "Account is inactive.");
  }

  const match = await bcrypt.compare(String(pin), staff.pin_hash);
  if (!match) {
    throw new functions.https.HttpsError("unauthenticated", "Incorrect PIN.");
  }

  const token = await admin.auth().createCustomToken(staffId, {
    role:     staff.role,
    branches: staff.branches || [],
  });

  return { token };
});

// ─── createStaffUser ──────────────────────────────────────────────────────────
// Owner-only. Creates a Firebase Auth account + staff Firestore docs for a new
// team member.
//
// Input:  { name, role, branches, pin, legacyId? }
// Output: { uid: string }
exports.createStaffUser = functions.https.onCall(async (data, context) => {
  _requireOwner(context);
  return _createUser(data);
});

// ─── migrateUser ──────────────────────────────────────────────────────────────
// Owner-only. One-time migration helper for existing state.users entries.
// Same as createStaffUser but exposed separately for the migration UI.
//
// Input:  { name, role, branches, pin, legacyId }
// Output: { uid: string }
exports.migrateUser = functions.https.onCall(async (data, context) => {
  _requireOwner(context);
  return _createUser(data);
});

// ─── updateStaffPin ───────────────────────────────────────────────────────────
// Hashes and stores a new PIN. Owner can change anyone's; staff can only change
// their own (must supply currentPin for verification).
//
// Input:  { targetUid, newPin, currentPin? }
exports.updateStaffPin = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Must be signed in.");
  }

  const { targetUid, newPin, currentPin } = data;
  const callerUid  = context.auth.uid;
  const isOwner    = context.auth.token.role === "owner";
  const isSelf     = callerUid === targetUid;

  if (!isOwner && !isSelf) {
    throw new functions.https.HttpsError("permission-denied", "Not authorised.");
  }

  if (!isOwner && isSelf) {
    if (!currentPin) {
      throw new functions.https.HttpsError("invalid-argument", "currentPin is required.");
    }
    const snap = await db.collection("staff").doc(targetUid).get();
    const ok = await bcrypt.compare(String(currentPin), snap.data().pin_hash);
    if (!ok) {
      throw new functions.https.HttpsError("unauthenticated", "Current PIN is incorrect.");
    }
  }

  const pin_hash = await bcrypt.hash(String(newPin), 12);
  await db.collection("staff").doc(targetUid).update({ pin_hash });

  return { ok: true };
});

// ─── setStaffRole ─────────────────────────────────────────────────────────────
// Owner-only. Updates role and branches in both Auth claims and Firestore.
//
// Input:  { targetUid, role, branches }
exports.setStaffRole = functions.https.onCall(async (data, context) => {
  _requireOwner(context);

  const { targetUid, role, branches } = data;
  if (!targetUid || !role) {
    throw new functions.https.HttpsError("invalid-argument", "targetUid and role are required.");
  }

  await admin.auth().setCustomUserClaims(targetUid, { role, branches: branches || [] });
  await db.collection("staff").doc(targetUid).update({ role, branches: branches || [] });
  await db.collection("staff_public").doc(targetUid).update({ role, branches: branches || [] });

  return { ok: true };
});

// ─── setStaffActive ───────────────────────────────────────────────────────────
// Owner-only. Enables or disables a staff account.
//
// Input:  { targetUid, active: boolean }
exports.setStaffActive = functions.https.onCall(async (data, context) => {
  _requireOwner(context);

  const { targetUid, active } = data;
  await admin.auth().updateUser(targetUid, { disabled: !active });
  await db.collection("staff").doc(targetUid).update({ active });
  await db.collection("staff_public").doc(targetUid).update({ active });

  return { ok: true };
});

// ─── internal helpers ──────────────────────────────────────────────────────────

function _requireOwner(context) {
  if (!context.auth || context.auth.token.role !== "owner") {
    throw new functions.https.HttpsError("permission-denied", "Owner access required.");
  }
}

async function _createUser({ name, role, branches, pin, legacyId }) {
  if (!name || !role || !pin) {
    throw new functions.https.HttpsError("invalid-argument", "name, role, and pin are required.");
  }
  const validRoles = ["owner", "head_barista", "barista", "accountant", "manager", "helper"];
  if (!validRoles.includes(role)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid role.");
  }

  const userRecord = await admin.auth().createUser({ displayName: name });
  const uid = userRecord.uid;

  await admin.auth().setCustomUserClaims(uid, {
    role,
    branches: branches || [],
  });

  const pin_hash = await bcrypt.hash(String(pin), 12);

  const staffData = {
    name,
    role,
    branches:     branches || [],
    active:       true,
    pin_hash,
    deny_access:  [],
    extra_access: [],
    legacy_id:    legacyId || null,
    created_at:   admin.firestore.FieldValue.serverTimestamp(),
  };

  // staff/{uid}     — private: contains pin_hash, deny/extra_access
  // staff_public/{uid} — public read: name, role, branches, active, uid for login screen
  await db.collection("staff").doc(uid).set(staffData);
  await db.collection("staff_public").doc(uid).set({ uid, name, role, branches: branches || [], active: true });

  return { uid };
}
