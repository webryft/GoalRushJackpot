/**
 * GoalRush Jackpot — Cloud Functions
 * ----------------------------------
 * This is the trusted backend. Nothing that touches money, passwords,
 * or admin rights should ever be decided by client-side JS — it all
 * routes through here, where secrets stay server-side and every write
 * is checked against the caller's real identity (Firebase Auth token),
 * not a value typed into a browser.
 *
 * Deploy:
 *   cd functions && npm install
 *   firebase deploy --only functions,firestore:rules
 *
 * Required config (do NOT put these in index.html / admin.html):
 *   firebase functions:config:set paystack.secret="sk_live_xxx" \
 *                                  admin.bootstrap_secret="choose-a-long-random-string"
 */

const functions = require("firebase-functions");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.firestore();

const PAYSTACK_SECRET = functions.config().paystack?.secret || "";
const BOOTSTRAP_SECRET = functions.config().admin?.bootstrap_secret || "";
const MIN_DEPOSIT = 1000;

// ────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────
function requireAdmin(context) {
  if (!context.auth || context.auth.token.admin !== true) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Admin privileges required."
    );
  }
}

function hashCode(code) {
  return crypto.createHash("sha256").update(String(code)).digest("hex");
}

function genRef(prefix) {
  return prefix + "-" + crypto.randomBytes(6).toString("hex").toUpperCase();
}

async function logAction(action, user) {
  await db.collection("logs").add({
    time: new Date().toISOString(),
    action,
    user: user || "",
  });
}

// ────────────────────────────────────────────────────────────
// 1. PAYSTACK WEBHOOK
//    Paystack calls this directly — never the browser.
//    Register in Paystack Dashboard → Settings → API Keys & Webhooks:
//    https://<region>-<project-id>.cloudfunctions.net/paystackWebhook
// ────────────────────────────────────────────────────────────
exports.paystackWebhook = functions.https.onRequest(async (req, res) => {
  try {
    const signature = req.headers["x-paystack-signature"];
    const expected = crypto
      .createHmac("sha512", PAYSTACK_SECRET)
      .update(req.rawBody)
      .digest("hex");

    if (!signature || signature !== expected) {
      console.warn("Paystack webhook: bad signature");
      return res.sendStatus(401); // reject silently, nothing written to admin
    }

    const event = req.body;

    if (event.event !== "charge.success") {
      // Per spec: unsuccessful callbacks never appear in admin at all.
      return res.sendStatus(200);
    }

    const data = event.data;
    const reference = data.reference;
    const amountNaira = Math.round(Number(data.amount || 0) / 100);
    const email = data.customer?.email || "";
    const meta = data.metadata || {};
    const phone = (meta.custom_fields || []).find(
      (f) => f.variable_name === "phone"
    )?.value || "";
    const method = (meta.custom_fields || []).find(
      (f) => f.variable_name === "method"
    )?.value || "Paystack";

    // Double-check with Paystack's verify endpoint using the SECRET key
    // (never trust the webhook body alone).
    const verifyRes = await fetch(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` } }
    );
    const verifyJson = await verifyRes.json();
    if (!verifyJson.status || verifyJson.data?.status !== "success") {
      console.warn("Paystack webhook: verify mismatch for", reference);
      return res.sendStatus(200); // still don't surface to admin
    }

    // Find the user by phone (fallback: email) to attach uid for later crediting.
    let userUid = "";
    if (phone) {
      const uq = await db.collection("users").where("phone", "==", phone).limit(1).get();
      if (!uq.empty) userUid = uq.docs[0].id;
    }

    // Record as PENDING — admin still confirms manually before crediting (per spec).
    await db.collection("deposits").doc(reference).set(
      {
        id: reference,
        user: phone,
        userUid,
        email,
        amount: amountNaira,
        method,
        time: new Date().toISOString(),
        status: "pending", // admin sees this in the queue: pending / approved / declined
        paystackVerified: true,
        ref: reference,
      },
      { merge: true }
    );

    return res.sendStatus(200);
  } catch (err) {
    console.error("paystackWebhook error", err);
    return res.sendStatus(500);
  }
});

// ────────────────────────────────────────────────────────────
// 2. APPROVE / DECLINE DEPOSIT (admin only, server-credited)
// ────────────────────────────────────────────────────────────
exports.approveDeposit = functions.https.onCall(async (data, context) => {
  requireAdmin(context);
  const { depositId } = data;
  if (!depositId) throw new functions.https.HttpsError("invalid-argument", "depositId required");

  const depRef = db.collection("deposits").doc(depositId);

  const result = await db.runTransaction(async (tx) => {
    const depSnap = await tx.get(depRef);
    if (!depSnap.exists) throw new functions.https.HttpsError("not-found", "Deposit not found");
    const dep = depSnap.data();
    if (dep.status === "approved") throw new functions.https.HttpsError("failed-precondition", "Already approved");
    if (!dep.userUid) throw new functions.https.HttpsError("failed-precondition", "No matching user account for this deposit");

    const userRef = db.collection("users").doc(dep.userUid);
    const userSnap = await tx.get(userRef);
    const currentBal = Number(userSnap.data()?.balance || 0);
    const newBal = currentBal + Number(dep.amount || 0);

    tx.update(userRef, { balance: newBal, lastDeposit: new Date().toISOString() });
    tx.update(depRef, { status: "approved", approvedAt: new Date().toISOString(), approvedBy: context.auth.uid });

    return { newBal, amount: dep.amount, user: dep.user };
  });

  await logAction(`Deposit approved ₦${result.amount} (ref ${depositId})`, result.user);
  return { ok: true, newBalance: result.newBal };
});

exports.declineDeposit = functions.https.onCall(async (data, context) => {
  requireAdmin(context);
  const { depositId, reason } = data;
  if (!depositId) throw new functions.https.HttpsError("invalid-argument", "depositId required");

  const depRef = db.collection("deposits").doc(depositId);
  const depSnap = await depRef.get();
  if (!depSnap.exists) throw new functions.https.HttpsError("not-found", "Deposit not found");

  await depRef.update({
    status: "declined",
    declinedAt: new Date().toISOString(),
    declinedBy: context.auth.uid,
    declineReason: reason || "",
  });
  await logAction(`Deposit declined ₦${depSnap.data().amount} (ref ${depositId})`, depSnap.data().user);
  return { ok: true };
});

// ────────────────────────────────────────────────────────────
// 3. PASSWORD RESET — manual admin-relayed code
//    Flow: user requests -> admin sets a code -> user confirms code + new pw
// ────────────────────────────────────────────────────────────
exports.requestPasswordReset = functions.https.onCall(async (data) => {
  const email = String(data.email || "").trim().toLowerCase();
  if (!email || !email.includes("@")) {
    throw new functions.https.HttpsError("invalid-argument", "Valid email required");
  }
  try {
    await admin.auth().getUserByEmail(email);
  } catch (e) {
    // Don't reveal whether the email exists — respond the same either way.
    return { ok: true, requestId: null };
  }

  const reqRef = await db.collection("password_resets").add({
    email,
    status: "pending", // pending -> code_sent -> completed / expired
    requestedAt: new Date().toISOString(),
  });
  return { ok: true, requestId: reqRef.id };
});

exports.adminSetResetCode = functions.https.onCall(async (data, context) => {
  requireAdmin(context);
  const { requestId, code } = data;
  if (!requestId || !/^\d{6}$/.test(String(code || ""))) {
    throw new functions.https.HttpsError("invalid-argument", "requestId and 6-digit code required");
  }
  const reqRef = db.collection("password_resets").doc(requestId);
  const snap = await reqRef.get();
  if (!snap.exists) throw new functions.https.HttpsError("not-found", "Request not found");

  await reqRef.update({
    codeHash: hashCode(code),
    status: "code_sent",
    codeSetAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(), // 30 min
  });
  return { ok: true };
});

exports.confirmResetCode = functions.https.onCall(async (data) => {
  const { email, code, newPassword } = data;
  if (!email || !code || !newPassword || newPassword.length < 6) {
    throw new functions.https.HttpsError("invalid-argument", "email, code and newPassword (6+ chars) required");
  }
  // Find this email's most recent request that's awaiting a code.
  const q = await db.collection("password_resets")
    .where("email", "==", String(email).trim().toLowerCase())
    .where("status", "==", "code_sent")
    .orderBy("codeSetAt", "desc")
    .limit(1)
    .get();
  if (q.empty) throw new functions.https.HttpsError("not-found", "No active reset request for this email");
  const reqRef = q.docs[0].ref;
  const reqData = q.docs[0].data();

  if (reqData.status !== "code_sent") {
    throw new functions.https.HttpsError("failed-precondition", "No active code for this request");
  }
  if (new Date(reqData.expiresAt) < new Date()) {
    await reqRef.update({ status: "expired" });
    throw new functions.https.HttpsError("deadline-exceeded", "Code expired, request a new one");
  }
  if (hashCode(code) !== reqData.codeHash) {
    throw new functions.https.HttpsError("permission-denied", "Incorrect code");
  }

  const user = await admin.auth().getUserByEmail(reqData.email);
  await admin.auth().updateUser(user.uid, { password: newPassword });
  await reqRef.update({ status: "completed", completedAt: new Date().toISOString() });
  await logAction("Password reset completed", reqData.email);

  return { ok: true };
});

// ────────────────────────────────────────────────────────────
// 4. ADMIN USER MANAGEMENT — balance edits go through here so
//    every change is authenticated + logged, not a raw client write.
// ────────────────────────────────────────────────────────────
exports.adminAdjustBalance = functions.https.onCall(async (data, context) => {
  requireAdmin(context);
  const { uid, newBalance, note } = data;
  if (!uid || typeof newBalance !== "number" || newBalance < 0) {
    throw new functions.https.HttpsError("invalid-argument", "uid and non-negative newBalance required");
  }
  await db.collection("users").doc(uid).update({ balance: newBalance });
  await logAction(`Admin set balance to ₦${newBalance}${note ? " (" + note + ")" : ""}`, uid);
  return { ok: true };
});

exports.adminSetUserDisabled = functions.https.onCall(async (data, context) => {
  requireAdmin(context);
  const { uid, disabled } = data;
  if (!uid || typeof disabled !== "boolean") {
    throw new functions.https.HttpsError("invalid-argument", "uid and disabled(boolean) required");
  }
  await db.collection("users").doc(uid).update({ disabled });
  await admin.auth().updateUser(uid, { disabled });
  await logAction(disabled ? "Account disabled" : "Account re-enabled", uid);
  return { ok: true };
});

// ────────────────────────────────────────────────────────────
// 5. CLEAR MATCHES — wipes the round data so the next 14 load fresh
// ────────────────────────────────────────────────────────────
exports.clearMatches = functions.https.onCall(async (data, context) => {
  requireAdmin(context);
  await db.collection("app_settings").doc("matches").set({ matches: [], clearedAt: new Date().toISOString() });
  await db.collection("app_settings").doc("current_results").set({ results: null });
  await logAction("Matches cleared by admin", context.auth.uid);
  return { ok: true };
});

// ────────────────────────────────────────────────────────────
// 6. BROADCAST -> pushes into a real "notifications" collection
//    so the bell icon has a proper feed to read (instead of a
//    single app_settings/broadcast doc with no history).
// ────────────────────────────────────────────────────────────
exports.sendBroadcast = functions.https.onCall(async (data, context) => {
  requireAdmin(context);
  const { title, message } = data;
  if (!title || !message) throw new functions.https.HttpsError("invalid-argument", "title and message required");

  const note = {
    title,
    message,
    time: new Date().toISOString(),
    createdBy: context.auth.uid,
  };
  await db.collection("notifications").add(note);
  await db.collection("app_settings").doc("broadcast").set({
    msg: title + ": " + message,
    ts: Date.now(),
  });
  await logAction(`Broadcast sent: ${title}`, "admin");
  return { ok: true };
});

// ────────────────────────────────────────────────────────────
// 7. ONE-TIME BOOTSTRAP — grants the admin custom claim to your
//    Firebase Auth account. Call ONCE after creating the account,
//    then treat BOOTSTRAP_SECRET as burned (rotate/remove it).
//    curl -X POST https://<region>-<project>.cloudfunctions.net/bootstrapAdmin \
//      -H "Content-Type: application/json" \
//      -d '{"secret":"<BOOTSTRAP_SECRET>","email":"your-admin@yourdomain.com"}'
// ────────────────────────────────────────────────────────────
exports.bootstrapAdmin = functions.https.onRequest(async (req, res) => {
  try {
    const { secret, email } = req.body || {};
    if (!BOOTSTRAP_SECRET || secret !== BOOTSTRAP_SECRET) {
      return res.status(403).send("Forbidden");
    }
    const user = await admin.auth().getUserByEmail(email);
    await admin.auth().setCustomUserClaims(user.uid, { admin: true });
    return res.send(`OK — admin claim granted to ${email}. Sign the user out and back in to refresh their token.`);
  } catch (err) {
    console.error(err);
    return res.status(500).send(String(err));
  }
});
