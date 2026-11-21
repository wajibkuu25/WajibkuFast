/**
 * ============================================================================
 * Wajibku Fast — Backend Google Apps Script (Code.gs) [Hardened Phase 1]
 * ============================================================================
 * Petunjuk Setup & Deployment Aman:
 * 1. Pastikan SPREADSHEET_ID dan DRIVE_FOLDER_ID mengarah ke file/folder Anda
 *    dengan izin berbagi Google Drive disetel TERBATAS (Restricted / Hanya Anda).
 * 2. Jalankan `setupDatabaseSheets()` satu kali dari Editor Apps Script untuk
 *    menyiapkan header 5 tab (termasuk kolom Status_Akun, Token_Version, & Status)
 *    serta meng-hash password plaintext lama.
 * 3. Jika belum ada akun Super Admin, jalankan dari Editor Apps Script:
 *    `bootstrapSuperAdmin("email@domain.id", "KataSandiKuatMinimal10Karakter!")`
 *    (Tidak ada kata sandi bawaan dan kata sandi tidak pernah ditulis ke log.)
 * 4. Jalankan `aktifkanIzinEmailOtp()` satu kali dari Editor Apps Script untuk
 *    menyetujui izin MailApp, cek kuota email harian, dan kirim email uji coba.
 * 5. Klik Deploy > Manage deployments > Edit > Version: New version
 *    - Execute as: Me (Email Anda)
 *    - Who has access: Anyone
 * ============================================================================
 */

const SPREADSHEET_ID = "1aJjDWtT3qMEm891oXI1FyKg4SaXGS1EV-kBjnPWXyDc";
const DRIVE_FOLDER_ID = "1rtEXH6wI0sm5tH4shNBXMUAuQ2mwzUDs";
const DRIVE_FOLDER_URL = "https://drive.google.com/drive/folders/1rtEXH6wI0sm5tH4shNBXMUAuQ2mwzUDs";
const DATABASE_FILE_NAME = "WajibkuFast_Database";
const DRIVE_FOLDER_NAME = "WajibkuFast_Upload_Files";

const TOKEN_TTL_SECONDS = 12 * 60 * 60; // 12 jam
const PBKDF2_ITERATIONS = 1000;
const LEGACY_SHA256_ITERATIONS = 100;
const MIN_PASSWORD_LENGTH = 8;
const MIN_BOOTSTRAP_PASSWORD_LENGTH = 10;
const MAX_UPLOAD_BYTES = Math.floor(2.5 * 1024 * 1024); // Tepat 2,5 MB (2.621.440 byte)

const OTP_TTL_SECONDS = 10 * 60; // 10 menit
const OTP_MAX_ATTEMPTS = 5;

const RL_WINDOW_SECONDS = 15 * 60; // 15 menit
const RL_LOGIN_MAX = 5;
const RL_TRACK_MAX = 5;
const RL_OTP_MAX = 3;

const PUBLIC_ORDER_STEPS = ["Menunggu Bayar", "Diproses", "Selesai", "Diambil"];
const ALLOWED_ORDER_STATUS = ["Menunggu Bayar", "Diproses", "Selesai", "Diambil", "Diarsipkan"];
const ALLOWED_PAY_STATUS = ["Belum Bayar", "Menunggu Verifikasi", "Lunas"];
const ALLOWED_USER_ROLES = ["User", "Admin", "Super Admin"];
const ALLOWED_ACCOUNT_STATUS = ["Aktif", "Nonaktif"];
const ALLOWED_PRODUCT_STATUS = ["Tersedia", "Habis", "Arsip"];
const ALLOWED_FINISHING_STATUS = ["Tersedia", "Arsip"];

const ALLOWED_UPLOAD_MIME_MAP = {
  "image/jpeg": { canonical: "image/jpeg", ext: ".jpg", kind: "jpeg" },
  "image/jpg": { canonical: "image/jpeg", ext: ".jpg", kind: "jpeg" },
  "image/png": { canonical: "image/png", ext: ".png", kind: "png" },
  "image/webp": { canonical: "image/webp", ext: ".webp", kind: "webp" },
  "application/pdf": { canonical: "application/pdf", ext: ".pdf", kind: "pdf" },
  "application/zip": { canonical: "application/zip", ext: ".zip", kind: "zip" },
  "application/x-zip-compressed": { canonical: "application/zip", ext: ".zip", kind: "zip" },
  "application/postscript": { canonical: "application/postscript", ext: ".ai", kind: "postscript" },
  "application/illustrator": { canonical: "application/postscript", ext: ".ai", kind: "postscript" }
};

/**
 * Definisi Header 5 Tab Wajib (Case-Sensitive, penambahan kolom bersifat non-destruktif)
 */
const SCHEMA_HEADERS = {
  Users: ["User_ID", "Nama", "No_WA", "Email", "Role", "Alamat", "Password", "Status_Akun", "Token_Version"],
  Produk: ["Produk_ID", "Nama_Produk", "Kategori", "Tipe_Hitung", "Harga_Dasar", "Satuan", "Min_Order", "Status"],
  Finishing: ["Finishing_ID", "Nama_Finishing", "Tipe_Biaya", "Tambahan_Harga", "Keterangan", "Status"],
  Pesanan: ["Order_ID", "Tanggal", "User_ID", "Status_Order", "Total_Tagihan", "Bukti_Bayar", "Status_Bayar", "Catatan", "Harga_Kotor", "Saldo_Dipakai", "Saldo_Status", "Harga_Per_M2", "Modal_Per_M2", "Reward_Per_M2", "Reward_Amount", "Reward_Status", "Reward_Ref"],
  Detail_Pesanan: ["Detail_ID", "Order_ID", "Produk_ID", "Panjang_m", "Lebar_m", "Qty", "Finishing_ID", "File_Desain", "Keterangan_Item", "Subtotal"],
  Member_Profiles: ["User_ID", "Nama_Bank", "Nomor_Rekening", "Nama_Pemilik", "Updated_At"],
  Wallet_Accounts: ["Wallet_ID", "User_ID", "Available_Balance", "Held_Balance", "Created_At", "Updated_At"],
  Wallet_Transactions: ["Trx_ID", "Created_At", "User_ID", "Order_ID", "Transaction_Type", "Amount", "Reference_ID", "Description", "Created_By"],
  Withdrawal_Requests: ["Withdraw_ID", "Created_At", "User_ID", "Amount", "Bank_Name", "Account_Number", "Account_Holder", "Status", "Admin_Note", "Bukti_Transfer", "Reference_ID", "Processed_At", "Processed_By"],
  System_Settings: ["Setting_Key", "Setting_Value", "Updated_At", "Updated_By"],
  Biaya_Tambahan: ["Biaya_ID", "Tanggal", "Keterangan", "Jumlah", "Created_By"]
};

// ============================================================================
// UTILITAS KEAMANAN, PBKDF2-HMAC-SHA256, RATE LIMIT, OTP, & HMAC TOKEN
// ============================================================================

function getHmacSecret_() {
  const props = PropertiesService.getScriptProperties();
  let secret = props.getProperty("AUTH_HMAC_SECRET");
  if (!secret || secret.length < 32) {
    secret = Utilities.getUuid() + "-" + Utilities.getUuid() + "-" + String(Date.now());
    props.setProperty("AUTH_HMAC_SECRET", secret);
  }
  return secret;
}

const HEX_BYTE_TABLE_ = (function () {
  const t = [];
  for (let i = 0; i < 256; i++) t.push(("0" + i.toString(16)).slice(-2));
  return t;
})();

function bytesToHex_(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += HEX_BYTE_TABLE_[bytes[i] & 0xff];
  }
  return out;
}

function base64UrlEncodeBytes_(bytes) {
  return Utilities.base64EncodeWebSafe(bytes).replace(/=+$/, "");
}

function base64UrlEncodeString_(str) {
  const utf8 = Utilities.newBlob(String(str)).getBytes();
  return base64UrlEncodeBytes_(utf8);
}

function base64UrlDecodeString_(b64url) {
  const padded = String(b64url) + "===".slice((String(b64url).length + 3) % 4);
  const bytes = Utilities.base64DecodeWebSafe(padded);
  return Utilities.newBlob(bytes).getDataAsString("UTF-8");
}

function constantTimeEqual_(a, b) {
  const strA = String(a || "");
  const strB = String(b || "");
  const maxLen = Math.max(strA.length, strB.length);
  let diff = strA.length ^ strB.length;
  for (let i = 0; i < maxLen; i++) {
    const ca = i < strA.length ? strA.charCodeAt(i) : 0;
    const cb = i < strB.length ? strB.charCodeAt(i) : 0;
    diff |= (ca ^ cb);
  }
  return diff === 0 && maxLen > 0;
}

function computePbkdf2Hash_(plainPassword, salt, iterations) {
  const rounds = Math.max(1, Math.floor(Number(iterations) || PBKDF2_ITERATIONS));
  let u = Utilities.computeHmacSha256Signature(salt + ":1", plainPassword);
  const acc = u.map(function (b) { return b & 0xff; });
  for (let i = 1; i < rounds; i++) {
    u = Utilities.computeHmacSha256Signature(bytesToHex_(u), plainPassword);
    for (let j = 0; j < acc.length && j < u.length; j++) {
      acc[j] = acc[j] ^ (u[j] & 0xff);
    }
  }
  return "pbkdf2$" + rounds + "$" + salt + "$" + bytesToHex_(acc);
}

function hashLegacySha256_(plainPassword, salt) {
  let digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, salt + ":" + plainPassword);
  for (let i = 1; i < LEGACY_SHA256_ITERATIONS; i++) {
    digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytesToHex_(digest) + ":" + salt);
  }
  return "sha256$" + salt + "$" + bytesToHex_(digest);
}

function hashPassword_(plainPassword, saltOpt) {
  const plain = String(plainPassword || "");
  if (!plain) return "";
  const salt = saltOpt || Utilities.getUuid().replace(/-/g, "");
  return computePbkdf2Hash_(plain, salt, PBKDF2_ITERATIONS);
}

function isHashedPassword_(val) {
  const s = String(val || "").trim();
  return s.startsWith("pbkdf2$") || s.startsWith("sha256$");
}

function verifyPassword_(plainPassword, storedPassword) {
  const plain = String(plainPassword || "");
  const stored = String(storedPassword || "").trim();
  if (!plain || !stored) {
    return { valid: false, needsUpgrade: false };
  }
  if (stored.startsWith("pbkdf2$")) {
    const parts = stored.split("$");
    if (parts.length !== 4 || !parts[1] || !parts[2] || !parts[3]) {
      return { valid: false, needsUpgrade: false };
    }
    const iter = parseInt(parts[1], 10);
    if (!Number.isFinite(iter) || iter < 1 || iter > 20000) {
      return { valid: false, needsUpgrade: false };
    }
    const expected = computePbkdf2Hash_(plain, parts[2], iter);
    return {
      valid: constantTimeEqual_(expected, stored),
      needsUpgrade: iter < PBKDF2_ITERATIONS
    };
  }
  if (stored.startsWith("sha256$")) {
    const parts = stored.split("$");
    if (parts.length !== 3 || !parts[1] || !parts[2]) {
      return { valid: false, needsUpgrade: false };
    }
    const expectedHash = hashLegacySha256_(plain, parts[1]);
    return { valid: constantTimeEqual_(expectedHash, stored), needsUpgrade: true };
  }
  // Dukungan migrasi otomatis sekali pakai untuk password plaintext lama di Sheet
  return { valid: constantTimeEqual_(plain, stored), needsUpgrade: true };
}

function normalizeRole_(roleVal) {
  const r = String(roleVal || "").trim().toLowerCase();
  if (r === "super admin" || r === "superadmin") return "Super Admin";
  if (r === "admin") return "Admin";
  return "User";
}

function normalizeAccountStatus_(statusVal) {
  const s = String(statusVal || "").trim().toLowerCase();
  if (s === "nonaktif" || s === "inactive" || s === "disabled" || s === "arsip") {
    return "Nonaktif";
  }
  return "Aktif";
}

function normalizeTokenVersion_(verVal) {
  const n = Math.floor(Number(verVal));
  return Number.isFinite(n) && n >= 1 ? n : 1;
}

function sanitizeUser_(u) {
  if (!u) return null;
  return {
    User_ID: String(u.User_ID || ""),
    Nama: String(u.Nama || ""),
    No_WA: String(u.No_WA || "").replace(/^'/, ""),
    Email: String(u.Email || ""),
    Role: normalizeRole_(u.Role),
    Alamat: String(u.Alamat || ""),
    Status_Akun: normalizeAccountStatus_(u.Status_Akun),
    Token_Version: normalizeTokenVersion_(u.Token_Version),
    Has_Password: Boolean(String(u.Password || "").trim())
  };
}

function createToken_(user) {
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = {
    uid: String(user.User_ID || ""),
    role: normalizeRole_(user.Role),
    email: String(user.Email || ""),
    nama: String(user.Nama || ""),
    ver: normalizeTokenVersion_(user.Token_Version),
    iat: nowSec,
    exp: nowSec + TOKEN_TTL_SECONDS
  };
  const payloadB64 = base64UrlEncodeString_(JSON.stringify(payload));
  const sigBytes = Utilities.computeHmacSha256Signature(payloadB64, getHmacSecret_());
  const sigB64 = base64UrlEncodeBytes_(sigBytes);
  return payloadB64 + "." + sigB64;
}

function verifyToken_(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;

  const payloadB64 = parts[0];
  const providedSig = parts[1];
  const expectedSigBytes = Utilities.computeHmacSha256Signature(payloadB64, getHmacSecret_());
  const expectedSig = base64UrlEncodeBytes_(expectedSigBytes);

  if (!constantTimeEqual_(providedSig, expectedSig)) {
    return null;
  }

  try {
    const payload = JSON.parse(base64UrlDecodeString_(payloadB64));
    const nowSec = Math.floor(Date.now() / 1000);
    if (!payload || !payload.uid || !payload.exp || Number(payload.exp) <= nowSec) {
      return null;
    }
    return payload;
  } catch (err) {
    return null;
  }
}

function requireRole_(ss, body, allowedRoles) {
  const token = body && body.token ? String(body.token) : "";
  const session = verifyToken_(token);
  if (!session) {
    throw new Error("Sesi tidak valid atau telah berakhir. Silakan login ulang.");
  }

  const users = sheetToObjects_(ss, "Users");
  const liveUser = users.find(function (u) {
    return String(u.User_ID || "").trim() === String(session.uid).trim();
  });
  if (!liveUser) {
    throw new Error("Sesi tidak valid: akun pengguna tidak ditemukan.");
  }

  if (normalizeAccountStatus_(liveUser.Status_Akun) !== "Aktif") {
    throw new Error("Akun Anda sedang dinonaktifkan. Hubungi pengelola.");
  }

  const liveVer = normalizeTokenVersion_(liveUser.Token_Version);
  const tokenVer = normalizeTokenVersion_(session.ver);
  if (tokenVer !== liveVer) {
    throw new Error("Sesi telah dicabut atau kata sandi telah berubah. Silakan login ulang.");
  }

  const liveRole = normalizeRole_(liveUser.Role);
  if (allowedRoles && allowedRoles.indexOf(liveRole) === -1) {
    throw new Error("Akses ditolak: Anda tidak memiliki izin (" + liveRole + ").");
  }

  return { session: session, user: liveUser, role: liveRole };
}

function isProtectedSuperAdmin_(allUsers, targetUser) {
  if (!targetUser) return false;
  const targetId = String(targetUser.User_ID || "").trim().toUpperCase();
  if (targetId === "SUP-001") return true;
  const isTargetActiveSuper =
    normalizeRole_(targetUser.Role) === "Super Admin" &&
    normalizeAccountStatus_(targetUser.Status_Akun) === "Aktif";
  if (!isTargetActiveSuper) return false;

  const activeSupers = (allUsers || []).filter(function (u) {
    return normalizeRole_(u.Role) === "Super Admin" &&
      normalizeAccountStatus_(u.Status_Akun) === "Aktif";
  });
  return activeSupers.length <= 1;
}

// ============================================================================
// CACHE SERVICE: RATE LIMITER & PENYIMPANAN OTP SEMENTARA
// ============================================================================

function getScriptCacheSafe_() {
  try {
    if (typeof CacheService !== "undefined" && CacheService && typeof CacheService.getScriptCache === "function") {
      return CacheService.getScriptCache();
    }
  } catch (e) {}
  return null;
}

function buildCacheKey_(prefix, rawKey) {
  const normalized = String(rawKey || "").trim().toLowerCase();
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, prefix + ":" + normalized);
  return prefix + "_" + bytesToHex_(digest).slice(0, 32);
}

function checkRateLimit_(prefix, rawKey, maxAttempts) {
  const cache = getScriptCacheSafe_();
  if (!cache) return { blocked: false, count: 0 };
  const key = buildCacheKey_("rl_" + prefix, rawKey);
  const raw = cache.get(key);
  if (!raw) return { blocked: false, count: 0 };
  try {
    const parsed = JSON.parse(raw);
    const count = Number(parsed.count) || 0;
    const resetAt = Number(parsed.resetAt) || 0;
    if (resetAt && Date.now() > resetAt) {
      cache.remove(key);
      return { blocked: false, count: 0 };
    }
    return { blocked: count >= maxAttempts, count: count };
  } catch (e) {
    return { blocked: false, count: 0 };
  }
}

function recordRateLimitAttempt_(prefix, rawKey, windowSeconds) {
  const cache = getScriptCacheSafe_();
  if (!cache) return 1;
  const key = buildCacheKey_("rl_" + prefix, rawKey);
  const winSec = Math.max(60, Number(windowSeconds) || RL_WINDOW_SECONDS);
  let count = 1;
  let resetAt = Date.now() + winSec * 1000;
  const raw = cache.get(key);
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (!parsed.resetAt || Date.now() <= Number(parsed.resetAt)) {
        count = (Number(parsed.count) || 0) + 1;
        resetAt = Number(parsed.resetAt) || resetAt;
      }
    } catch (e) {}
  }
  const remainingSec = Math.max(10, Math.ceil((resetAt - Date.now()) / 1000));
  cache.put(key, JSON.stringify({ count: count, resetAt: resetAt }), Math.min(21600, remainingSec));
  return count;
}

function clearRateLimit_(prefix, rawKey) {
  const cache = getScriptCacheSafe_();
  if (!cache) return;
  cache.remove(buildCacheKey_("rl_" + prefix, rawKey));
}

function generateSixDigitOtp_() {
  const raw = Utilities.getUuid().replace(/-/g, "");
  const num = parseInt(raw.slice(0, 8), 16) % 900000;
  return String(100000 + num);
}

function hashOtpCode_(otp, salt) {
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, "otp:" + salt + ":" + otp);
  return bytesToHex_(digest);
}

// ============================================================================
// GENERATOR ID UNIK ANTI-TABRAKAN (UUID)
// ============================================================================

function generateUniqueEntityId_(existingRows, idField, prefix) {
  const existingSet = {};
  (existingRows || []).forEach(function (row) {
    const val = String(row[idField] || "").trim().toUpperCase();
    if (val) existingSet[val] = true;
  });

  for (let attempt = 0; attempt < 25; attempt++) {
    const token = Utilities.getUuid().replace(/-/g, "").slice(0, 8).toUpperCase();
    const candidate = prefix + "-" + token;
    if (!existingSet[candidate]) {
      return candidate;
    }
  }
  return prefix + "-" + Utilities.getUuid().replace(/-/g, "").slice(0, 12).toUpperCase();
}

function generateUniqueOrderId_(existingOrders) {
  const datePart = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyMMdd");
  const existingSet = {};
  (existingOrders || []).forEach(function (o) {
    existingSet[String(o.Order_ID || "").trim().toUpperCase()] = true;
  });

  for (let attempt = 0; attempt < 25; attempt++) {
    const suffix = Utilities.getUuid().replace(/-/g, "").slice(0, 6).toUpperCase();
    const candidate = "ORD-" + datePart + "-" + suffix;
    if (!existingSet[candidate]) {
      return candidate;
    }
  }
  return "ORD-" + datePart + "-" + Utilities.getUuid().replace(/-/g, "").slice(0, 10).toUpperCase();
}

function maskWaForTracking_(rawWa) {
  const norm = normalizeWa_(rawWa);
  if (!norm) return "-";
  if (norm.length <= 4) return norm;
  return "••••••" + norm.slice(-4);
}

function parseSheetNumber_(val) {
  if (typeof val === "number") return Number.isFinite(val) ? val : 0;
  const raw = String(val || "").trim();
  if (!raw) return 0;
  if (/^\d{1,3}(\.\d{3})+(,\d+)?$/.test(raw)) {
    const nId = Number(raw.replace(/\./g, "").replace(",", "."));
    return Number.isFinite(nId) ? nId : 0;
  }
  if (/^\d+(\.\d+)?$/.test(raw)) return Number(raw) || 0;
  let cleaned = raw.replace(/[^\d.,-]/g, "");
  if (/^\d{1,3}(\.\d{3})+(,\d+)?$/.test(cleaned)) {
    cleaned = cleaned.replace(/\./g, "").replace(",", ".");
  } else if (/^\d{1,3}(,\d{3})+(\.\d+)?$/.test(cleaned)) {
    cleaned = cleaned.replace(/,/g, "");
  } else {
    cleaned = cleaned.replace(",", ".");
  }
  const n = Number(cleaned);
  return Number.isFinite(n) ? n : 0;
}

function normalizeProductRow_(p) {
  const rawTipe = String(p.Tipe_Hitung || "").trim().toLowerCase();
  const rawStatus = String(p.Status || "").trim().toLowerCase();
  const minOrd = Math.floor(parseSheetNumber_(p.Min_Order));
  let status = "Tersedia";
  if (rawStatus === "habis") status = "Habis";
  else if (rawStatus === "arsip") status = "Arsip";

  return {
    Produk_ID: String(p.Produk_ID || "").trim(),
    Nama_Produk: String(p.Nama_Produk || "").trim(),
    Kategori: String(p.Kategori || "").trim() || "Umum",
    Tipe_Hitung: rawTipe === "dimensi" ? "Dimensi" : "Unit",
    Harga_Dasar: Math.max(0, Math.round(parseSheetNumber_(p.Harga_Dasar))),
    Satuan: String(p.Satuan || "").trim() || "Unit",
    Min_Order: minOrd >= 1 ? minOrd : 1,
    Status: status
  };
}

function normalizeFinishingRow_(f) {
  const rawTipe = String(f.Tipe_Biaya || "").trim().toLowerCase();
  const rawStatus = String(f.Status || "").trim().toLowerCase();
  return {
    Finishing_ID: String(f.Finishing_ID || "").trim(),
    Nama_Finishing: String(f.Nama_Finishing || "").trim(),
    Tipe_Biaya: rawTipe === "per_qty" || rawTipe === "per qty" ? "Per_Qty" : "Tetap",
    Tambahan_Harga: Math.max(0, Math.round(parseSheetNumber_(f.Tambahan_Harga))),
    Keterangan: String(f.Keterangan || "").trim(),
    Status: rawStatus === "arsip" ? "Arsip" : "Tersedia"
  };
}

// ============================================================================
// GOOGLE DRIVE, VALIDASI MAGIC BYTES, & AKSES SPREADSHEET
// ============================================================================

function getDatabaseFolder_() {
  if (DRIVE_FOLDER_ID) {
    try {
      return DriveApp.getFolderById(DRIVE_FOLDER_ID);
    } catch (err) {
      Logger.log("Folder ID tidak dapat diakses: " + err.message);
    }
  }
  return null;
}

function openNonTrashedSpreadsheet_(fileId) {
  const file = DriveApp.getFileById(fileId);
  if (file.isTrashed()) {
    throw new Error("Spreadsheet berada di Trash.");
  }
  return SpreadsheetApp.openById(fileId);
}

function getSpreadsheet_() {
  if (SPREADSHEET_ID && SPREADSHEET_ID !== "MASUKKAN_ID_SPREADSHEET_ANDA_DI_SINI") {
    return SpreadsheetApp.openById(SPREADSHEET_ID);
  }

  const props = PropertiesService.getScriptProperties();
  const forcedId = props.getProperty("FORCE_DB_SPREADSHEET_ID");
  if (forcedId) {
    try {
      return openNonTrashedSpreadsheet_(forcedId);
    } catch (e) {
      props.deleteProperty("FORCE_DB_SPREADSHEET_ID");
    }
  }

  const savedId = props.getProperty("DB_SPREADSHEET_ID");
  if (savedId) {
    try {
      return openNonTrashedSpreadsheet_(savedId);
    } catch (e) {
      props.deleteProperty("DB_SPREADSHEET_ID");
    }
  }

  const dbFolder = getDatabaseFolder_();
  if (dbFolder) {
    const namedSheets = dbFolder.getFilesByName(DATABASE_FILE_NAME);
    while (namedSheets.hasNext()) {
      const f = namedSheets.next();
      if (!f.isTrashed() && f.getMimeType() === MimeType.GOOGLE_SHEETS) {
        props.setProperty("DB_SPREADSHEET_ID", f.getId());
        return SpreadsheetApp.openById(f.getId());
      }
    }

    const sheetsInFolder = dbFolder.getFilesByType(MimeType.GOOGLE_SHEETS);
    while (sheetsInFolder.hasNext()) {
      const existingFile = sheetsInFolder.next();
      if (!existingFile.isTrashed()) {
        props.setProperty("DB_SPREADSHEET_ID", existingFile.getId());
        return SpreadsheetApp.openById(existingFile.getId());
      }
    }
  }

  const active = SpreadsheetApp.getActiveSpreadsheet();
  if (active) {
    return active;
  }

  throw new Error("Spreadsheet database tidak ditemukan. Jalankan setupDatabaseSheets() di Apps Script.");
}

function getOrCreateUploadFolder_() {
  const dbFolder = getDatabaseFolder_();
  if (dbFolder) {
    const subFolders = dbFolder.getFoldersByName(DRIVE_FOLDER_NAME);
    if (subFolders.hasNext()) {
      return subFolders.next();
    }
    return dbFolder.createFolder(DRIVE_FOLDER_NAME);
  }
  const folders = DriveApp.getFoldersByName(DRIVE_FOLDER_NAME);
  if (folders.hasNext()) {
    return folders.next();
  }
  return DriveApp.createFolder(DRIVE_FOLDER_NAME);
}

function validateMagicBytes_(decodedBytes, kind) {
  if (!decodedBytes || decodedBytes.length < 4) return false;
  const b = function (idx) {
    return idx < decodedBytes.length ? (decodedBytes[idx] & 0xff) : -1;
  };

  if (kind === "jpeg") {
    return b(0) === 0xff && b(1) === 0xd8 && b(2) === 0xff;
  }
  if (kind === "png") {
    return decodedBytes.length >= 8 &&
      b(0) === 0x89 && b(1) === 0x50 && b(2) === 0x4e && b(3) === 0x47 &&
      b(4) === 0x0d && b(5) === 0x0a && b(6) === 0x1a && b(7) === 0x0a;
  }
  if (kind === "webp") {
    return decodedBytes.length >= 12 &&
      b(0) === 0x52 && b(1) === 0x49 && b(2) === 0x46 && b(3) === 0x46 && // RIFF
      b(8) === 0x57 && b(9) === 0x45 && b(10) === 0x42 && b(11) === 0x50; // WEBP
  }
  if (kind === "pdf") {
    return decodedBytes.length >= 5 &&
      b(0) === 0x25 && b(1) === 0x50 && b(2) === 0x44 && b(3) === 0x46 && b(4) === 0x2d; // %PDF-
  }
  if (kind === "zip") {
    return b(0) === 0x50 && b(1) === 0x4b && (
      (b(2) === 0x03 && b(3) === 0x04) ||
      (b(2) === 0x05 && b(3) === 0x06) ||
      (b(2) === 0x07 && b(3) === 0x08)
    );
  }
  if (kind === "postscript") {
    const isPs = b(0) === 0x25 && b(1) === 0x21 && b(2) === 0x50 && b(3) === 0x53; // %!PS
    const isPdfAi = decodedBytes.length >= 5 &&
      b(0) === 0x25 && b(1) === 0x50 && b(2) === 0x44 && b(3) === 0x46 && b(4) === 0x2d; // %PDF-
    return isPs || isPdfAi;
  }
  return false;
}

/**
 * Menyimpan string Base64 (Data URL) ke Google Drive secara PRIVAT
 * dengan validasi batas tepat 2,5 MB, allowlist MIME, dan pemeriksaan magic bytes.
 */
function saveBase64ToDrive_(base64Data, fileNamePrefix, originalName, options) {
  if (!base64Data || typeof base64Data !== "string") return "";
  if (!base64Data.startsWith("data:")) {
    const safeText = String(base64Data).trim().slice(0, 150);
    if (/^(javascript:|vbscript:|data:)/i.test(safeText)) {
      throw new Error("Format nama file tidak valid.");
    }
    return safeText;
  }

  const parts = base64Data.split(",");
  if (parts.length < 2) {
    throw new Error("Format data lampiran tidak valid.");
  }
  const header = parts[0];
  const encoded = parts[1];
  const mimeMatch = header.match(/^data:([^;]+);base64$/i);
  if (!mimeMatch) {
    throw new Error("Header tipe file Base64 tidak valid.");
  }

  const rawMime = String(mimeMatch[1] || "").trim().toLowerCase();
  const mimeInfo = ALLOWED_UPLOAD_MIME_MAP[rawMime];
  if (!mimeInfo) {
    throw new Error("Tipe file tidak diizinkan (" + rawMime + "). Gunakan JPG, PNG, WEBP, PDF, ZIP, atau AI/EPS.");
  }
  if (options && options.imagesOnly && ["jpeg", "png", "webp"].indexOf(mimeInfo.kind) === -1) {
    throw new Error("Bukti pembayaran harus berupa gambar JPG, PNG, atau WEBP.");
  }

  const decodedBytes = Utilities.base64Decode(encoded);
  if (!decodedBytes || decodedBytes.length === 0) {
    throw new Error("File lampiran kosong atau rusak.");
  }
  if (decodedBytes.length > MAX_UPLOAD_BYTES) {
    throw new Error("Ukuran file melebihi batas server (maks. 2,5 MB).");
  }
  if (!validateMagicBytes_(decodedBytes, mimeInfo.kind)) {
    throw new Error("Isi file tidak sesuai dengan tipe " + mimeInfo.canonical + " (validasi signature gagal).");
  }

  const baseOrig = String(originalName || "upload_file")
    .replace(/\.[^.]+$/, "")
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .slice(0, 70) || "upload_file";
  const safeName = (fileNamePrefix ? fileNamePrefix + "_" : "") + baseOrig + mimeInfo.ext;
  const blob = Utilities.newBlob(decodedBytes, mimeInfo.canonical, safeName);

  const folder = getOrCreateUploadFolder_();
  const file = folder.createFile(blob);
  return file.getUrl();
}

function normalizeWa_(val) {
  const raw = String(val || "").replace(/^'/, "").replace(/\D/g, "");
  if (!raw) return "";
  if (raw.startsWith("0")) return "62" + raw.slice(1);
  if (raw.startsWith("8")) return "62" + raw;
  return raw;
}

function sheetToObjects_(ss, sheetName) {
  const sheet = ss.getSheetByName(sheetName);
  if (!sheet) return [];
  const values = sheet.getDataRange().getValues();
  if (values.length < 2) return [];

  const headers = values[0].map(function (h) {
    return String(h).trim();
  });

  const rows = [];
  for (let i = 1; i < values.length; i++) {
    const row = values[i];
    const isEmpty = row.every(function (cell) {
      return cell === "" || cell === null || cell === undefined;
    });
    if (isEmpty) continue;

    const obj = {};
    for (let j = 0; j < headers.length; j++) {
      if (!headers[j]) continue;
      let val = row[j];
      if (val instanceof Date) {
        val = Utilities.formatDate(val, Session.getScriptTimeZone(), "yyyy-MM-dd HH:mm");
      }
      obj[headers[j]] = val;
    }
    rows.push(obj);
  }
  return rows;
}

function ensureSheetColumns_(ss, sheetName, requiredColumns) {
  const sheet = ss.getSheetByName(sheetName);
  if (!sheet || sheet.getLastRow() === 0) return;
  const lastCol = Math.max(sheet.getLastColumn(), 1);
  const currentHeaders = sheet.getRange(1, 1, 1, lastCol).getValues()[0].map(function (h) {
    return String(h).trim();
  });
  requiredColumns.forEach(function (colName) {
    if (currentHeaders.indexOf(colName) === -1) {
      const nextCol = sheet.getLastColumn() + 1;
      const cell = sheet.getRange(1, nextCol);
      cell.setValue(colName);
      cell.setFontWeight("bold");
      cell.setBackground("#F1F5F9");
      currentHeaders.push(colName);
    }
  });
}

function appendObjectRow_(ss, sheetName, dataObj) {
  const sheet = ss.getSheetByName(sheetName);
  if (!sheet) throw new Error("Sheet '" + sheetName + "' tidak ditemukan.");
  const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0].map(function (h) {
    return String(h).trim();
  });
  const rowValues = headers.map(function (header) {
    return dataObj.hasOwnProperty(header) ? dataObj[header] : "";
  });
  sheet.appendRow(rowValues);
}

function updateUserFields_(ss, userId, updatesObj) {
  ensureSheetColumns_(ss, "Users", ["Status_Akun", "Token_Version"]);
  const sheet = ss.getSheetByName("Users");
  if (!sheet) return false;
  const values = sheet.getDataRange().getValues();
  if (values.length < 2) return false;
  const headers = values[0].map(function (h) { return String(h).trim(); });
  const colId = headers.indexOf("User_ID");
  if (colId === -1) return false;

  for (let r = 1; r < values.length; r++) {
    if (String(values[r][colId]).trim() === String(userId).trim()) {
      Object.keys(updatesObj).forEach(function (key) {
        const colIdx = headers.indexOf(key);
        if (colIdx !== -1) {
          sheet.getRange(r + 1, colIdx + 1).setValue(updatesObj[key]);
        }
      });
      return true;
    }
  }
  return false;
}

function updateUserPasswordCell_(ss, userId, hashedPassword) {
  return updateUserFields_(ss, userId, { Password: hashedPassword });
}

function migratePlaintextPasswords_(ss) {
  const sheet = ss.getSheetByName("Users");
  if (!sheet) return 0;
  const values = sheet.getDataRange().getValues();
  if (values.length < 2) return 0;
  const headers = values[0].map(function (h) { return String(h).trim(); });
  const colPass = headers.indexOf("Password");
  if (colPass === -1) return 0;

  let upgradedCount = 0;
  for (let r = 1; r < values.length; r++) {
    const rawPass = String(values[r][colPass] || "").trim();
    if (rawPass && !isHashedPassword_(rawPass)) {
      sheet.getRange(r + 1, colPass + 1).setValue(hashPassword_(rawPass));
      upgradedCount++;
    }
  }
  return upgradedCount;
}

function jsonResponse_(payload) {
  return ContentService
    .createTextOutput(JSON.stringify(payload))
    .setMimeType(ContentService.MimeType.JSON);
}

function assertRequiredSheetsPresent_(ss, requiredList) {
  const missing = [];
  (requiredList || Object.keys(SCHEMA_HEADERS)).forEach(function (name) {
    if (!ss.getSheetByName(name)) missing.push(name);
  });
  if (missing.length > 0) {
    throw new Error(
      "Tab database belum lengkap (" + missing.join(", ") + "). Jalankan fungsi setupDatabaseSheets() secara manual di Google Apps Script."
    );
  }
}

// ============================================================================
// INISIALISASI 5 TAB SHEET & BOOTSTRAP AMAN (OWNER-ONLY, TANPA DEFAULT PASS)
// ============================================================================

function ensureSheetsInitialized_(ss) {
  const createdSheets = [];
  const initializedHeaders = [];

  Object.keys(SCHEMA_HEADERS).forEach(function (sheetName) {
    const expectedHeaders = SCHEMA_HEADERS[sheetName];
    let sheet = ss.getSheetByName(sheetName);
    let isNewSheet = false;

    if (!sheet) {
      sheet = ss.insertSheet(sheetName);
      createdSheets.push(sheetName);
      isNewSheet = true;
    }

    const lastRow = sheet.getLastRow();
    const lastCol = sheet.getLastColumn();
    let headerEmpty = lastRow === 0 || lastCol === 0;

    if (!headerEmpty) {
      const firstRow = sheet.getRange(1, 1, 1, expectedHeaders.length).getValues()[0];
      headerEmpty = firstRow.every(function (cell) {
        return cell === "" || cell === null || cell === undefined;
      });
    }

    if (headerEmpty) {
      const headerRange = sheet.getRange(1, 1, 1, expectedHeaders.length);
      headerRange.setValues([expectedHeaders]);
      headerRange.setFontWeight("bold");
      headerRange.setBackground("#F1F5F9");
      sheet.setFrozenRows(1);
      initializedHeaders.push(sheetName);
    } else {
      const currentLastCol = Math.max(sheet.getLastColumn(), 1);
      const currentHeaders = sheet.getRange(1, 1, 1, currentLastCol).getValues()[0].map(function (h) {
        return String(h).trim();
      });
      expectedHeaders.forEach(function (expectedCol) {
        if (currentHeaders.indexOf(expectedCol) === -1) {
          const nextCol = sheet.getLastColumn() + 1;
          const cell = sheet.getRange(1, nextCol);
          cell.setValue(expectedCol);
          cell.setFontWeight("bold");
          cell.setBackground("#F1F5F9");
          currentHeaders.push(expectedCol);
          if (initializedHeaders.indexOf(sheetName) === -1) {
            initializedHeaders.push(sheetName);
          }
        }
      });
    }

    if (isNewSheet || sheet.getLastRow() <= 1) {
      if (sheetName === "Produk" && sheet.getLastRow() <= 1) {
        const seedProducts = [
          {
            Produk_ID: "PRD-001",
            Nama_Produk: "Spanduk Flexi China 280gr",
            Kategori: "Outdoor & Banner",
            Tipe_Hitung: "Dimensi",
            Harga_Dasar: 18000,
            Satuan: "m2",
            Min_Order: 1,
            Status: "Tersedia"
          },
          {
            Produk_ID: "PRD-002",
            Nama_Produk: "X-Banner Flexi Korea",
            Kategori: "Display & Stand",
            Tipe_Hitung: "Unit",
            Harga_Dasar: 85000,
            Satuan: "Set",
            Min_Order: 1,
            Status: "Tersedia"
          },
          {
            Produk_ID: "PRD-003",
            Nama_Produk: "Stiker Vinyl Camel",
            Kategori: "Stiker & Label",
            Tipe_Hitung: "Unit",
            Harga_Dasar: 12000,
            Satuan: "Lembar A3+",
            Min_Order: 5,
            Status: "Tersedia"
          },
          {
            Produk_ID: "PRD-004",
            Nama_Produk: "Kertas Concorde 220gr",
            Kategori: "Dokumen & Kartu",
            Tipe_Hitung: "Unit",
            Harga_Dasar: 5000,
            Satuan: "Lembar A3+",
            Min_Order: 10,
            Status: "Tersedia"
          }
        ];
        seedProducts.forEach(function (p) { appendObjectRow_(ss, "Produk", p); });
      }
      if (sheetName === "Finishing" && sheet.getLastRow() <= 1) {
        const seedFinishing = [
          {
            Finishing_ID: "FIN-000",
            Nama_Finishing: "Tanpa Finishing",
            Tipe_Biaya: "Tetap",
            Tambahan_Harga: 0,
            Keterangan: "Potong keliling standar",
            Status: "Tersedia"
          },
          {
            Finishing_ID: "FIN-001",
            Nama_Finishing: "Mata Ayam",
            Tipe_Biaya: "Per_Qty",
            Tambahan_Harga: 2000,
            Keterangan: "Lubang ring besi 4 sudut per pcs",
            Status: "Tersedia"
          },
          {
            Finishing_ID: "FIN-002",
            Nama_Finishing: "Laminasi",
            Tipe_Biaya: "Per_Qty",
            Tambahan_Harga: 3000,
            Keterangan: "Laminasi Doff / Glossy per pcs",
            Status: "Tersedia"
          },
          {
            Finishing_ID: "FIN-003",
            Nama_Finishing: "Cutting Pola",
            Tipe_Biaya: "Tetap",
            Tambahan_Harga: 4000,
            Keterangan: "Biaya potong pola khusus per item",
            Status: "Tersedia"
          }
        ];
        seedFinishing.forEach(function (f) { appendObjectRow_(ss, "Finishing", f); });
      }
    }
  });

  // Backfill nilai bawaan Status_Akun & Token_Version untuk baris Users lama yang kosong
  const usersSheet = ss.getSheetByName("Users");
  if (usersSheet && usersSheet.getLastRow() > 1) {
    const uVals = usersSheet.getDataRange().getValues();
    const uHeaders = uVals[0].map(function (h) { return String(h).trim(); });
    const colStatus = uHeaders.indexOf("Status_Akun");
    const colVer = uHeaders.indexOf("Token_Version");
    for (let r = 1; r < uVals.length; r++) {
      if (colStatus !== -1 && !String(uVals[r][colStatus] || "").trim()) {
        usersSheet.getRange(r + 1, colStatus + 1).setValue("Aktif");
      }
      if (colVer !== -1 && !String(uVals[r][colVer] || "").trim()) {
        usersSheet.getRange(r + 1, colVer + 1).setValue(1);
      }
    }
  }

  const defaultSheet1 = ss.getSheetByName("Sheet1");
  if (defaultSheet1 && ss.getSheets().length > 1 && defaultSheet1.getLastRow() <= 1) {
    try {
      ss.deleteSheet(defaultSheet1);
    } catch (delErr) {
      Logger.log("Info hapus Sheet1: " + delErr.message);
    }
  }

  return {
    createdSheets: createdSheets,
    initializedHeaders: initializedHeaders,
    spreadsheetId: ss.getId(),
    spreadsheetUrl: ss.getUrl()
  };
}

/**
 * Jalankan manual dari Editor Google Apps Script untuk menyiapkan 5 tab
 * sekaligus meng-hash seluruh password plaintext lama di sheet Users.
 */
function setupDatabaseSheets() {
  const ss = getSpreadsheet_();
  const result = ensureSheetsInitialized_(ss);
  const migrated = migratePlaintextPasswords_(ss);
  result.migratedPlaintextPasswords = migrated;
  Logger.log("Setup Database Selesai: " + JSON.stringify(result));
  return result;
}

/**
 * Jalankan manual 1x dari Editor Google Apps Script untuk:
 * 1. Memicu pop-up persetujuan izin kirim email (MailApp).
 * 2. Mengecek sisa kuota pengiriman email harian akun Google Anda.
 * 3. Mengirim email uji coba ke email pemilik script (atau parameter emailTujuan).
 * Setelah berhasil, lakukan Deploy > Manage deployments > Edit > New version.
 */
function aktifkanIzinEmailOtp(emailTujuan) {
  const target = String(emailTujuan || Session.getActiveUser().getEmail() || Session.getEffectiveUser().getEmail() || "").trim();
  const remainingQuota = MailApp.getRemainingDailyQuota();
  Logger.log("Sisa kuota email harian MailApp: " + remainingQuota);

  if (!target || target.indexOf("@") === -1) {
    throw new Error("Email tujuan tidak terdeteksi otomatis. Jalankan dengan parameter, contoh: aktifkanIzinEmailOtp('emailanda@gmail.com')");
  }
  if (remainingQuota <= 0) {
    throw new Error("Kuota pengiriman email harian MailApp sudah habis (0 tersisa). Tunggu reset harian Google atau gunakan akun Workspace.");
  }

  MailApp.sendEmail({
    to: target,
    name: "Wajibku Fast",
    subject: "[Wajibku Fast] Uji Coba Pengiriman Email OTP Berhasil",
    body:
      "Halo,\n\n" +
      "Pengiriman email OTP Wajibku Fast sudah aktif dan siap digunakan.\n" +
      "Sisa kuota email harian saat ini: " + Math.max(0, remainingQuota - 1) + " email.\n\n" +
      "Jangan lupa lakukan Deploy > Manage deployments > Edit > Version: New version agar perubahan aktif di website.\n\n" +
      "Salam,\nSistem Wajibku Fast"
  });

  const info = {
    status: "ok",
    sentTo: target,
    remainingQuotaAfterTest: Math.max(0, remainingQuota - 1)
  };
  Logger.log("Uji coba email OTP berhasil: " + JSON.stringify(info));
  return info;
}

/**
 * Jalankan manual dari Editor Apps Script untuk membuat akun Super Admin pertama.
 * Wajib menyertakan email dan customPassword kuat minimal 10 karakter.
 */
function bootstrapSuperAdmin(email, customPassword) {
  const cleanEmail = String(email || "").trim().toLowerCase();
  const cleanPass = String(customPassword || "").trim();
  if (!cleanEmail || cleanEmail.indexOf("@") === -1) {
    throw new Error("Email Super Admin yang valid wajib diisi.");
  }
  if (cleanPass.length < MIN_BOOTSTRAP_PASSWORD_LENGTH) {
    throw new Error("Kata sandi Super Admin minimal " + MIN_BOOTSTRAP_PASSWORD_LENGTH + " karakter.");
  }

  const ss = getSpreadsheet_();
  ensureSheetsInitialized_(ss);
  const users = sheetToObjects_(ss, "Users");
  const existingSuper = users.find(function (u) {
    return normalizeRole_(u.Role) === "Super Admin";
  });
  if (existingSuper) {
    throw new Error("Akun Super Admin sudah ada (" + existingSuper.User_ID + "). Gunakan resetSuperAdminAccess(customPassword) untuk reset darurat.");
  }

  appendObjectRow_(ss, "Users", {
    User_ID: "SUP-001",
    Nama: "Super Admin Wajibku Fast",
    No_WA: "'6281100009999",
    Email: cleanEmail,
    Role: "Super Admin",
    Alamat: "Kantor Pusat",
    Password: hashPassword_(cleanPass),
    Status_Akun: "Aktif",
    Token_Version: 1
  });
  Logger.log("Bootstrap Super Admin berhasil -> User_ID: SUP-001 | Email: " + cleanEmail);
  return { userId: "SUP-001", email: cleanEmail };
}

/**
 * Jalankan manual dari Editor Apps Script untuk reset darurat kata sandi Super Admin.
 * Tidak memiliki kata sandi default dan tidak pernah menulis kata sandi ke Logger.
 */
function resetSuperAdminAccess(customPassword) {
  const cleanPass = String(customPassword || "").trim();
  if (cleanPass.length < MIN_BOOTSTRAP_PASSWORD_LENGTH) {
    throw new Error(
      "Wajib mengisi parameter customPassword minimal " + MIN_BOOTSTRAP_PASSWORD_LENGTH + " karakter. Contoh: resetSuperAdminAccess('SandiBaruKuat!2026')"
    );
  }

  const ss = getSpreadsheet_();
  ensureSheetsInitialized_(ss);
  const users = sheetToObjects_(ss, "Users");
  const superAdmin = users.find(function (u) {
    return String(u.User_ID || "").trim().toUpperCase() === "SUP-001";
  }) || users.find(function (u) {
    return normalizeRole_(u.Role) === "Super Admin";
  });

  if (!superAdmin) {
    throw new Error("Akun Super Admin tidak ditemukan. Jalankan bootstrapSuperAdmin(email, customPassword) terlebih dahulu.");
  }

  const nextVer = normalizeTokenVersion_(superAdmin.Token_Version) + 1;
  updateUserFields_(ss, superAdmin.User_ID, {
    Password: hashPassword_(cleanPass),
    Status_Akun: "Aktif",
    Token_Version: nextVer
  });
  Logger.log("Reset akses Super Admin berhasil -> User_ID: " + superAdmin.User_ID + " | Email: " + superAdmin.Email);
  return {
    userId: superAdmin.User_ID,
    email: superAdmin.Email,
    tokenVersion: nextVer
  };
}

function migratePasswordsToHash() {
  const ss = getSpreadsheet_();
  const migrated = migratePlaintextPasswords_(ss);
  Logger.log("Password plaintext yang di-hash: " + migrated);
  return migrated;
}

function buatDatabaseBaru_(actorUser) {
  const dbFolder = getDatabaseFolder_();
  const newSs = SpreadsheetApp.create(DATABASE_FILE_NAME);
  if (dbFolder) {
    const newFile = DriveApp.getFileById(newSs.getId());
    newFile.moveTo(dbFolder);
  }
  const props = PropertiesService.getScriptProperties();
  props.setProperty("FORCE_DB_SPREADSHEET_ID", newSs.getId());
  props.setProperty("DB_SPREADSHEET_ID", newSs.getId());
  const initResult = ensureSheetsInitialized_(newSs);

  // Salin akun Super Admin pembuat agar tidak terkunci dari database baru
  if (actorUser && actorUser.User_ID) {
    appendObjectRow_(newSs, "Users", {
      User_ID: String(actorUser.User_ID),
      Nama: String(actorUser.Nama || "Super Admin"),
      No_WA: "'" + normalizeWa_(actorUser.No_WA),
      Email: String(actorUser.Email || "").trim().toLowerCase(),
      Role: "Super Admin",
      Alamat: String(actorUser.Alamat || ""),
      Password: String(actorUser.Password || ""),
      Status_Akun: "Aktif",
      Token_Version: normalizeTokenVersion_(actorUser.Token_Version)
    });
  }

  Logger.log("Database Baru Dibuat: " + newSs.getUrl());
  return initResult;
}

// ============================================================================
// HTTP GET (HANYA DATA KATALOG PUBLIK AKTIF: Produk & Finishing)
// ============================================================================

function doGet(e) {
  try {
    const action = (e && e.parameter && e.parameter.action) ? e.parameter.action : "getInitData";

    if (action === "getInitData") {
      const ss = getSpreadsheet_();
      assertRequiredSheetsPresent_(ss, ["Produk", "Finishing"]);
      // Hanya kirim katalog publik yang tidak diarsipkan; JANGAN kirim driveFolderUrl, Users, atau Pesanan
      const publicProduk = sheetToObjects_(ss, "Produk")
        .map(normalizeProductRow_)
        .filter(function (p) { return Boolean(p.Produk_ID) && p.Status !== "Arsip"; });
      const publicFinishing = sheetToObjects_(ss, "Finishing")
        .map(normalizeFinishingRow_)
        .filter(function (f) { return Boolean(f.Finishing_ID) && f.Status !== "Arsip"; });

      return jsonResponse_({
        status: "success",
        data: {
          produk: publicProduk,
          finishing: publicFinishing,
          memberProgram: publicProgramInfo_(getSystemSettings_(ss))
        },
        meta: {
          statusOrderList: PUBLIC_ORDER_STEPS,
          statusPayList: ALLOWED_PAY_STATUS,
          maxUploadBytes: MAX_UPLOAD_BYTES
        }
      });
    }

    return jsonResponse_({ status: "error", message: "Action GET tidak diizinkan atau tidak dikenal." });
  } catch (err) {
    return jsonResponse_({ status: "error", message: err.message });
  }
}

// ============================================================================
// HTTP POST (AUTENTIKASI, OTP, PELANGGAN, & OPERASI ADMIN TERPROTEKSI)
// ============================================================================

const READ_ONLY_POST_ACTIONS_ = {
  login: true,
  getMyOrders: true,
  adminGetData: true,
  getMemberDashboard: true,
  adminGetMemberData: true,
  adminGetFinancialReport: true,
  trackOrder: true
};

function buildAdminBundle_(ss, role) {
  const users = sheetToObjects_(ss, "Users").map(sanitizeUser_);
  return {
    data: {
      users: users,
      produk: sheetToObjects_(ss, "Produk").map(normalizeProductRow_).filter(function (p) { return Boolean(p.Produk_ID); }),
      finishing: sheetToObjects_(ss, "Finishing").map(normalizeFinishingRow_).filter(function (f) { return Boolean(f.Finishing_ID); }),
      pesanan: sheetToObjects_(ss, "Pesanan"),
      detail_pesanan: sheetToObjects_(ss, "Detail_Pesanan")
    },
    meta: {
      spreadsheetUrl: ss.getUrl(),
      role: role,
      statusOrderList: ALLOWED_ORDER_STATUS,
      statusPayList: ALLOWED_PAY_STATUS,
      maxUploadBytes: MAX_UPLOAD_BYTES
    }
  };
}

function buildMyOrdersBundle_(ss, userObj) {
  const uid = String(userObj.User_ID || "").trim();
  const myOrders = sheetToObjects_(ss, "Pesanan")
    .filter(function (o) {
      return String(o.User_ID || "").trim() === uid &&
        String(o.Status_Order || "").trim() !== "Diarsipkan";
    })
    .map(function (o) {
      return {
        Order_ID: o.Order_ID,
        Tanggal: o.Tanggal,
        User_ID: o.User_ID,
        Status_Order: o.Status_Order,
        Total_Tagihan: o.Total_Tagihan,
        Bukti_Bayar: o.Bukti_Bayar ? "Sudah diunggah" : "",
        Status_Bayar: o.Status_Bayar,
        Catatan: o.Catatan,
        Saldo_Dipakai: Number(o.Saldo_Dipakai) || 0,
        Reward_Amount: Number(o.Reward_Amount) || 0,
        Reward_Status: o.Reward_Status || ""
      };
    });

  const myOrderIds = {};
  myOrders.forEach(function (o) {
    myOrderIds[String(o.Order_ID || "").trim()] = true;
  });
  const myDetails = sheetToObjects_(ss, "Detail_Pesanan")
    .filter(function (d) {
      return Boolean(myOrderIds[String(d.Order_ID || "").trim()]);
    })
    .map(function (d) {
      return {
        Detail_ID: d.Detail_ID,
        Order_ID: d.Order_ID,
        Produk_ID: d.Produk_ID,
        Panjang_m: d.Panjang_m,
        Lebar_m: d.Lebar_m,
        Qty: d.Qty,
        Finishing_ID: d.Finishing_ID,
        File_Desain: d.File_Desain ? "File terlampir" : "",
        Keterangan_Item: d.Keterangan_Item,
        Subtotal: d.Subtotal
      };
    });

  return {
    user: sanitizeUser_(userObj),
    pesanan: myOrders,
    detail_pesanan: myDetails
  };
}

function doPost(e) {
  const lock = LockService.getScriptLock();
  let hasLock = false;
  try {
    const body = JSON.parse(e.postData.contents);
    const action = body.action;
    if (!READ_ONLY_POST_ACTIONS_[action]) {
      lock.waitLock(15000);
      hasLock = true;
    }
    const ss = getSpreadsheet_();

    // ------------------------------------------------------------------------
    // 1. LOGIN SERVER-SIDE -> Rate Limit + Status_Akun + PBKDF2 + Single-Roundtrip Bootstrap
    // ------------------------------------------------------------------------
    if (action === "login") {
      assertRequiredSheetsPresent_(ss, ["Users"]);
      const identifierRaw = String(body.identifier || "").trim();
      const identifier = identifierRaw.toLowerCase();
      const normIdentifierWa = normalizeWa_(identifierRaw);
      const password = String(body.password || "");

      if (!identifier || !password) {
        return jsonResponse_({ status: "error", message: "Email/WhatsApp dan kata sandi wajib diisi." });
      }

      const rlKey = normIdentifierWa || identifier;
      const rlCheck = checkRateLimit_("login", rlKey, RL_LOGIN_MAX);
      if (rlCheck.blocked) {
        return jsonResponse_({
          status: "error",
          message: "Terlalu banyak percobaan login gagal. Coba lagi dalam 15 menit."
        });
      }

      const users = sheetToObjects_(ss, "Users");
      const matched = users.find(function (u) {
        const uEmail = String(u.Email || "").trim().toLowerCase();
        const uWa = normalizeWa_(u.No_WA);
        const uId = String(u.User_ID || "").trim().toLowerCase();
        return (uEmail && uEmail === identifier) ||
          (normIdentifierWa && uWa && uWa === normIdentifierWa) ||
          (uId && uId === identifier);
      });

      if (!matched) {
        recordRateLimitAttempt_("login", rlKey, RL_WINDOW_SECONDS);
        return jsonResponse_({ status: "error", message: "Email/No. WhatsApp atau kata sandi salah." });
      }

      if (normalizeAccountStatus_(matched.Status_Akun) !== "Aktif") {
        recordRateLimitAttempt_("login", rlKey, RL_WINDOW_SECONDS);
        return jsonResponse_({
          status: "error",
          message: "Akun Anda sedang dinonaktifkan. Silakan hubungi pengelola."
        });
      }

      const storedPass = String(matched.Password || "").trim();
      if (!storedPass) {
        recordRateLimitAttempt_("login", rlKey, RL_WINDOW_SECONDS);
        return jsonResponse_({
          status: "error",
          message: "Akun checkout tamu ini belum memiliki kata sandi. Silakan daftar member baru atau hubungi Admin."
        });
      }

      const passCheck = verifyPassword_(password, storedPass);
      if (!passCheck.valid) {
        recordRateLimitAttempt_("login", rlKey, RL_WINDOW_SECONDS);
        return jsonResponse_({ status: "error", message: "Email/No. WhatsApp atau kata sandi salah." });
      }

      clearRateLimit_("login", rlKey);
      if (passCheck.needsUpgrade) {
        lock.waitLock(15000);
        hasLock = true;
        updateUserFields_(ss, matched.User_ID, { Password: hashPassword_(password) });
      }

      const token = createToken_(matched);
      const safeUser = sanitizeUser_(matched);
      const loginData = {
        token: token,
        user: safeUser
      };

      // Percepatan login: sertakan data awal sesuai role dalam 1 kali respons server
      if (body.includeBootstrap !== false) {
        try {
          const roleNorm = normalizeRole_(matched.Role);
          if (roleNorm === "Admin" || roleNorm === "Super Admin") {
            const adminBundle = buildAdminBundle_(ss, roleNorm);
            loginData.adminData = adminBundle.data;
            loginData.adminMeta = adminBundle.meta;
          } else if (!isGuestUserId_(matched.User_ID)) {
            loginData.myOrders = buildMyOrdersBundle_(ss, matched);
            if (ss.getSheetByName("Wallet_Accounts") && ss.getSheetByName("Wallet_Transactions")) {
              const memDash = handleGetMemberDashboard_(ss, { user: matched });
              if (memDash && memDash.status === "success" && memDash.data) {
                loginData.memberDashboard = memDash.data;
              }
            }
          }
        } catch (bootErr) {
          // Abaikan error bootstrap parsial; klien akan fallback ke pemanggilan standar
        }
      }

      return jsonResponse_({
        status: "success",
        message: "Login berhasil.",
        data: loginData
      });
    }

    // ------------------------------------------------------------------------
    // 1B. LOGOUT SERVER-SIDE -> Cabut Sesi Dengan Menaikkan Token_Version
    // ------------------------------------------------------------------------
    if (action === "logout") {
      assertRequiredSheetsPresent_(ss, ["Users"]);
      const auth = requireRole_(ss, body, ["User", "Admin", "Super Admin"]);
      const nextVer = normalizeTokenVersion_(auth.user.Token_Version) + 1;
      updateUserFields_(ss, auth.user.User_ID, { Token_Version: nextVer });
      return jsonResponse_({
        status: "success",
        message: "Sesi berhasil diakhiri dan dicabut."
      });
    }

    // ------------------------------------------------------------------------
    // 2. REGISTER MEMBER (Role: "User", Min 8 Karakter, UUID Anti-Tabrakan)
    // ------------------------------------------------------------------------
    if (action === "registerMember") {
      assertRequiredSheetsPresent_(ss, ["Users"]);
      ensureSheetColumns_(ss, "Users", ["Status_Akun", "Token_Version"]);
      const usr = body.user || body;
      const nama = String(usr.Nama || "").trim();
      const email = String(usr.Email || "").trim().toLowerCase();
      const normWa = normalizeWa_(usr.No_WA);
      const password = String(usr.Password || "");
      const alamat = String(usr.Alamat || "").trim();

      if (!nama || !email || email.indexOf("@") === -1 || !normWa || normWa.length < 10) {
        return jsonResponse_({
          status: "error",
          message: "Nama lengkap, Nomor WhatsApp valid, dan Email aktif wajib diisi."
        });
      }
      if (password.length < MIN_PASSWORD_LENGTH) {
        return jsonResponse_({
          status: "error",
          message: "Kata sandi minimal " + MIN_PASSWORD_LENGTH + " karakter."
        });
      }

      const existingUsers = sheetToObjects_(ss, "Users");
      const duplicate = existingUsers.find(function (u) {
        // Abaikan baris GUEST- (checkout tamu terisolasi) agar member tetap bisa mendaftar
        if (String(u.User_ID || "").trim().toUpperCase().startsWith("GUEST-")) return false;
        const uEmail = String(u.Email || "").trim().toLowerCase();
        const uNormWa = normalizeWa_(u.No_WA);
        return (uEmail && uEmail === email) || (uNormWa && uNormWa === normWa);
      });

      if (duplicate) {
        return jsonResponse_({
          status: "error",
          message: "Email atau Nomor WhatsApp sudah terdaftar. Silakan masuk atau gunakan Lupa Sandi."
        });
      }

      const newUserId = generateUniqueEntityId_(existingUsers, "User_ID", "USR");
      const newMember = {
        User_ID: newUserId,
        Nama: nama,
        No_WA: "'" + normWa,
        Email: email,
        Role: "User",
        Alamat: alamat,
        Password: hashPassword_(password),
        Status_Akun: "Aktif",
        Token_Version: 1
      };

      appendObjectRow_(ss, "Users", newMember);
      const safeMember = sanitizeUser_(newMember);
      const token = createToken_(safeMember);
      return jsonResponse_({
        status: "success",
        message: "Pendaftaran member berhasil!",
        data: {
          token: token,
          user: safeMember
        }
      });
    }

    // ------------------------------------------------------------------------
    // 2B. LUPA SANDI PELANGGAN 2 LANGKAH (OTP 6 DIGIT VIA MAILAPP)
    // ------------------------------------------------------------------------
    if (action === "forgotPassword") {
      return jsonResponse_({
        status: "error",
        message: "Alur reset sandi langsung dinonaktifkan. Gunakan verifikasi kode OTP email."
      });
    }

    if (action === "requestPasswordResetOtp") {
      assertRequiredSheetsPresent_(ss, ["Users"]);
      const email = String(body.email || body.Email || "").trim().toLowerCase();
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return jsonResponse_({
          status: "error",
          message: "Masukkan alamat email yang valid."
        });
      }

      const rlCheck = checkRateLimit_("otp_req", email, RL_OTP_MAX);
      if (rlCheck.blocked) {
        return jsonResponse_({
          status: "error",
          message: "Terlalu banyak permintaan kode OTP untuk email ini. Coba lagi dalam 15 menit."
        });
      }
      recordRateLimitAttempt_("otp_req", email, RL_WINDOW_SECONDS);

      const neutralMessage = "Jika email terdaftar sebagai akun pelanggan aktif, kode OTP 6 digit telah dikirim ke kotak masuk Anda (berlaku 10 menit).";
      const existingUsers = sheetToObjects_(ss, "Users");
      const matched = existingUsers.find(function (u) {
        const uId = String(u.User_ID || "").trim().toUpperCase();
        if (uId.startsWith("GUEST-")) return false;
        const uEmail = String(u.Email || "").trim().toLowerCase();
        return Boolean(uEmail && uEmail === email);
      });

      // Hanya kirim OTP untuk akun Role === "User" yang Aktif (tanpa membocorkan status akun ke luar)
      if (matched && normalizeRole_(matched.Role) === "User" && normalizeAccountStatus_(matched.Status_Akun) === "Aktif") {
        const cache = getScriptCacheSafe_();
        if (!cache) {
          return jsonResponse_({
            status: "error",
            message: "Layanan cache OTP tidak tersedia sementara."
          });
        }

        const otpKey = buildCacheKey_("otp_code", email);
        const otpCode = generateSixDigitOtp_();
        const otpSalt = Utilities.getUuid().replace(/-/g, "").slice(0, 16);
        const otpPayload = {
          uid: String(matched.User_ID),
          salt: otpSalt,
          hash: hashOtpCode_(otpCode, otpSalt),
          exp: Date.now() + OTP_TTL_SECONDS * 1000,
          attempts: 0
        };
        cache.put(otpKey, JSON.stringify(otpPayload), OTP_TTL_SECONDS);

        const recipientName = String(matched.Nama || "Pelanggan").trim();
        const subject = "[Wajibku Fast] Kode OTP Reset Kata Sandi Anda";
        const mailBody =
          "Halo " + recipientName + ",\n\n" +
          "Kami menerima permintaan untuk mengatur ulang kata sandi akun Wajibku Fast Anda.\n\n" +
          "Kode OTP Anda: " + otpCode + "\n" +
          "Masa berlaku: 10 menit (maksimal 5 kali percobaan).\n\n" +
          "Jangan bagikan kode ini kepada siapa pun. Jika Anda tidak meminta reset kata sandi, abaikan email ini.\n\n" +
          "Salam,\nTim Wajibku Fast";

        try {
          if (typeof MailApp.getRemainingDailyQuota === "function" && MailApp.getRemainingDailyQuota() <= 0) {
            cache.remove(otpKey);
            return jsonResponse_({
              status: "error",
              message: "Kuota pengiriman email OTP harian server sedang habis. Silakan coba lagi besok atau hubungi admin."
            });
          }
          MailApp.sendEmail({
            to: email,
            name: "Wajibku Fast",
            subject: subject,
            body: mailBody
          });
        } catch (mailErr) {
          cache.remove(otpKey);
          Logger.log("Gagal mengirim email OTP ke " + email + ": " + (mailErr && mailErr.message ? mailErr.message : mailErr));
          const errMsg = String(mailErr && mailErr.message ? mailErr.message : mailErr || "");
          if (/permission|auth|scope|MailApp/i.test(errMsg)) {
            return jsonResponse_({
              status: "error",
              message: "Pengiriman email OTP belum diizinkan di server Apps Script. Pemilik sistem perlu menjalankan aktifkanIzinEmailOtp() di Editor Apps Script lalu Deploy versi baru."
            });
          }
          return jsonResponse_({
            status: "error",
            message: "Gagal mengirim email OTP sementara (" + errMsg + "). Silakan coba lagi atau hubungi admin."
          });
        }
      }

      return jsonResponse_({
        status: "success",
        message: neutralMessage,
        data: {
          ttlSeconds: OTP_TTL_SECONDS
        }
      });
    }

    if (action === "verifyPasswordResetOtp") {
      assertRequiredSheetsPresent_(ss, ["Users"]);
      const email = String(body.email || body.Email || "").trim().toLowerCase();
      const otpInput = String(body.otp || "").replace(/\D/g, "");
      const newPassword = String(body.newPassword || body.Password || "");

      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return jsonResponse_({ status: "error", message: "Alamat email tidak valid." });
      }
      if (!/^\d{6}$/.test(otpInput)) {
        return jsonResponse_({ status: "error", message: "Masukkan kode OTP 6 digit angka yang valid." });
      }
      if (newPassword.length < MIN_PASSWORD_LENGTH) {
        return jsonResponse_({
          status: "error",
          message: "Kata sandi baru minimal " + MIN_PASSWORD_LENGTH + " karakter."
        });
      }

      const cache = getScriptCacheSafe_();
      const otpKey = buildCacheKey_("otp_code", email);
      const rawOtp = cache ? cache.get(otpKey) : null;
      if (!rawOtp) {
        return jsonResponse_({
          status: "error",
          message: "Kode OTP tidak ditemukan atau sudah kedaluwarsa. Silakan kirim ulang kode OTP."
        });
      }

      let otpRecord = null;
      try {
        otpRecord = JSON.parse(rawOtp);
      } catch (e) {
        if (cache) cache.remove(otpKey);
        return jsonResponse_({ status: "error", message: "Kode OTP tidak valid. Silakan kirim ulang." });
      }

      if (!otpRecord || !otpRecord.exp || Date.now() > Number(otpRecord.exp)) {
        if (cache) cache.remove(otpKey);
        return jsonResponse_({
          status: "error",
          message: "Kode OTP sudah kedaluwarsa. Silakan minta kode OTP baru."
        });
      }

      const attempts = Number(otpRecord.attempts) || 0;
      if (attempts >= OTP_MAX_ATTEMPTS) {
        if (cache) cache.remove(otpKey);
        return jsonResponse_({
          status: "error",
          message: "Batas percobaan kode OTP tercapai. Silakan kirim ulang kode OTP baru."
        });
      }

      const expectedHash = hashOtpCode_(otpInput, otpRecord.salt);
      if (!constantTimeEqual_(expectedHash, otpRecord.hash)) {
        const nextAttempts = attempts + 1;
        if (nextAttempts >= OTP_MAX_ATTEMPTS) {
          if (cache) cache.remove(otpKey);
          return jsonResponse_({
            status: "error",
            message: "Kode OTP salah dan batas percobaan tercapai. Silakan minta kode OTP baru."
          });
        }
        otpRecord.attempts = nextAttempts;
        const remainingSec = Math.max(10, Math.ceil((Number(otpRecord.exp) - Date.now()) / 1000));
        if (cache) cache.put(otpKey, JSON.stringify(otpRecord), remainingSec);
        return jsonResponse_({
          status: "error",
          message: "Kode OTP tidak cocok. Sisa percobaan: " + (OTP_MAX_ATTEMPTS - nextAttempts) + "."
        });
      }

      const existingUsers = sheetToObjects_(ss, "Users");
      const matched = existingUsers.find(function (u) {
        return String(u.User_ID || "").trim() === String(otpRecord.uid).trim();
      });

      if (!matched || normalizeRole_(matched.Role) !== "User" || normalizeAccountStatus_(matched.Status_Akun) !== "Aktif") {
        if (cache) cache.remove(otpKey);
        return jsonResponse_({
          status: "error",
          message: "Akun pelanggan tidak dapat direset. Hubungi pengelola."
        });
      }

      const nextVer = normalizeTokenVersion_(matched.Token_Version) + 1;
      updateUserFields_(ss, matched.User_ID, {
        Password: hashPassword_(newPassword),
        Token_Version: nextVer
      });

      if (cache) cache.remove(otpKey);
      clearRateLimit_("login", email);
      if (matched.No_WA) clearRateLimit_("login", normalizeWa_(matched.No_WA));

      return jsonResponse_({
        status: "success",
        message: "Kata sandi berhasil diperbarui dan sesi lama telah dicabut. Silakan masuk dengan sandi baru."
      });
    }

    // ------------------------------------------------------------------------
    // 3. TRACK ORDER PUBLIK TERPROTEKSI (Rate Limit + Order_ID + 4 Digit WA)
    // ------------------------------------------------------------------------
    if (action === "trackOrder") {
      assertRequiredSheetsPresent_(ss, ["Pesanan", "Detail_Pesanan", "Users"]);
      const reqOrderId = String(body.orderId || "").trim().toUpperCase();
      const reqWaLast4 = String(body.waLast4 || "").replace(/\D/g, "");

      if (!reqOrderId || !/^\d{4}$/.test(reqWaLast4)) {
        return jsonResponse_({
          status: "error",
          message: "Masukkan ID Pesanan lengkap dan 4 digit terakhir Nomor WhatsApp."
        });
      }

      const rlCheck = checkRateLimit_("track", reqOrderId, RL_TRACK_MAX);
      if (rlCheck.blocked) {
        return jsonResponse_({
          status: "error",
          message: "Terlalu banyak percobaan pelacakan gagal untuk ID ini. Coba lagi dalam 15 menit."
        });
      }

      const allOrders = sheetToObjects_(ss, "Pesanan");
      const order = allOrders.find(function (o) {
        return String(o.Order_ID || "").trim().toUpperCase() === reqOrderId &&
          String(o.Status_Order || "").trim() !== "Diarsipkan";
      });
      if (!order) {
        recordRateLimitAttempt_("track", reqOrderId, RL_WINDOW_SECONDS);
        return jsonResponse_({
          status: "error",
          message: "Pesanan tidak ditemukan atau 4 digit terakhir WhatsApp tidak cocok."
        });
      }

      const allUsers = sheetToObjects_(ss, "Users");
      const owner = allUsers.find(function (u) {
        return String(u.User_ID || "").trim() === String(order.User_ID || "").trim();
      }) || {};
      const ownerWaNorm = normalizeWa_(owner.No_WA);

      if (!ownerWaNorm || ownerWaNorm.slice(-4) !== reqWaLast4) {
        recordRateLimitAttempt_("track", reqOrderId, RL_WINDOW_SECONDS);
        return jsonResponse_({
          status: "error",
          message: "Pesanan tidak ditemukan atau 4 digit terakhir WhatsApp tidak cocok."
        });
      }

      clearRateLimit_("track", reqOrderId);

      const allDetails = sheetToObjects_(ss, "Detail_Pesanan");
      const items = allDetails
        .filter(function (d) {
          return String(d.Order_ID || "").trim().toUpperCase() === reqOrderId;
        })
        .map(function (d) {
          return {
            Detail_ID: d.Detail_ID,
            Order_ID: d.Order_ID,
            Produk_ID: d.Produk_ID,
            Panjang_m: d.Panjang_m,
            Lebar_m: d.Lebar_m,
            Qty: d.Qty,
            Finishing_ID: d.Finishing_ID,
            File_Desain: d.File_Desain ? "File terlampir" : "",
            Keterangan_Item: d.Keterangan_Item,
            Subtotal: d.Subtotal
          };
        });

      return jsonResponse_({
        status: "success",
        data: {
          pesanan: {
            Order_ID: order.Order_ID,
            Tanggal: order.Tanggal,
            User_ID: order.User_ID,
            Status_Order: order.Status_Order,
            Total_Tagihan: order.Total_Tagihan,
            Bukti_Bayar: order.Bukti_Bayar ? "Sudah diunggah" : "",
            Status_Bayar: order.Status_Bayar,
            Catatan: order.Catatan
          },
          detail_pesanan: items,
          customer: {
            User_ID: owner.User_ID || order.User_ID,
            Nama: owner.Nama || "Pelanggan",
            No_WA: maskWaForTracking_(owner.No_WA)
          }
        }
      });
    }

    // ------------------------------------------------------------------------
    // 4. GET MY ORDERS (Riwayat Pesanan Member Login — URL Drive Diredaksi)
    // ------------------------------------------------------------------------
    if (action === "getMyOrders") {
      assertRequiredSheetsPresent_(ss, ["Users", "Pesanan", "Detail_Pesanan"]);
      const auth = requireRole_(ss, body, ["User", "Admin", "Super Admin"]);
      return jsonResponse_({
        status: "success",
        data: buildMyOrdersBundle_(ss, auth.user)
      });
    }

    // ------------------------------------------------------------------------
    // 5. ADMIN GET DATA (Terproteksi Admin / Super Admin, Tanpa Password)
    // ------------------------------------------------------------------------
    if (action === "adminGetData") {
      assertRequiredSheetsPresent_(ss, ["Users", "Produk", "Finishing", "Pesanan", "Detail_Pesanan"]);
      const auth = requireRole_(ss, body, ["Admin", "Super Admin"]);
      const bundle = buildAdminBundle_(ss, auth.role);
      return jsonResponse_({
        status: "success",
        data: bundle.data,
        meta: bundle.meta
      });
    }

    // ------------------------------------------------------------------------
    // 6. CREATE ORDER (Harga Server, Isolasi Tamu GUEST-, Validasi Upload Ketat)
    // ------------------------------------------------------------------------
    if (action === "createOrder") {
      assertRequiredSheetsPresent_(ss, ["Users", "Produk", "Finishing", "Pesanan", "Detail_Pesanan"]);
      ensureMemberSheets_(ss);
      const userPayload = body.user || {};
      const orderPayload = body.pesanan || {};
      const detailsPayload = Array.isArray(body.detail_pesanan) ? body.detail_pesanan : [];

      if (!detailsPayload.length) {
        return jsonResponse_({ status: "error", message: "Keranjang pesanan kosong." });
      }
      if (detailsPayload.length > 50) {
        return jsonResponse_({ status: "error", message: "Maksimal 50 item dalam satu pesanan." });
      }

      const namaPelanggan = String(userPayload.Nama || "").trim();
      const reqNormWa = normalizeWa_(userPayload.No_WA);
      const reqEmail = String(userPayload.Email || "").trim().toLowerCase();
      const reqAlamat = String(userPayload.Alamat || "").trim();

      if (!namaPelanggan || !reqNormWa || reqNormWa.length < 10) {
        return jsonResponse_({ status: "error", message: "Nama pelanggan dan Nomor WhatsApp valid wajib diisi." });
      }

      // Bangun lookup Produk & Finishing aktif dari database server (abaikan harga dari klien)
      const produkList = sheetToObjects_(ss, "Produk").map(normalizeProductRow_);
      const finishingList = sheetToObjects_(ss, "Finishing").map(normalizeFinishingRow_);
      const produkMap = {};
      produkList.forEach(function (p) { if (p.Produk_ID) produkMap[p.Produk_ID] = p; });
      const finishingMap = {};
      finishingList.forEach(function (f) { if (f.Finishing_ID) finishingMap[f.Finishing_ID] = f; });

      const rates = getSystemSettings_(ss);
      let serverTotal = 0;
      const computedItems = [];
      for (let i = 0; i < detailsPayload.length; i++) {
        const rawItem = detailsPayload[i] || {};
        const prodId = String(rawItem.Produk_ID || "").trim();
        const prod = produkMap[prodId];
        if (!prod || prod.Status !== "Tersedia") {
          return jsonResponse_({
            status: "error",
            message: "Produk tidak valid atau sedang tidak tersedia: " + (prodId || "-")
          });
        }

        const isDimensi = prod.Tipe_Hitung === "Dimensi";
        const panjang = isDimensi ? Number(rawItem.Panjang_m) : 0;
        const lebar = isDimensi ? Number(rawItem.Lebar_m) : 0;
        const qty = Math.floor(Number(rawItem.Qty));
        const minOrder = prod.Min_Order || 1;

        if (!Number.isFinite(qty) || qty < minOrder || qty > 100000) {
          return jsonResponse_({
            status: "error",
            message: "Qty untuk " + prod.Nama_Produk + " minimal " + minOrder + "."
          });
        }
        if (isDimensi && (!Number.isFinite(panjang) || !Number.isFinite(lebar) || panjang <= 0 || lebar <= 0 || panjang > 500 || lebar > 500)) {
          return jsonResponse_({
            status: "error",
            message: "Panjang dan lebar untuk " + prod.Nama_Produk + " harus lebih dari 0 meter."
          });
        }

        const finId = String(rawItem.Finishing_ID || "FIN-000").trim();
        const fin = finishingMap[finId] || finishingMap["FIN-000"] || null;
        if (finId && (!finishingMap[finId] || finishingMap[finId].Status === "Arsip") && finId !== "FIN-000") {
          return jsonResponse_({
            status: "error",
            message: "Opsi finishing tidak ditemukan atau tidak aktif: " + finId
          });
        }

        // Produk berukuran m² memakai tarif program saat aktif; jika nonaktif memakai Harga_Dasar produk.
        const hargaDasar = (isDimensi && rates.aktif && rates.hargaJualPerM2 > 0)
          ? rates.hargaJualPerM2
          : (Number(prod.Harga_Dasar) || 0);
        const baseCost = isDimensi
          ? Math.round(panjang * lebar * qty * hargaDasar)
          : Math.round(qty * hargaDasar);
        const finTambahan = fin ? (Number(fin.Tambahan_Harga) || 0) : 0;
        const finCost = (fin && fin.Tipe_Biaya === "Per_Qty") ? (finTambahan * qty) : finTambahan;
        const serverSubtotal = baseCost + finCost;

        serverTotal += serverSubtotal;
        computedItems.push({
          Produk_ID: prodId,
          Panjang_m: isDimensi ? panjang : 0,
          Lebar_m: isDimensi ? lebar : 0,
          Qty: qty,
          Finishing_ID: fin ? String(fin.Finishing_ID) : "FIN-000",
          File_Desain: rawItem.File_Desain || "",
          File_Desain_Base64: rawItem.File_Desain_Base64 || "",
          Keterangan_Item: String(rawItem.Keterangan_Item || "").slice(0, 500),
          Subtotal: serverSubtotal
        });
      }

      // Identifikasi Pemesan:
      // - Jika membawa token valid & aktif -> kaitkan ke User_ID terautentikasi.
      // - Jika checkout tamu (tanpa token valid) -> JANGAN pernah menempelkan ke akun member lain;
      //   buat record GUEST-<UUID> terisolasi agar riwayat getMyOrders milik member lain tidak tercemar.
      const existingUsers = sheetToObjects_(ss, "Users");
      let userId = "";
      let authenticatedUser = null;

      if (body.token) {
        const authSession = verifyToken_(String(body.token));
        if (authSession) {
          const live = existingUsers.find(function (u) {
            return String(u.User_ID || "").trim() === String(authSession.uid).trim();
          });
          if (
            live &&
            normalizeAccountStatus_(live.Status_Akun) === "Aktif" &&
            normalizeTokenVersion_(authSession.ver) === normalizeTokenVersion_(live.Token_Version)
          ) {
            authenticatedUser = live;
          }
        }
      }

      // Potongan saldo member: hanya akun terdaftar, dicek ulang terhadap saldo di server.
      const requestedSaldo = Math.floor(Number(orderPayload.Gunakan_Saldo) || 0);
      if (requestedSaldo < 0) {
        return jsonResponse_({ status: "error", message: "Nominal saldo yang digunakan tidak valid." });
      }
      if (requestedSaldo > 0) {
        if (!authenticatedUser || isGuestUserId_(authenticatedUser.User_ID)) {
          return jsonResponse_({ status: "error", message: "Masuk sebagai member untuk menggunakan saldo." });
        }
        if (requestedSaldo > serverTotal) {
          return jsonResponse_({ status: "error", message: "Saldo yang digunakan tidak boleh melebihi total tagihan." });
        }
        const walletNow = getWallet_(ss, authenticatedUser.User_ID);
        if (requestedSaldo > walletNow.available) {
          return jsonResponse_({ status: "error", message: "Saldo tersedia tidak mencukupi. Saldo tersedia: Rp " + formatIdrServer_(walletNow.available) + "." });
        }
      }
      const existingOrders = sheetToObjects_(ss, "Pesanan");
      const orderId = generateUniqueOrderId_(existingOrders);
      const tanggal = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyyy-MM-dd HH:mm");

      // Validasi & unggah seluruh lampiran SEBELUM menulis baris ke Sheet agar atomik bila ada file ditolak
      let buktiBayarUrl = "";
      if (orderPayload.Bukti_Bayar) {
        buktiBayarUrl = saveBase64ToDrive_(
          orderPayload.Bukti_Bayar,
          orderId + "_BUKTI",
          orderPayload.Bukti_Bayar_Name || "bukti_bayar.jpg",
          { imagesOnly: true }
        );
      }

      const uploadedDesignUrls = [];
      for (let i = 0; i < computedItems.length; i++) {
        const item = computedItems[i];
        const detailId = "DTL-" + orderId.replace("ORD-", "") + "-" + (i + 1);
        let fileDesainUrl = "";
        if (item.File_Desain_Base64) {
          fileDesainUrl = saveBase64ToDrive_(
            item.File_Desain_Base64,
            detailId,
            item.File_Desain || "desain_cetak"
          );
        } else if (item.File_Desain) {
          fileDesainUrl = saveBase64ToDrive_(item.File_Desain, detailId, item.File_Desain);
        }
        uploadedDesignUrls.push({ detailId: detailId, url: fileDesainUrl });
      }

      if (authenticatedUser) {
        userId = String(authenticatedUser.User_ID);
      } else {
        ensureSheetColumns_(ss, "Users", ["Status_Akun", "Token_Version"]);
        userId = generateUniqueEntityId_(existingUsers, "User_ID", "GUEST");
        appendObjectRow_(ss, "Users", {
          User_ID: userId,
          Nama: namaPelanggan,
          No_WA: "'" + reqNormWa,
          Email: reqEmail,
          Role: "User",
          Alamat: reqAlamat,
          Password: "",
          Status_Akun: "Aktif",
          Token_Version: 1
        });
      }

      const netTagihan = serverTotal - requestedSaldo;
      let statusBayarAwal = buktiBayarUrl ? "Menunggu Verifikasi" : "Belum Bayar";
      if (netTagihan === 0) statusBayarAwal = "Lunas"; // tagihan sepenuhnya ditutup saldo
      const savedOrder = {
        Order_ID: orderId,
        Tanggal: tanggal,
        User_ID: userId,
        Status_Order: netTagihan === 0 ? "Diproses" : "Menunggu Bayar",
        Total_Tagihan: netTagihan,
        Bukti_Bayar: buktiBayarUrl,
        Status_Bayar: statusBayarAwal,
        Catatan: String(orderPayload.Catatan || "").slice(0, 500),
        Harga_Kotor: serverTotal,
        Saldo_Dipakai: requestedSaldo,
        Saldo_Status: requestedSaldo > 0 ? "Dipakai" : "",
        Harga_Per_M2: rates.hargaJualPerM2,
        Modal_Per_M2: rates.modalPerM2,
        Reward_Per_M2: rates.rewardPerM2,
        Reward_Amount: "",
        Reward_Status: "",
        Reward_Ref: ""
      };
      if (requestedSaldo > 0) {
        applyWalletTx_(ss, userId, {
          type: "DISCOUNT_USED", amount: requestedSaldo, orderId: orderId,
          reference: "SLD-" + orderId, description: "Potongan saldo member untuk pesanan " + orderId, actor: userId
        });
      }
      appendObjectRow_(ss, "Pesanan", savedOrder);

      const savedDetailsForClient = [];
      for (let i = 0; i < computedItems.length; i++) {
        const item = computedItems[i];
        const up = uploadedDesignUrls[i];
        const detailRow = {
          Detail_ID: up.detailId,
          Order_ID: orderId,
          Produk_ID: item.Produk_ID,
          Panjang_m: item.Panjang_m,
          Lebar_m: item.Lebar_m,
          Qty: item.Qty,
          Finishing_ID: item.Finishing_ID,
          File_Desain: up.url,
          Keterangan_Item: item.Keterangan_Item,
          Subtotal: item.Subtotal
        };
        appendObjectRow_(ss, "Detail_Pesanan", detailRow);
        savedDetailsForClient.push({
          Detail_ID: detailRow.Detail_ID,
          Order_ID: detailRow.Order_ID,
          Produk_ID: detailRow.Produk_ID,
          Panjang_m: detailRow.Panjang_m,
          Lebar_m: detailRow.Lebar_m,
          Qty: detailRow.Qty,
          Finishing_ID: detailRow.Finishing_ID,
          File_Desain: detailRow.File_Desain ? "File terlampir" : "",
          Keterangan_Item: detailRow.Keterangan_Item,
          Subtotal: detailRow.Subtotal
        });
      }

      return jsonResponse_({
        status: "success",
        message: "Pesanan berhasil disimpan",
        data: {
          User_ID: userId,
          customer: {
            User_ID: userId,
            Nama: namaPelanggan,
            No_WA: maskWaForTracking_(reqNormWa)
          },
          pesanan: {
            Order_ID: savedOrder.Order_ID,
            Tanggal: savedOrder.Tanggal,
            User_ID: savedOrder.User_ID,
            Status_Order: savedOrder.Status_Order,
            Total_Tagihan: savedOrder.Total_Tagihan,
            Bukti_Bayar: savedOrder.Bukti_Bayar ? "Sudah diunggah" : "",
            Status_Bayar: savedOrder.Status_Bayar,
            Catatan: savedOrder.Catatan,
            Saldo_Dipakai: savedOrder.Saldo_Dipakai
          },
          detail_pesanan: savedDetailsForClient
        }
      });
    }

    // ------------------------------------------------------------------------
    // 7. UPDATE STATUS (Hanya Admin / Super Admin)
    // ------------------------------------------------------------------------
    if (action === "updateStatus") {
      assertRequiredSheetsPresent_(ss, ["Users", "Pesanan"]);
      const actor = requireRole_(ss, body, ["Admin", "Super Admin"]);
      const orderId = String(body.Order_ID || "").trim();
      const statusOrder = body.Status_Order ? String(body.Status_Order).trim() : "";
      const statusBayar = body.Status_Bayar ? String(body.Status_Bayar).trim() : "";

      if (statusOrder && ALLOWED_ORDER_STATUS.indexOf(statusOrder) === -1) {
        return jsonResponse_({ status: "error", message: "Status_Order tidak valid." });
      }
      if (statusBayar && ALLOWED_PAY_STATUS.indexOf(statusBayar) === -1) {
        return jsonResponse_({ status: "error", message: "Status_Bayar tidak valid." });
      }

      const sheet = ss.getSheetByName("Pesanan");
      const values = sheet.getDataRange().getValues();
      const headers = values[0].map(function (h) { return String(h).trim(); });

      const colOrderId = headers.indexOf("Order_ID");
      const colStatusOrder = headers.indexOf("Status_Order");
      const colStatusBayar = headers.indexOf("Status_Bayar");
      if (colOrderId === -1) throw new Error("Kolom Order_ID tidak ditemukan.");

      let updated = false;
      for (let r = 1; r < values.length; r++) {
        if (String(values[r][colOrderId]).trim() === orderId) {
          if (statusOrder && colStatusOrder !== -1) {
            sheet.getRange(r + 1, colStatusOrder + 1).setValue(statusOrder);
          }
          if (statusBayar && colStatusBayar !== -1) {
            sheet.getRange(r + 1, colStatusBayar + 1).setValue(statusBayar);
          }
          updated = true;
          break;
        }
      }

      if (!updated) {
        return jsonResponse_({ status: "error", message: "Order_ID tidak ditemukan: " + orderId });
      }
      let rewardNote = "";
      try {
        syncOrderRewardState_(ss, orderId, actor.user.User_ID);
      } catch (syncErr) {
        rewardNote = " Namun sinkronisasi saldo member gagal: " + syncErr.message;
      }
      return jsonResponse_({ status: "success", message: "Status pesanan diperbarui." + rewardNote });
    }

    // ------------------------------------------------------------------------
    // 8. SAVE PRODUCT (Anti-Tabrakan ID + Mode Edit Eksplisit)
    // ------------------------------------------------------------------------
    if (action === "saveProduct") {
      assertRequiredSheetsPresent_(ss, ["Users", "Produk"]);
      requireRole_(ss, body, ["Admin", "Super Admin"]);
      const prod = body.produk || body;
      const isEdit = Boolean(body.isEdit || prod.isEdit);
      const sheet = ss.getSheetByName("Produk");

      const existingRows = sheetToObjects_(ss, "Produk");
      const requestedId = String(prod.Produk_ID || "").trim();
      const prodId = requestedId || generateUniqueEntityId_(existingRows, "Produk_ID", "PRD");

      const hargaDasar = Math.round(parseSheetNumber_(prod.Harga_Dasar));
      const minOrder = Math.floor(parseSheetNumber_(prod.Min_Order));
      const tipeHitung = String(prod.Tipe_Hitung || "").trim().toLowerCase() === "dimensi" ? "Dimensi" : "Unit";
      const rawStatus = String(prod.Status || "").trim().toLowerCase();
      let statusProd = "Tersedia";
      if (rawStatus === "habis") statusProd = "Habis";
      else if (rawStatus === "arsip") statusProd = "Arsip";

      if (!String(prod.Nama_Produk || "").trim() || !Number.isFinite(hargaDasar) || hargaDasar < 0 || !Number.isFinite(minOrder) || minOrder < 1) {
        return jsonResponse_({ status: "error", message: "Data produk tidak valid." });
      }

      const values = sheet.getDataRange().getValues();
      const headers = values[0].map(function (h) { return String(h).trim(); });
      const colProdId = headers.indexOf("Produk_ID");

      let rowIndex = -1;
      for (let r = 1; r < values.length; r++) {
        if (String(values[r][colProdId]).trim() === prodId) {
          rowIndex = r + 1;
          break;
        }
      }

      if (!isEdit && rowIndex > 0) {
        return jsonResponse_({
          status: "error",
          message: "Produk_ID '" + prodId + "' sudah digunakan. Gunakan tombol Ubah untuk mengedit atau kosongkan ID agar dibuat otomatis."
        });
      }
      if (isEdit && rowIndex === -1) {
        return jsonResponse_({
          status: "error",
          message: "Produk dengan ID '" + prodId + "' tidak ditemukan."
        });
      }

      const productData = {
        Produk_ID: prodId,
        Nama_Produk: String(prod.Nama_Produk || "").trim(),
        Kategori: String(prod.Kategori || "").trim() || "Umum",
        Tipe_Hitung: tipeHitung,
        Harga_Dasar: hargaDasar,
        Satuan: String(prod.Satuan || "").trim() || "Unit",
        Min_Order: minOrder,
        Status: statusProd
      };

      if (rowIndex > 0) {
        headers.forEach(function (h, idx) {
          if (productData.hasOwnProperty(h)) {
            sheet.getRange(rowIndex, idx + 1).setValue(productData[h]);
          }
        });
      } else {
        appendObjectRow_(ss, "Produk", productData);
      }

      return jsonResponse_({
        status: "success",
        message: rowIndex > 0 ? "Produk diperbarui" : "Produk ditambahkan",
        data: productData
      });
    }

    // ------------------------------------------------------------------------
    // 9. SAVE FINISHING (Anti-Tabrakan ID + Mode Edit Eksplisit + Status Arsip)
    // ------------------------------------------------------------------------
    if (action === "saveFinishing") {
      assertRequiredSheetsPresent_(ss, ["Users", "Finishing"]);
      requireRole_(ss, body, ["Admin", "Super Admin"]);
      ensureSheetColumns_(ss, "Finishing", ["Status"]);
      const fin = body.finishing || body;
      const isEdit = Boolean(body.isEdit || fin.isEdit);
      const sheet = ss.getSheetByName("Finishing");

      const existingRows = sheetToObjects_(ss, "Finishing");
      const requestedId = String(fin.Finishing_ID || "").trim();
      const finId = requestedId || generateUniqueEntityId_(existingRows, "Finishing_ID", "FIN");
      const tambahanHarga = Math.round(parseSheetNumber_(fin.Tambahan_Harga));

      if (!String(fin.Nama_Finishing || "").trim() || !Number.isFinite(tambahanHarga) || tambahanHarga < 0) {
        return jsonResponse_({ status: "error", message: "Data finishing tidak valid." });
      }

      const values = sheet.getDataRange().getValues();
      const headers = values[0].map(function (h) { return String(h).trim(); });
      const colFinId = headers.indexOf("Finishing_ID");

      let rowIndex = -1;
      for (let r = 1; r < values.length; r++) {
        if (String(values[r][colFinId]).trim() === finId) {
          rowIndex = r + 1;
          break;
        }
      }

      if (!isEdit && rowIndex > 0) {
        return jsonResponse_({
          status: "error",
          message: "Finishing_ID '" + finId + "' sudah digunakan. Gunakan tombol Ubah untuk mengedit atau kosongkan ID."
        });
      }
      if (isEdit && rowIndex === -1) {
        return jsonResponse_({
          status: "error",
          message: "Finishing dengan ID '" + finId + "' tidak ditemukan."
        });
      }

      const statusFin = String(fin.Status || "").trim().toLowerCase() === "arsip" ? "Arsip" : "Tersedia";
      const finData = {
        Finishing_ID: finId,
        Nama_Finishing: String(fin.Nama_Finishing || "").trim(),
        Tipe_Biaya: fin.Tipe_Biaya === "Per_Qty" ? "Per_Qty" : "Tetap",
        Tambahan_Harga: tambahanHarga,
        Keterangan: String(fin.Keterangan || "").trim(),
        Status: statusFin
      };

      if (rowIndex > 0) {
        headers.forEach(function (h, idx) {
          if (finData.hasOwnProperty(h)) {
            sheet.getRange(rowIndex, idx + 1).setValue(finData[h]);
          }
        });
      } else {
        appendObjectRow_(ss, "Finishing", finData);
      }

      return jsonResponse_({
        status: "success",
        message: rowIndex > 0 ? "Opsi finishing diperbarui" : "Opsi finishing ditambahkan",
        data: finData
      });
    }

    // ------------------------------------------------------------------------
    // 10. SAVE USER (Super Admin Only + Proteksi Super Admin Utama/Terakhir)
    // ------------------------------------------------------------------------
    if (action === "saveUser") {
      assertRequiredSheetsPresent_(ss, ["Users"]);
      const auth = requireRole_(ss, body, ["Super Admin"]);
      ensureSheetColumns_(ss, "Users", ["Status_Akun", "Token_Version"]);
      const usr = body.user || body;
      const isEdit = Boolean(body.isEdit || usr.isEdit);
      const sheet = ss.getSheetByName("Users");

      const allUsers = sheetToObjects_(ss, "Users");
      const requestedId = String(usr.User_ID || "").trim();
      const userId = requestedId || generateUniqueEntityId_(allUsers, "User_ID", "USR");
      const roleVal = normalizeRole_(usr.Role);
      const statusAkunVal = normalizeAccountStatus_(usr.Status_Akun);

      if (ALLOWED_USER_ROLES.indexOf(roleVal) === -1) {
        return jsonResponse_({ status: "error", message: "Role tidak valid." });
      }
      if (!String(usr.Nama || "").trim()) {
        return jsonResponse_({ status: "error", message: "Nama pengguna wajib diisi." });
      }

      const values = sheet.getDataRange().getValues();
      const headers = values[0].map(function (h) { return String(h).trim(); });
      const colUserId = headers.indexOf("User_ID");

      let rowIndex = -1;
      for (let r = 1; r < values.length; r++) {
        if (String(values[r][colUserId]).trim() === userId) {
          rowIndex = r + 1;
          break;
        }
      }

      if (!isEdit && rowIndex > 0) {
        return jsonResponse_({
          status: "error",
          message: "User_ID '" + userId + "' sudah digunakan. Gunakan tombol Ubah untuk mengedit atau kosongkan ID."
        });
      }
      if (isEdit && rowIndex === -1) {
        return jsonResponse_({
          status: "error",
          message: "Pengguna dengan ID '" + userId + "' tidak ditemukan."
        });
      }

      const existingTarget = allUsers.find(function (u) {
        return String(u.User_ID || "").trim() === userId;
      }) || null;

      if (existingTarget) {
        const actorId = String(auth.session.uid).trim().toUpperCase();
        const targetIdUpper = String(existingTarget.User_ID || "").trim().toUpperCase();
        if (targetIdUpper === "SUP-001" && actorId !== "SUP-001") {
          return jsonResponse_({
            status: "error",
            message: "Akun Super Admin utama (SUP-001) dilindungi dan tidak dapat diubah oleh akun lain."
          });
        }
        if (String(existingTarget.User_ID).trim() === String(auth.session.uid).trim()) {
          if (roleVal !== "Super Admin" || statusAkunVal !== "Aktif") {
            return jsonResponse_({
              status: "error",
              message: "Anda tidak dapat menurunkan role atau menonaktifkan akun Anda sendiri."
            });
          }
        }
        if (isProtectedSuperAdmin_(allUsers, existingTarget) && (roleVal !== "Super Admin" || statusAkunVal !== "Aktif")) {
          return jsonResponse_({
            status: "error",
            message: "Super Admin utama atau terakhir yang aktif tidak dapat diturunkan perannya atau dinonaktifkan."
          });
        }
      }

      const rawPassword = String(usr.Password || "").trim();
      if (rowIndex === -1 && rawPassword.length < MIN_PASSWORD_LENGTH) {
        return jsonResponse_({
          status: "error",
          message: "Akun baru wajib memiliki kata sandi minimal " + MIN_PASSWORD_LENGTH + " karakter."
        });
      }
      if (rowIndex > 0 && rawPassword && !isHashedPassword_(rawPassword) && rawPassword.length < MIN_PASSWORD_LENGTH) {
        return jsonResponse_({
          status: "error",
          message: "Kata sandi baru minimal " + MIN_PASSWORD_LENGTH + " karakter."
        });
      }

      const passwordChanged = Boolean(rawPassword);
      const hashedPass = passwordChanged
        ? (isHashedPassword_(rawPassword) ? rawPassword : hashPassword_(rawPassword))
        : "";
      const normWa = normalizeWa_(usr.No_WA);
      const prevVer = existingTarget ? normalizeTokenVersion_(existingTarget.Token_Version) : 1;
      const shouldBumpVer = Boolean(
        existingTarget && (
          passwordChanged ||
          statusAkunVal !== "Aktif" ||
          normalizeRole_(existingTarget.Role) !== roleVal
        )
      );
      const nextTokenVer = shouldBumpVer ? (prevVer + 1) : prevVer;

      const userData = {
        User_ID: userId,
        Nama: String(usr.Nama || "").trim(),
        No_WA: normWa ? ("'" + normWa) : ("'" + String(usr.No_WA || "").replace(/^'/, "")),
        Email: String(usr.Email || "").trim().toLowerCase(),
        Role: roleVal,
        Alamat: String(usr.Alamat || "").trim(),
        Password: hashedPass,
        Status_Akun: statusAkunVal,
        Token_Version: nextTokenVer
      };

      if (rowIndex > 0) {
        headers.forEach(function (h, idx) {
          if (userData.hasOwnProperty(h) && (h !== "Password" || userData.Password !== "")) {
            sheet.getRange(rowIndex, idx + 1).setValue(userData[h]);
          }
        });
      } else {
        appendObjectRow_(ss, "Users", userData);
      }

      const responseObj = Object.assign({}, userData);
      if (!responseObj.Password && existingTarget && existingTarget.Password) {
        responseObj.Password = existingTarget.Password;
      }

      return jsonResponse_({
        status: "success",
        message: rowIndex > 0 ? "Data pengguna diperbarui" : "Pengguna ditambahkan",
        data: sanitizeUser_(responseObj)
      });
    }

    // ------------------------------------------------------------------------
    // 10B. TOGGLE USER STATUS & REVOKE USER SESSIONS (Khusus Super Admin)
    // ------------------------------------------------------------------------
    if (action === "toggleUserStatus") {
      assertRequiredSheetsPresent_(ss, ["Users"]);
      const auth = requireRole_(ss, body, ["Super Admin"]);
      const targetId = String(body.userId || body.User_ID || body.id || "").trim();
      if (!targetId) {
        return jsonResponse_({ status: "error", message: "User_ID target wajib diisi." });
      }

      const allUsers = sheetToObjects_(ss, "Users");
      const target = allUsers.find(function (u) {
        return String(u.User_ID || "").trim() === targetId;
      });
      if (!target) {
        return jsonResponse_({ status: "error", message: "Pengguna tidak ditemukan." });
      }

      const currentStatus = normalizeAccountStatus_(target.Status_Akun);
      const nextStatus = currentStatus === "Aktif" ? "Nonaktif" : "Aktif";

      if (nextStatus === "Nonaktif") {
        if (targetId === String(auth.session.uid).trim()) {
          return jsonResponse_({ status: "error", message: "Akun yang sedang aktif login tidak dapat dinonaktifkan." });
        }
        if (isProtectedSuperAdmin_(allUsers, target)) {
          return jsonResponse_({ status: "error", message: "Super Admin utama atau terakhir yang aktif tidak dapat dinonaktifkan." });
        }
      }

      const nextVer = nextStatus === "Nonaktif"
        ? normalizeTokenVersion_(target.Token_Version) + 1
        : normalizeTokenVersion_(target.Token_Version);

      updateUserFields_(ss, target.User_ID, {
        Status_Akun: nextStatus,
        Token_Version: nextVer
      });

      const updatedUser = Object.assign({}, target, {
        Status_Akun: nextStatus,
        Token_Version: nextVer
      });

      return jsonResponse_({
        status: "success",
        message: nextStatus === "Aktif"
          ? "Akun " + target.Nama + " diaktifkan kembali."
          : "Akun " + target.Nama + " dinonaktifkan dan seluruh sesinya dicabut.",
        data: sanitizeUser_(updatedUser)
      });
    }

    if (action === "revokeUserSessions") {
      assertRequiredSheetsPresent_(ss, ["Users"]);
      const auth = requireRole_(ss, body, ["Super Admin"]);
      const targetId = String(body.userId || body.User_ID || body.id || "").trim();
      if (!targetId) {
        return jsonResponse_({ status: "error", message: "User_ID target wajib diisi." });
      }

      const allUsers = sheetToObjects_(ss, "Users");
      const target = allUsers.find(function (u) {
        return String(u.User_ID || "").trim() === targetId;
      });
      if (!target) {
        return jsonResponse_({ status: "error", message: "Pengguna tidak ditemukan." });
      }

      const actorId = String(auth.session.uid).trim().toUpperCase();
      if (String(target.User_ID).trim().toUpperCase() === "SUP-001" && actorId !== "SUP-001") {
        return jsonResponse_({ status: "error", message: "Sesi Super Admin utama (SUP-001) tidak dapat dicabut oleh akun lain." });
      }

      const nextVer = normalizeTokenVersion_(target.Token_Version) + 1;
      updateUserFields_(ss, target.User_ID, { Token_Version: nextVer });

      return jsonResponse_({
        status: "success",
        message: "Seluruh sesi aktif untuk " + target.Nama + " berhasil dicabut.",
        data: {
          User_ID: target.User_ID,
          Token_Version: nextVer
        }
      });
    }

    // ------------------------------------------------------------------------
    // 11. SOFT-DELETE / ARSIP RECORD (Tidak Menghapus Baris Permanen)
    // ------------------------------------------------------------------------
    if (action === "deleteRecord" || action === "archiveRecord") {
      const sheetName = String(body.sheetName || "").trim();
      const recordId = String(body.id || "").trim();
      const idColMap = {
        Produk: "Produk_ID",
        Finishing: "Finishing_ID",
        Users: "User_ID",
        Pesanan: "Order_ID"
      };
      const idColName = idColMap[sheetName];
      if (!idColName || !recordId) {
        return jsonResponse_({ status: "error", message: "Parameter sheetName atau id tidak valid." });
      }

      assertRequiredSheetsPresent_(ss, ["Users", sheetName]);
      const allowed = sheetName === "Users" ? ["Super Admin"] : ["Admin", "Super Admin"];
      const auth = requireRole_(ss, body, allowed);

      if (sheetName === "Users") {
        const allUsers = sheetToObjects_(ss, "Users");
        const target = allUsers.find(function (u) {
          return String(u.User_ID || "").trim() === recordId;
        });
        if (!target) {
          return jsonResponse_({ status: "error", message: "Pengguna tidak ditemukan." });
        }
        if (recordId === String(auth.session.uid).trim()) {
          return jsonResponse_({ status: "error", message: "Akun yang sedang aktif login tidak dapat diarsipkan." });
        }
        if (isProtectedSuperAdmin_(allUsers, target)) {
          return jsonResponse_({ status: "error", message: "Super Admin utama atau terakhir yang aktif tidak dapat diarsipkan." });
        }
        const nextVer = normalizeTokenVersion_(target.Token_Version) + 1;
        updateUserFields_(ss, target.User_ID, {
          Status_Akun: "Nonaktif",
          Token_Version: nextVer
        });
        return jsonResponse_({
          status: "success",
          message: "Akun pengguna dinonaktifkan & diarsipkan (riwayat pesanan tetap terjaga).",
          archivedCount: 1
        });
      }

      if (sheetName === "Finishing") {
        ensureSheetColumns_(ss, "Finishing", ["Status"]);
      }

      const sheet = ss.getSheetByName(sheetName);
      const values = sheet.getDataRange().getValues();
      const headers = values[0].map(function (h) { return String(h).trim(); });
      const colIdx = headers.indexOf(idColName);
      if (colIdx === -1) throw new Error("Kolom '" + idColName + "' tidak ditemukan.");

      const statusColName = sheetName === "Pesanan" ? "Status_Order" : "Status";
      const targetArchiveValue = sheetName === "Pesanan" ? "Diarsipkan" : "Arsip";
      const statusColIdx = headers.indexOf(statusColName);
      if (statusColIdx === -1) throw new Error("Kolom '" + statusColName + "' tidak ditemukan.");

      let archivedCount = 0;
      for (let r = 1; r < values.length; r++) {
        if (String(values[r][colIdx]).trim() === recordId) {
          sheet.getRange(r + 1, statusColIdx + 1).setValue(targetArchiveValue);
          archivedCount++;
        }
      }

      if (archivedCount === 0) {
        return jsonResponse_({ status: "error", message: "Data dengan ID '" + recordId + "' tidak ditemukan." });
      }

      if (sheetName === "Pesanan") {
        syncOrderRewardState_(ss, recordId, auth.user.User_ID);
      }

      return jsonResponse_({
        status: "success",
        message: "Data berhasil diarsipkan (" + archivedCount + " baris). Histori transaksi tetap aman.",
        archivedCount: archivedCount
      });
    }

    // ------------------------------------------------------------------------
    // 11b. BANNER MEMBER REWARDS (saldo, reward, penarikan, laporan)
    // ------------------------------------------------------------------------
    const memberResponse = handleMemberRewardAction_(ss, body, action);
    if (memberResponse) return memberResponse;

    // ------------------------------------------------------------------------
    // 12. INIT SHEETS & CREATE NEW DATABASE (Hanya Super Admin)
    // ------------------------------------------------------------------------
    if (action === "initSheets") {
      assertRequiredSheetsPresent_(ss, ["Users"]);
      requireRole_(ss, body, ["Super Admin"]);
      const initResult = ensureSheetsInitialized_(ss);
      const migrated = migratePlaintextPasswords_(ss);
      initResult.migratedPlaintextPasswords = migrated;
      return jsonResponse_({
        status: "success",
        message: "Inisialisasi 11 tab (5 inti + 6 Banner Member Rewards) & hash password selesai.",
        data: initResult
      });
    }

    if (action === "createNewDatabase") {
      assertRequiredSheetsPresent_(ss, ["Users"]);
      const auth = requireRole_(ss, body, ["Super Admin"]);
      const createdResult = buatDatabaseBaru_(auth.user);
      return jsonResponse_({
        status: "success",
        message: "Database Google Sheets baru berhasil dibuat di Google Drive.",
        data: createdResult
      });
    }

    return jsonResponse_({ status: "error", message: "Action POST tidak dikenal: " + action });
  } catch (err) {
    return jsonResponse_({ status: "error", message: err.message });
  } finally {
    if (hasLock) {
      try { lock.releaseLock(); } catch (e) {}
    }
  }
}

// ============================================================================
// BANNER MEMBER REWARDS — saldo member, reward, potongan saldo, penarikan,
// dan laporan keuangan. Semua fungsi penulisan dipanggil dari doPost yang
// sudah memegang ScriptLock, sehingga pembacaan dan penulisan saldo tidak
// bisa saling tumpang tindih (mencegah saldo ganda / reward ganda).
// ============================================================================

const MEMBER_SETTING_DEFAULTS_ = {
  HARGA_JUAL_PER_M2: 20000,
  MODAL_PER_M2: 16000,
  REWARD_PER_M2: 1000,
  MIN_TARIK: 50000,
  PROGRAM_AKTIF: "TRUE"
};

const WITHDRAW_STATUS_LIST_ = ["Menunggu Verifikasi", "Disetujui", "Sedang Diproses", "Berhasil", "Ditolak", "Gagal"];

const WITHDRAW_TRANSITIONS_ = {
  "Menunggu Verifikasi": ["Disetujui", "Ditolak"],
  "Disetujui": ["Sedang Diproses", "Berhasil", "Gagal"],
  "Sedang Diproses": ["Berhasil", "Gagal"]
};

// Efek setiap jenis transaksi: av = saldo tersedia, he = saldo tertahan (dikali nominal).
const WALLET_EFFECTS_ = {
  REWARD_HELD:       { av: 0,  he: 1 },
  REWARD_RELEASED:   { av: 1,  he: -1 },
  REWARD_REVERSED:   { av: 0,  he: -1 },
  DISCOUNT_USED:     { av: -1, he: 0 },
  DISCOUNT_RESTORED: { av: 1,  he: 0 },
  WITHDRAW_HOLD:     { av: -1, he: 1 },
  WITHDRAW_PAID:     { av: 0,  he: -1 },
  WITHDRAW_RELEASED: { av: 1,  he: -1 },
  ADJUST_IN:         { av: 1,  he: 0 },
  ADJUST_OUT:        { av: -1, he: 0 }
};

// Arah transaksi untuk indikator visual di dashboard member.
const TX_ARAH_ = {
  REWARD_HELD: "tertahan",
  REWARD_RELEASED: "masuk",
  REWARD_REVERSED: "batal",
  DISCOUNT_USED: "keluar",
  DISCOUNT_RESTORED: "masuk",
  WITHDRAW_HOLD: "tertahan",
  WITHDRAW_PAID: "keluar",
  WITHDRAW_RELEASED: "masuk",
  ADJUST_IN: "masuk",
  ADJUST_OUT: "keluar"
};

function nowStamp_() {
  return Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyyy-MM-dd HH:mm");
}

function shortUpper_(len) {
  return Utilities.getUuid().replace(/-/g, "").slice(0, len).toUpperCase();
}

function formatIdrServer_(n) {
  return String(Math.round(Number(n) || 0)).replace(/\B(?=(\d{3})+(?!\d))/g, ".");
}

function sheetHeaders_(ss, sheetName) {
  const sheet = ss.getSheetByName(sheetName);
  if (!sheet || sheet.getLastColumn() === 0) return [];
  return sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0].map(function (h) {
    return String(h).trim();
  });
}

function isGuestUserId_(userId) {
  return String(userId || "").trim().indexOf("GUEST-") === 0;
}

// Migrasi aditif: tab/kolom baru ditambahkan bila belum ada. Tidak ada data yang diubah atau dihapus.
function ensureMemberSheets_(ss) {
  const required = ["Member_Profiles", "Wallet_Accounts", "Wallet_Transactions", "Withdrawal_Requests", "System_Settings", "Biaya_Tambahan"];
  const missingSheet = required.some(function (name) { return !ss.getSheetByName(name); });
  const missingColumn = sheetHeaders_(ss, "Pesanan").indexOf("Reward_Status") === -1;
  if (missingSheet || missingColumn) {
    ensureSheetsInitialized_(ss);
  }
}

// ---------------------------------------------------------------------------
// PENGATURAN PROGRAM (System_Settings)
// ---------------------------------------------------------------------------
function getSystemSettings_(ss) {
  const merged = {};
  Object.keys(MEMBER_SETTING_DEFAULTS_).forEach(function (k) {
    merged[k] = MEMBER_SETTING_DEFAULTS_[k];
  });
  sheetToObjects_(ss, "System_Settings").forEach(function (row) {
    const key = String(row.Setting_Key || "").trim();
    if (MEMBER_SETTING_DEFAULTS_.hasOwnProperty(key)) merged[key] = row.Setting_Value;
  });
  return {
    hargaJualPerM2: Number(merged.HARGA_JUAL_PER_M2) || 0,
    modalPerM2: Number(merged.MODAL_PER_M2) || 0,
    rewardPerM2: Number(merged.REWARD_PER_M2) || 0,
    minTarik: Number(merged.MIN_TARIK) || 0,
    aktif: String(merged.PROGRAM_AKTIF).trim().toUpperCase() === "TRUE"
  };
}

// Data publik (tanpa harga modal) yang boleh dilihat pelanggan.
function publicProgramInfo_(settings) {
  return {
    hargaJualPerM2: settings.hargaJualPerM2,
    rewardPerM2: settings.rewardPerM2,
    minTarik: settings.minTarik,
    aktif: settings.aktif
  };
}

// ---------------------------------------------------------------------------
// DOMPET (Wallet_Accounts) & BUKU BESAR (Wallet_Transactions)
// ---------------------------------------------------------------------------
function getWallet_(ss, userId) {
  const result = { rowIdx: -1, available: 0, held: 0 };
  const sheet = ss.getSheetByName("Wallet_Accounts");
  if (!sheet || sheet.getLastRow() < 2) return result;
  const headers = sheetHeaders_(ss, "Wallet_Accounts");
  const values = sheet.getDataRange().getValues();
  const colUser = headers.indexOf("User_ID");
  const target = String(userId).trim();
  for (let r = 1; r < values.length; r++) {
    if (String(values[r][colUser]).trim() === target) {
      result.rowIdx = r + 1;
      result.available = Number(values[r][headers.indexOf("Available_Balance")]) || 0;
      result.held = Number(values[r][headers.indexOf("Held_Balance")]) || 0;
      break;
    }
  }
  return result;
}

function setWalletBalances_(ss, userId, available, held) {
  if (available < 0 || held < 0) throw new Error("Saldo tidak boleh bernilai negatif.");
  const now = nowStamp_();
  const current = getWallet_(ss, userId);
  if (current.rowIdx === -1) {
    appendObjectRow_(ss, "Wallet_Accounts", {
      Wallet_ID: "WAL-" + shortUpper_(8),
      User_ID: String(userId).trim(),
      Available_Balance: available,
      Held_Balance: held,
      Created_At: now,
      Updated_At: now
    });
    return;
  }
  const sheet = ss.getSheetByName("Wallet_Accounts");
  const headers = sheetHeaders_(ss, "Wallet_Accounts");
  sheet.getRange(current.rowIdx, headers.indexOf("Available_Balance") + 1).setValue(available);
  sheet.getRange(current.rowIdx, headers.indexOf("Held_Balance") + 1).setValue(held);
  sheet.getRange(current.rowIdx, headers.indexOf("Updated_At") + 1).setValue(now);
}

// Satu-satunya pintu perubahan saldo: setiap perubahan pasti tercatat di Wallet_Transactions.
function applyWalletTx_(ss, userId, tx) {
  const effect = WALLET_EFFECTS_[tx.type];
  if (!effect) throw new Error("Jenis transaksi saldo tidak dikenal: " + tx.type);
  const amount = Math.round(Number(tx.amount));
  if (!Number.isFinite(amount) || amount <= 0) throw new Error("Nominal transaksi saldo tidak valid.");
  const wallet = getWallet_(ss, userId);
  const nextAvailable = wallet.available + effect.av * amount;
  const nextHeld = wallet.held + effect.he * amount;
  if (nextAvailable < 0 || nextHeld < 0) throw new Error("Saldo tidak mencukupi untuk transaksi ini.");
  setWalletBalances_(ss, userId, nextAvailable, nextHeld);
  appendObjectRow_(ss, "Wallet_Transactions", {
    Trx_ID: "TRX-" + shortUpper_(10),
    Created_At: nowStamp_(),
    User_ID: String(userId).trim(),
    Order_ID: tx.orderId || "",
    Transaction_Type: tx.type,
    Amount: amount,
    Reference_ID: tx.reference || "",
    Description: tx.description || "",
    Created_By: tx.actor || "SYSTEM"
  });
  return { available: nextAvailable, held: nextHeld };
}

function summarizeWalletTx_(rows) {
  const sumOf = function (type) {
    return rows.reduce(function (acc, t) {
      return t.Transaction_Type === type ? acc + (Number(t.Amount) || 0) : acc;
    }, 0);
  };
  const rewardGranted = sumOf("REWARD_HELD");
  const rewardReleased = sumOf("REWARD_RELEASED");
  const rewardReversed = sumOf("REWARD_REVERSED");
  return {
    rewardGranted: rewardGranted,
    rewardHeld: rewardGranted - rewardReleased - rewardReversed,
    rewardReleased: rewardReleased,
    saldoDipakai: sumOf("DISCOUNT_USED") - sumOf("DISCOUNT_RESTORED"),
    ditarik: sumOf("WITHDRAW_PAID")
  };
}

function mapWalletTx_(t, includeActor) {
  const row = {
    Trx_ID: t.Trx_ID,
    Created_At: t.Created_At,
    User_ID: t.User_ID,
    Order_ID: t.Order_ID,
    Transaction_Type: t.Transaction_Type,
    Arah: TX_ARAH_[t.Transaction_Type] || "",
    Amount: Number(t.Amount) || 0,
    Reference_ID: t.Reference_ID,
    Description: t.Description
  };
  if (includeActor) row.Created_By = t.Created_By;
  return row;
}

function byNewestFirst_(field) {
  return function (a, b) { return String(b[field] || "").localeCompare(String(a[field] || "")); };
}

// ---------------------------------------------------------------------------
// REWARD PESANAN (dipicu dari updateStatus)
// ---------------------------------------------------------------------------
function setOrderCells_(ss, orderId, updates) {
  const sheet = ss.getSheetByName("Pesanan");
  const headers = sheetHeaders_(ss, "Pesanan");
  const values = sheet.getDataRange().getValues();
  const colId = headers.indexOf("Order_ID");
  for (let r = 1; r < values.length; r++) {
    if (String(values[r][colId]).trim() === String(orderId).trim()) {
      Object.keys(updates).forEach(function (key) {
        const col = headers.indexOf(key);
        if (col === -1) throw new Error("Kolom " + key + " tidak ditemukan di Pesanan.");
        sheet.getRange(r + 1, col + 1).setValue(updates[key]);
      });
      return;
    }
  }
  throw new Error("Pesanan tidak ditemukan: " + orderId);
}

function findOrder_(ss, orderId) {
  return sheetToObjects_(ss, "Pesanan").find(function (o) {
    return String(o.Order_ID || "").trim() === String(orderId).trim();
  }) || null;
}

// Total luas (m²) × jumlah dari detail pesanan. Hanya item berukuran (Panjang & Lebar > 0).
function computeOrderLuas_(ss, orderId) {
  let luas = 0;
  sheetToObjects_(ss, "Detail_Pesanan").forEach(function (d) {
    if (String(d.Order_ID || "").trim() !== String(orderId).trim()) return;
    const p = Number(d.Panjang_m) || 0;
    const l = Number(d.Lebar_m) || 0;
    const q = Number(d.Qty) || 0;
    if (p > 0 && l > 0 && q > 0) luas += p * l * q;
  });
  return Math.round(luas * 10000) / 10000;
}

// Sinkronisasi state saldo untuk satu pesanan. Dipanggil setiap kali status berubah.
// Setiap langkah idempoten: status di Sheet menjadi penanda sehingga tidak ada reward/refund ganda.
function syncOrderRewardState_(ss, orderId, actorId) {
  ensureMemberSheets_(ss);
  const order = findOrder_(ss, orderId);
  if (!order) return;
  const userId = String(order.User_ID || "").trim();
  const guest = isGuestUserId_(userId);
  const status = String(order.Status_Order || "").trim();
  const bayar = String(order.Status_Bayar || "").trim();
  const rewardStatus = String(order.Reward_Status || "").trim();
  const rewardAmount = Number(order.Reward_Amount) || 0;
  const rewardRef = "REW-" + orderId;

  // (1) Pembatalan: kembalikan potongan saldo sekali saja.
  if (status === "Diarsipkan" && !guest && String(order.Saldo_Status || "").trim() === "Dipakai") {
    const used = Number(order.Saldo_Dipakai) || 0;
    if (used > 0) {
      applyWalletTx_(ss, userId, {
        type: "DISCOUNT_RESTORED", amount: used, orderId: orderId, reference: "SLD-" + orderId,
        description: "Pengembalian potongan saldo: pesanan " + orderId + " dibatalkan", actor: actorId
      });
    }
    setOrderCells_(ss, orderId, { Saldo_Status: "Dikembalikan" });
  }

  // (2) Reward yang masih ditahan dibatalkan bila pesanan diarsipkan atau belum lunas.
  if (rewardStatus === "Ditahan" && (status === "Diarsipkan" || bayar !== "Lunas")) {
    applyWalletTx_(ss, userId, {
      type: "REWARD_REVERSED", amount: rewardAmount, orderId: orderId, reference: rewardRef,
      description: "Reward dibatalkan: pesanan " + orderId + " dibatalkan atau belum lunas", actor: actorId
    });
    setOrderCells_(ss, orderId, { Reward_Status: "Dibatalkan" });
    return;
  }

  // (3) Pemberian reward: sekali per pesanan, hanya jika lunas dan sudah selesai produksi.
  if (!rewardStatus && !guest && status !== "Diarsipkan" && bayar === "Lunas" && (status === "Selesai" || status === "Diambil")) {
    const settings = getSystemSettings_(ss);
    if (settings.aktif) {
      const ratePerM2 = Number(order.Reward_Per_M2);
      if (!(ratePerM2 > 0)) {
        // Pesanan dibuat sebelum program berjalan: tidak mendapat reward surut.
        setOrderCells_(ss, orderId, { Reward_Status: "Tidak Berlaku" });
      } else {
        const luas = computeOrderLuas_(ss, orderId);
        const amount = Math.round(luas * ratePerM2);
        if (amount > 0) {
          applyWalletTx_(ss, userId, {
            type: "REWARD_HELD", amount: amount, orderId: orderId, reference: rewardRef,
            description: "Reward member " + luas + " m² × Rp " + formatIdrServer_(ratePerM2) + " untuk pesanan " + orderId,
            actor: actorId
          });
          setOrderCells_(ss, orderId, { Reward_Amount: amount, Reward_Status: "Ditahan", Reward_Ref: rewardRef });
        } else {
          setOrderCells_(ss, orderId, { Reward_Status: "Tidak Berlaku" });
        }
      }
    }
  }

  // (4) Pencairan: setelah pesanan diambil, reward ditahan menjadi saldo tersedia.
  const latest = findOrder_(ss, orderId);
  if (
    latest &&
    String(latest.Reward_Status || "").trim() === "Ditahan" &&
    String(latest.Status_Order || "").trim() === "Diambil" &&
    String(latest.Status_Bayar || "").trim() === "Lunas"
  ) {
    applyWalletTx_(ss, userId, {
      type: "REWARD_RELEASED", amount: Number(latest.Reward_Amount) || 0, orderId: orderId, reference: rewardRef,
      description: "Reward dicairkan ke saldo tersedia: pesanan " + orderId + " sudah diambil", actor: actorId
    });
    setOrderCells_(ss, orderId, { Reward_Status: "Dirilis" });
  }
}

// ---------------------------------------------------------------------------
// PROFIL REKENING & PENARIKAN
// ---------------------------------------------------------------------------
function validateBankInput_(body) {
  const bank = String(body.Nama_Bank || body.Bank_Name || "").trim().slice(0, 60);
  const acc = String(body.Nomor_Rekening || body.Account_Number || "").replace(/[\s-]/g, "");
  const holder = String(body.Nama_Pemilik || body.Account_Holder || "").trim().slice(0, 80);
  if (!bank) throw new Error("Nama bank atau e-wallet wajib diisi.");
  if (!/^\d{6,20}$/.test(acc)) throw new Error("Nomor rekening atau e-wallet harus 6–20 digit angka.");
  if (!holder) throw new Error("Nama pemilik rekening wajib diisi.");
  return { Nama_Bank: bank, Nomor_Rekening: acc, Nama_Pemilik: holder };
}

function saveMemberProfile_(ss, userId, profile) {
  const sheet = ss.getSheetByName("Member_Profiles");
  const headers = sheetHeaders_(ss, "Member_Profiles");
  const values = sheet.getDataRange().getValues();
  const colUser = headers.indexOf("User_ID");
  const target = String(userId).trim();
  const row = {
    User_ID: target,
    Nama_Bank: profile.Nama_Bank,
    Nomor_Rekening: "'" + profile.Nomor_Rekening,
    Nama_Pemilik: profile.Nama_Pemilik,
    Updated_At: nowStamp_()
  };
  for (let r = 1; r < values.length; r++) {
    if (String(values[r][colUser]).trim() === target) {
      Object.keys(row).forEach(function (key) {
        const col = headers.indexOf(key);
        if (col !== -1) sheet.getRange(r + 1, col + 1).setValue(row[key]);
      });
      return;
    }
  }
  appendObjectRow_(ss, "Member_Profiles", row);
}

function maskAccount_(acc) {
  const s = String(acc || "");
  return s.length > 4 ? "•••• " + s.slice(-4) : s;
}

function getMemberProfile_(ss, userId) {
  const row = sheetToObjects_(ss, "Member_Profiles").find(function (p) {
    return String(p.User_ID || "").trim() === String(userId).trim();
  });
  if (!row) return { Nama_Bank: "", Nomor_Rekening_Masked: "", Nama_Pemilik: "", Tersimpan: false };
  return {
    Nama_Bank: String(row.Nama_Bank || ""),
    Nomor_Rekening_Masked: maskAccount_(row.Nomor_Rekening),
    Nama_Pemilik: String(row.Nama_Pemilik || ""),
    Tersimpan: true
  };
}

function generateWithdrawId_() {
  const stamp = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyyyMMdd");
  return "WD-" + stamp + "-" + shortUpper_(8);
}

function handleRequestWithdrawal_(ss, body, actor) {
  const userId = String(actor.user.User_ID).trim();
  const settings = getSystemSettings_(ss);
  const amount = Math.floor(Number(body.Amount) || 0);
  if (amount < settings.minTarik) {
    throw new Error("Minimal penarikan Rp " + formatIdrServer_(settings.minTarik) + ".");
  }
  const profile = validateBankInput_(body);
  const wallet = getWallet_(ss, userId);
  if (amount > wallet.available) {
    throw new Error("Saldo tersedia tidak mencukupi. Saldo tersedia: Rp " + formatIdrServer_(wallet.available) + ".");
  }
  const wdId = generateWithdrawId_();
  // Saldo dicadangkan saat pengajuan berhasil (available -> held).
  applyWalletTx_(ss, userId, { type: "WITHDRAW_HOLD", amount: amount, reference: wdId, description: "Pengajuan penarikan saldo " + wdId, actor: userId });
  appendObjectRow_(ss, "Withdrawal_Requests", {
    Withdraw_ID: wdId,
    Created_At: nowStamp_(),
    User_ID: userId,
    Amount: amount,
    Bank_Name: profile.Nama_Bank,
    Account_Number: "'" + profile.Nomor_Rekening,
    Account_Holder: profile.Nama_Pemilik,
    Status: "Menunggu Verifikasi",
    Admin_Note: "",
    Bukti_Transfer: "",
    Reference_ID: wdId,
    Processed_At: "",
    Processed_By: ""
  });
  saveMemberProfile_(ss, userId, profile);
  return { status: "success", message: "Permintaan penarikan " + wdId + " diterima. Saldo sudah dicadangkan.", data: { Withdraw_ID: wdId } };
}

function handleAdminUpdateWithdrawal_(ss, body, actor) {
  const wdId = String(body.Withdraw_ID || "").trim();
  const next = String(body.Status || "").trim();
  const note = String(body.Admin_Note || "").trim().slice(0, 300);
  if (WITHDRAW_STATUS_LIST_.indexOf(next) === -1) throw new Error("Status penarikan tidak valid.");

  const sheet = ss.getSheetByName("Withdrawal_Requests");
  if (!sheet) throw new Error("Tab Withdrawal_Requests belum tersedia.");
  const headers = sheetHeaders_(ss, "Withdrawal_Requests");
  const col = function (name) {
    const c = headers.indexOf(name);
    if (c === -1) throw new Error("Kolom " + name + " tidak ditemukan.");
    return c;
  };
  const values = sheet.getDataRange().getValues();
  let rowIdx = -1;
  for (let r = 1; r < values.length; r++) {
    if (String(values[r][col("Withdraw_ID")]).trim() === wdId) { rowIdx = r; break; }
  }
  if (rowIdx === -1) throw new Error("Permintaan penarikan tidak ditemukan: " + wdId);

  const row = values[rowIdx];
  const current = String(row[col("Status")]).trim();
  const allowed = WITHDRAW_TRANSITIONS_[current] || [];
  if (allowed.indexOf(next) === -1) {
    throw new Error("Perubahan status dari \"" + current + "\" ke \"" + next + "\" tidak diizinkan.");
  }

  const userId = String(row[col("User_ID")]).trim();
  const amount = Number(row[col("Amount")]) || 0;
  const actorId = String(actor.user.User_ID);

  let proofUrl = "";
  if (body.Bukti_Transfer) {
    proofUrl = saveBase64ToDrive_(
      String(body.Bukti_Transfer),
      wdId + "_TRANSFER",
      String(body.Bukti_Transfer_Name || "bukti_transfer.jpg"),
      { imagesOnly: true }
    );
  }
  const existingProof = String(row[col("Bukti_Transfer")] || "").trim();
  if (next === "Berhasil" && !proofUrl && !existingProof) {
    throw new Error("Unggah bukti transfer sebelum menandai penarikan Berhasil.");
  }

  // Efek saldo: ditolak/gagal -> saldo dikembalikan; berhasil -> pengeluaran permanen.
  if (next === "Ditolak" || next === "Gagal") {
    applyWalletTx_(ss, userId, {
      type: "WITHDRAW_RELEASED", amount: amount, reference: wdId,
      description: "Penarikan " + wdId + " " + next.toLowerCase() + ": saldo dikembalikan", actor: actorId
    });
  }
  if (next === "Berhasil") {
    applyWalletTx_(ss, userId, {
      type: "WITHDRAW_PAID", amount: amount, reference: wdId,
      description: "Penarikan " + wdId + " sudah ditransfer", actor: actorId
    });
  }

  const updates = { Status: next, Processed_At: nowStamp_(), Processed_By: actorId };
  if (note) updates.Admin_Note = note;
  if (proofUrl) updates.Bukti_Transfer = proofUrl;
  Object.keys(updates).forEach(function (key) {
    sheet.getRange(rowIdx + 1, col(key) + 1).setValue(updates[key]);
  });
  return { status: "success", message: "Status penarikan " + wdId + " menjadi " + next + "." };
}

// ---------------------------------------------------------------------------
// DASHBOARD MEMBER (hanya data milik sendiri)
// ---------------------------------------------------------------------------
function handleGetMemberDashboard_(ss, actor) {
  const userId = String(actor.user.User_ID).trim();
  const settings = getSystemSettings_(ss);
  const wallet = getWallet_(ss, userId);
  const txRows = sheetToObjects_(ss, "Wallet_Transactions").filter(function (t) {
    return String(t.User_ID).trim() === userId;
  });
  const sum = summarizeWalletTx_(txRows);
  const withdrawals = sheetToObjects_(ss, "Withdrawal_Requests")
    .filter(function (w) { return String(w.User_ID).trim() === userId; })
    .map(function (w) {
      return {
        Withdraw_ID: w.Withdraw_ID,
        Created_At: w.Created_At,
        Amount: Number(w.Amount) || 0,
        Bank_Name: w.Bank_Name,
        Account_Number_Masked: maskAccount_(w.Account_Number),
        Status: w.Status,
        Admin_Note: w.Admin_Note,
        Bukti_Transfer: w.Bukti_Transfer ? "Sudah diunggah" : "",
        Reference_ID: w.Reference_ID,
        Processed_At: w.Processed_At
      };
    })
    .sort(byNewestFirst_("Created_At"));
  const orders = sheetToObjects_(ss, "Pesanan")
    .filter(function (o) {
      return String(o.User_ID).trim() === userId && String(o.Status_Order).trim() !== "Diarsipkan";
    })
    .map(function (o) {
      return {
        Order_ID: o.Order_ID,
        Tanggal: o.Tanggal,
        Status_Order: o.Status_Order,
        Status_Bayar: o.Status_Bayar,
        Total_Tagihan: Number(o.Total_Tagihan) || 0,
        Saldo_Dipakai: Number(o.Saldo_Dipakai) || 0,
        Reward_Amount: Number(o.Reward_Amount) || 0,
        Reward_Status: o.Reward_Status || ""
      };
    })
    .sort(byNewestFirst_("Tanggal"));
  return {
    status: "success",
    data: {
      saldo: {
        tersedia: wallet.available,
        tertahan: sum.rewardHeld,
        penarikanProses: Math.max(0, wallet.held - sum.rewardHeld),
        totalReward: sum.rewardGranted,
        totalDipakai: sum.saldoDipakai,
        totalDitarik: sum.ditarik
      },
      program: publicProgramInfo_(settings),
      transaksi: txRows.map(function (t) { return mapWalletTx_(t, false); }).sort(byNewestFirst_("Created_At")),
      penarikan: withdrawals,
      pesanan: orders,
      profil: getMemberProfile_(ss, userId)
    }
  };
}

// ---------------------------------------------------------------------------
// ADMIN: MEMBER, KOREKSI SALDO, PENGATURAN, BIAYA, LAPORAN
// ---------------------------------------------------------------------------
function handleAdminGetMemberData_(ss) {
  const settings = getSystemSettings_(ss);
  const users = sheetToObjects_(ss, "Users").filter(function (u) {
    return normalizeRole_(u.Role) === "User" && !isGuestUserId_(u.User_ID);
  });
  const wallets = sheetToObjects_(ss, "Wallet_Accounts");
  const txs = sheetToObjects_(ss, "Wallet_Transactions");
  const orders = sheetToObjects_(ss, "Pesanan");
  const profiles = sheetToObjects_(ss, "Member_Profiles");
  const nameById = {};

  const members = users.map(function (u) {
    const uid = String(u.User_ID).trim();
    nameById[uid] = String(u.Nama || "");
    const w = wallets.find(function (x) { return String(x.User_ID).trim() === uid; });
    const sum = summarizeWalletTx_(txs.filter(function (t) { return String(t.User_ID).trim() === uid; }));
    const paid = orders.filter(function (o) {
      return String(o.User_ID).trim() === uid && String(o.Status_Bayar).trim() === "Lunas" && String(o.Status_Order).trim() !== "Diarsipkan";
    });
    const profile = profiles.find(function (p) { return String(p.User_ID).trim() === uid; });
    const available = w ? (Number(w.Available_Balance) || 0) : 0;
    const held = w ? (Number(w.Held_Balance) || 0) : 0;
    return {
      User_ID: uid,
      Nama: String(u.Nama || ""),
      No_WA: String(u.No_WA || ""),
      Email: String(u.Email || ""),
      Status_Akun: normalizeAccountStatus_(u.Status_Akun),
      jumlahTransaksi: paid.length,
      totalBelanja: paid.reduce(function (a, o) { return a + (Number(o.Total_Tagihan) || 0); }, 0),
      saldoTersedia: available,
      saldoTertahan: sum.rewardHeld,
      penarikanProses: Math.max(0, held - sum.rewardHeld),
      totalReward: sum.rewardGranted,
      totalDipakai: sum.saldoDipakai,
      totalDitarik: sum.ditarik,
      rekening: profile ? {
        Nama_Bank: String(profile.Nama_Bank || ""),
        Nomor_Rekening: String(profile.Nomor_Rekening || ""),
        Nama_Pemilik: String(profile.Nama_Pemilik || "")
      } : null
    };
  });

  const withdrawals = sheetToObjects_(ss, "Withdrawal_Requests").map(function (w) {
    return {
      Withdraw_ID: w.Withdraw_ID,
      Created_At: w.Created_At,
      User_ID: w.User_ID,
      Nama: nameById[String(w.User_ID).trim()] || "",
      Amount: Number(w.Amount) || 0,
      Bank_Name: w.Bank_Name,
      Account_Number: String(w.Account_Number || ""),
      Account_Holder: w.Account_Holder,
      Status: w.Status,
      Admin_Note: w.Admin_Note,
      Bukti_Transfer: w.Bukti_Transfer || "",
      Processed_At: w.Processed_At,
      Processed_By: w.Processed_By
    };
  }).sort(byNewestFirst_("Created_At"));

  const rewardRows = orders
    .filter(function (o) { return String(o.Reward_Status || "").trim() !== ""; })
    .map(function (o) {
      return {
        Order_ID: o.Order_ID,
        Tanggal: o.Tanggal,
        User_ID: o.User_ID,
        Nama: nameById[String(o.User_ID).trim()] || "",
        Status_Order: o.Status_Order,
        Status_Bayar: o.Status_Bayar,
        Reward_Amount: Number(o.Reward_Amount) || 0,
        Reward_Status: o.Reward_Status,
        Saldo_Dipakai: Number(o.Saldo_Dipakai) || 0
      };
    })
    .sort(byNewestFirst_("Tanggal"));

  const transactions = txs.map(function (t) {
    const row = mapWalletTx_(t, true);
    row.Nama = nameById[String(t.User_ID).trim()] || "";
    return row;
  }).sort(byNewestFirst_("Created_At")).slice(0, 300);

  return {
    members: members,
    settings: settings,
    withdrawals: withdrawals,
    rewards: rewardRows.slice(0, 300),
    transactions: transactions
  };
}

function handleAdminAdjustWallet_(ss, body, actor) {
  const userId = String(body.User_ID || "").trim();
  const arah = String(body.Arah || "").trim();
  const amount = Math.round(Number(body.Amount) || 0);
  const reason = String(body.Alasan || "").trim().slice(0, 300);
  if (!userId || isGuestUserId_(userId)) throw new Error("Pilih akun member yang valid.");
  if (arah !== "TAMBAH" && arah !== "KURANG") throw new Error("Arah koreksi harus TAMBAH atau KURANG.");
  if (!(amount > 0)) throw new Error("Nominal koreksi harus lebih dari 0.");
  if (reason.length < 5) throw new Error("Alasan koreksi wajib diisi (minimal 5 karakter).");
  const target = sheetToObjects_(ss, "Users").find(function (u) { return String(u.User_ID).trim() === userId; });
  if (!target) throw new Error("Akun member tidak ditemukan.");
  const actorId = String(actor.user.User_ID);
  applyWalletTx_(ss, userId, {
    type: arah === "TAMBAH" ? "ADJUST_IN" : "ADJUST_OUT",
    amount: amount,
    reference: "ADJ-" + shortUpper_(8),
    description: "Koreksi admin (" + actorId + "): " + reason,
    actor: actorId
  });
  return { status: "success", message: "Koreksi saldo berhasil dicatat dengan alasan." };
}

function handleAdminSaveSettings_(ss, body, actor) {
  const toInt = function (v, label) {
    const n = Math.round(Number(v));
    if (!Number.isFinite(n) || n < 0) throw new Error(label + " harus berupa angka 0 atau lebih.");
    return n;
  };
  const harga = toInt(body.HARGA_JUAL_PER_M2, "Harga jual per m²");
  const modal = toInt(body.MODAL_PER_M2, "Modal produksi per m²");
  const reward = toInt(body.REWARD_PER_M2, "Reward per m²");
  const minTarik = toInt(body.MIN_TARIK, "Minimal penarikan");
  if (modal >= harga) throw new Error("Modal per m² harus lebih kecil dari harga jual per m².");
  if (reward > harga - modal) {
    throw new Error("Reward per m² tidak boleh melebihi selisih harga jual dan modal (Rp " + formatIdrServer_(harga - modal) + ").");
  }
  const currentSettings = getSystemSettings_(ss);
  const aktif = body.PROGRAM_AKTIF === undefined
    ? (currentSettings.aktif ? "TRUE" : "FALSE")
    : ((body.PROGRAM_AKTIF === true || String(body.PROGRAM_AKTIF).trim().toUpperCase() === "TRUE") ? "TRUE" : "FALSE");
  const values = {
    HARGA_JUAL_PER_M2: harga,
    MODAL_PER_M2: modal,
    REWARD_PER_M2: reward,
    MIN_TARIK: minTarik,
    PROGRAM_AKTIF: aktif
  };
  const sheet = ss.getSheetByName("System_Settings");
  const headers = sheetHeaders_(ss, "System_Settings");
  const data = sheet.getDataRange().getValues();
  const colKey = headers.indexOf("Setting_Key");
  const actorId = String(actor.user.User_ID);
  Object.keys(values).forEach(function (key) {
    let found = -1;
    for (let r = 1; r < data.length; r++) {
      if (String(data[r][colKey]).trim() === key) { found = r + 1; break; }
    }
    if (found === -1) {
      appendObjectRow_(ss, "System_Settings", { Setting_Key: key, Setting_Value: values[key], Updated_At: nowStamp_(), Updated_By: actorId });
    } else {
      sheet.getRange(found, headers.indexOf("Setting_Value") + 1).setValue(values[key]);
      sheet.getRange(found, headers.indexOf("Updated_At") + 1).setValue(nowStamp_());
      sheet.getRange(found, headers.indexOf("Updated_By") + 1).setValue(actorId);
    }
  });
  return { status: "success", message: "Pengaturan reward disimpan. Berlaku untuk pesanan baru." };
}

function handleAdminAddExpense_(ss, body, actor) {
  const ket = String(body.Keterangan || "").trim().slice(0, 200);
  const jumlah = Math.round(Number(body.Jumlah) || 0);
  if (ket.length < 3) throw new Error("Keterangan biaya wajib diisi (minimal 3 karakter).");
  if (!(jumlah > 0)) throw new Error("Jumlah biaya harus lebih dari 0.");
  appendObjectRow_(ss, "Biaya_Tambahan", {
    Biaya_ID: "BIA-" + shortUpper_(8),
    Tanggal: nowStamp_(),
    Keterangan: ket,
    Jumlah: jumlah,
    Created_By: String(actor.user.User_ID)
  });
  return { status: "success", message: "Biaya tambahan dicatat." };
}

// Laporan keuangan. Omzet dihitung dari pesanan lunas (bukan dibatalkan).
// Keuntungan bisnis = omzet bersih − modal − reward; reward dihitung sekali saat diberikan.
function handleAdminFinancialReport_(ss, body) {
  const from = String(body.Dari || "").trim();
  const to = String(body.Sampai || "").trim();
  const memberId = String(body.User_ID || "").trim();
  const inRange = function (stamp) {
    const day = String(stamp || "").slice(0, 10);
    if (from && day < from) return false;
    if (to && day > to) return false;
    return true;
  };
  const orders = sheetToObjects_(ss, "Pesanan").filter(function (o) {
    if (String(o.Status_Order).trim() === "Diarsipkan") return false;
    if (String(o.Status_Bayar).trim() !== "Lunas") return false;
    if (memberId && String(o.User_ID).trim() !== memberId) return false;
    return inRange(o.Tanggal);
  });
  const orderMap = {};
  orders.forEach(function (o) { orderMap[String(o.Order_ID).trim()] = o; });

  let omzetKotor = 0, potonganSaldo = 0, omzetBersih = 0, rewardDiberikan = 0;
  orders.forEach(function (o) {
    const bersih = Number(o.Total_Tagihan) || 0;
    omzetKotor += Number(o.Harga_Kotor) || bersih;
    omzetBersih += bersih;
    potonganSaldo += Number(o.Saldo_Dipakai) || 0;
    const rs = String(o.Reward_Status || "").trim();
    if (rs === "Ditahan" || rs === "Dirilis") rewardDiberikan += Number(o.Reward_Amount) || 0;
  });

  // Modal hanya tersedia untuk produk berukuran m² (Dimensi). Produk satuan belum memiliki data modal.
  let modal = 0;
  sheetToObjects_(ss, "Detail_Pesanan").forEach(function (d) {
    const o = orderMap[String(d.Order_ID).trim()];
    if (!o) return;
    const luas = (Number(d.Panjang_m) || 0) * (Number(d.Lebar_m) || 0) * (Number(d.Qty) || 0);
    modal += luas * (Number(o.Modal_Per_M2) || 0);
  });
  modal = Math.round(modal);

  // Biaya tambahan & penarikan berhasil hanya ditampilkan untuk laporan seluruh member.
  let biayaTambahan = 0;
  if (!memberId) {
    biayaTambahan = sheetToObjects_(ss, "Biaya_Tambahan").reduce(function (a, b) {
      return inRange(b.Tanggal) ? a + (Number(b.Jumlah) || 0) : a;
    }, 0);
  }
  const penarikanBerhasil = sheetToObjects_(ss, "Wallet_Transactions").reduce(function (a, t) {
    if (t.Transaction_Type !== "WITHDRAW_PAID") return a;
    if (memberId && String(t.User_ID).trim() !== memberId) return a;
    return inRange(t.Created_At) ? a + (Number(t.Amount) || 0) : a;
  }, 0);

  const keuntunganBisnis = omzetBersih - modal - rewardDiberikan;
  const keuntunganBersih = keuntunganBisnis - biayaTambahan;

  const nameById = {};
  sheetToObjects_(ss, "Users").forEach(function (u) { nameById[String(u.User_ID).trim()] = String(u.Nama || ""); });

  return {
    status: "success",
    data: {
      periode: { dari: from, sampai: to },
      memberId: memberId,
      ringkasan: {
        jumlahPesanan: orders.length,
        omzetKotor: omzetKotor,
        potonganSaldo: potonganSaldo,
        omzetBersih: omzetBersih,
        modal: modal,
        rewardDiberikan: rewardDiberikan,
        keuntunganBisnis: keuntunganBisnis,
        biayaTambahan: biayaTambahan,
        keuntunganBersih: keuntunganBersih,
        penarikanBerhasil: penarikanBerhasil
      },
      pesanan: orders.slice(0, 500).map(function (o) {
        return {
          Order_ID: o.Order_ID,
          Tanggal: o.Tanggal,
          Nama: nameById[String(o.User_ID).trim()] || "",
          Total_Tagihan: Number(o.Total_Tagihan) || 0,
          Saldo_Dipakai: Number(o.Saldo_Dipakai) || 0,
          Reward_Amount: Number(o.Reward_Amount) || 0,
          Reward_Status: o.Reward_Status || ""
        };
      }).sort(byNewestFirst_("Tanggal"))
    }
  };
}

// ---------------------------------------------------------------------------
// DISPATCH (dipanggil dari doPost, sudah di dalam ScriptLock)
// ---------------------------------------------------------------------------
function handleMemberRewardAction_(ss, body, action) {
  const MEMBER_ACTIONS = [
    "getMemberDashboard", "saveMemberProfile", "requestWithdrawal",
    "adminGetMemberData", "adminAdjustWallet", "adminUpdateWithdrawal",
    "adminSaveRewardSettings", "adminAddExpense", "adminGetFinancialReport"
  ];
  if (MEMBER_ACTIONS.indexOf(action) === -1) return null;
  ensureMemberSheets_(ss);

  if (action === "getMemberDashboard" || action === "saveMemberProfile" || action === "requestWithdrawal") {
    const member = requireRole_(ss, body, ["User", "Admin", "Super Admin"]);
    if (isGuestUserId_(member.user.User_ID)) throw new Error("Fitur member hanya tersedia untuk akun terdaftar.");
    if (action === "getMemberDashboard") return jsonResponse_(handleGetMemberDashboard_(ss, member));
    if (action === "saveMemberProfile") {
      const profile = validateBankInput_(body);
      saveMemberProfile_(ss, member.user.User_ID, profile);
      return jsonResponse_({ status: "success", message: "Data rekening disimpan." });
    }
    return jsonResponse_(handleRequestWithdrawal_(ss, body, member));
  }

  const staff = requireRole_(ss, body, ["Admin", "Super Admin"]);
  if (action === "adminGetMemberData") return jsonResponse_({ status: "success", data: handleAdminGetMemberData_(ss) });
  if (action === "adminAdjustWallet") return jsonResponse_(handleAdminAdjustWallet_(ss, body, staff));
  if (action === "adminUpdateWithdrawal") return jsonResponse_(handleAdminUpdateWithdrawal_(ss, body, staff));
  if (action === "adminSaveRewardSettings") return jsonResponse_(handleAdminSaveSettings_(ss, body, staff));
  if (action === "adminAddExpense") return jsonResponse_(handleAdminAddExpense_(ss, body, staff));
  if (action === "adminGetFinancialReport") return jsonResponse_(handleAdminFinancialReport_(ss, body));
  return null;
}
