/**
 * ============================================================================
 * Wajibku Fast — Backend Google Apps Script (Code.gs) [Hardened]
 * ============================================================================
 * Petunjuk Setup:
 * 1. Pastikan SPREADSHEET_ID dan DRIVE_FOLDER_ID mengarah ke file/folder Anda.
 * 2. Jalankan fungsi `setupDatabaseSheets()` satu kali dari editor Apps Script
 *    untuk memastikan 5 tab wajib tersedia & meng-hash password plaintext lama.
 *    (Cek Execution Log untuk password sementara jika baru membuat akun awal,
 *    lalu ubah kata sandi melalui menu Akses Pengguna atau Apps Script.)
 * 3. Klik Deploy > Manage deployments > Edit > Version: New version
 *    - Execute as: Me (Email Anda)
 *    - Who has access: Anyone
 * ============================================================================
 */

const SPREADSHEET_ID = "1aJjDWtT3qMEm891oXI1FyKg4SaXGS1EV-kBjnPWXyDc";
const DRIVE_FOLDER_ID = "1rtEXH6wI0sm5tH4shNBXMUAuQ2mwzUDs";
const DRIVE_FOLDER_URL = "https://drive.google.com/drive/folders/1rtEXH6wI0sm5tH4shNBXMUAuQ2mwzUDs?usp=sharing";
const DATABASE_FILE_NAME = "WajibkuFast_Database";
const DRIVE_FOLDER_NAME = "WajibkuFast_Upload_Files";

const TOKEN_TTL_SECONDS = 12 * 60 * 60; // 12 jam
const HASH_ITERATIONS = 100;
const ALLOWED_ORDER_STATUS = ["Menunggu Bayar", "Diproses", "Selesai", "Diambil"];
const ALLOWED_PAY_STATUS = ["Belum Bayar", "Menunggu Verifikasi", "Lunas"];
const ALLOWED_USER_ROLES = ["User", "Admin", "Super Admin"];

/**
 * Definisi Header 5 Tab Wajib (Case-Sensitive)
 */
const SCHEMA_HEADERS = {
  Users: ["User_ID", "Nama", "No_WA", "Email", "Role", "Alamat", "Password"],
  Produk: ["Produk_ID", "Nama_Produk", "Kategori", "Tipe_Hitung", "Harga_Dasar", "Satuan", "Min_Order", "Status"],
  Finishing: ["Finishing_ID", "Nama_Finishing", "Tipe_Biaya", "Tambahan_Harga", "Keterangan"],
  Pesanan: ["Order_ID", "Tanggal", "User_ID", "Status_Order", "Total_Tagihan", "Bukti_Bayar", "Status_Bayar", "Catatan"],
  Detail_Pesanan: ["Detail_ID", "Order_ID", "Produk_ID", "Panjang_m", "Lebar_m", "Qty", "Finishing_ID", "File_Desain", "Keterangan_Item", "Subtotal"]
};

// ============================================================================
// UTILITAS KEAMANAN, HASHING PASSWORD, & HMAC TOKEN
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

function bytesToHex_(bytes) {
  return bytes.map(function (b) {
    const unsigned = b < 0 ? b + 256 : b;
    return ("0" + unsigned.toString(16)).slice(-2);
  }).join("");
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

function hashPassword_(plainPassword, saltOpt) {
  const plain = String(plainPassword || "");
  if (!plain) return "";
  const salt = saltOpt || Utilities.getUuid().replace(/-/g, "").slice(0, 16);
  let digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, salt + ":" + plain);
  for (let i = 1; i < HASH_ITERATIONS; i++) {
    digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytesToHex_(digest) + ":" + salt);
  }
  return "sha256$" + salt + "$" + bytesToHex_(digest);
}

function verifyPassword_(plainPassword, storedPassword) {
  const plain = String(plainPassword || "");
  const stored = String(storedPassword || "").trim();
  if (!plain || !stored) {
    return { valid: false, needsUpgrade: false };
  }
  if (stored.startsWith("sha256$")) {
    const parts = stored.split("$");
    if (parts.length !== 3 || !parts[1] || !parts[2]) {
      return { valid: false, needsUpgrade: false };
    }
    const expectedHash = hashPassword_(plain, parts[1]);
    return { valid: constantTimeEqual_(expectedHash, stored), needsUpgrade: false };
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

function getOrCreateOwnerRecoveryKey_() {
  const props = PropertiesService.getScriptProperties();
  let key = props.getProperty("OWNER_RECOVERY_KEY");
  if (!key || key.length < 12) {
    key = "WF-KEY-" + Utilities.getUuid().replace(/-/g, "").slice(0, 12).toUpperCase();
    props.setProperty("OWNER_RECOVERY_KEY", key);
  }
  return key;
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

  const liveRole = normalizeRole_(liveUser.Role);
  if (allowedRoles && allowedRoles.indexOf(liveRole) === -1) {
    throw new Error("Akses ditolak: Anda tidak memiliki izin (" + liveRole + ").");
  }

  return { session: session, user: liveUser, role: liveRole };
}

function generateUniqueOrderId_(existingOrders) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const datePart = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyMMdd");
  const existingSet = {};
  (existingOrders || []).forEach(function (o) {
    existingSet[String(o.Order_ID || "").trim().toUpperCase()] = true;
  });

  for (let attempt = 0; attempt < 25; attempt++) {
    let suffix = "";
    for (let i = 0; i < 6; i++) {
      suffix += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    const candidate = "ORD-" + datePart + "-" + suffix;
    if (!existingSet[candidate]) {
      return candidate;
    }
  }
  return "ORD-" + datePart + "-" + String(Date.now()).slice(-6);
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
  return {
    Produk_ID: String(p.Produk_ID || "").trim(),
    Nama_Produk: String(p.Nama_Produk || "").trim(),
    Kategori: String(p.Kategori || "").trim() || "Umum",
    Tipe_Hitung: rawTipe === "dimensi" ? "Dimensi" : "Unit",
    Harga_Dasar: Math.max(0, Math.round(parseSheetNumber_(p.Harga_Dasar))),
    Satuan: String(p.Satuan || "").trim() || "Unit",
    Min_Order: minOrd >= 1 ? minOrd : 1,
    Status: rawStatus === "habis" ? "Habis" : "Tersedia"
  };
}

function normalizeFinishingRow_(f) {
  const rawTipe = String(f.Tipe_Biaya || "").trim().toLowerCase();
  return {
    Finishing_ID: String(f.Finishing_ID || "").trim(),
    Nama_Finishing: String(f.Nama_Finishing || "").trim(),
    Tipe_Biaya: rawTipe === "per_qty" || rawTipe === "per qty" ? "Per_Qty" : "Tetap",
    Tambahan_Harga: Math.max(0, Math.round(parseSheetNumber_(f.Tambahan_Harga))),
    Keterangan: String(f.Keterangan || "").trim()
  };
}

// ============================================================================
// GOOGLE DRIVE & SPREADSHEET ACCESS
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

    const newSs = SpreadsheetApp.create(DATABASE_FILE_NAME);
    const newFile = DriveApp.getFileById(newSs.getId());
    newFile.moveTo(dbFolder);
    props.setProperty("DB_SPREADSHEET_ID", newSs.getId());
    return newSs;
  }

  const active = SpreadsheetApp.getActiveSpreadsheet();
  if (active) {
    return active;
  }

  throw new Error("Spreadsheet dan Folder Drive tidak ditemukan.");
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

/**
 * Menyimpan string Base64 (Data URL) ke Google Drive secara PRIVAT (tanpa ANYONE_WITH_LINK)
 */
function saveBase64ToDrive_(base64Data, fileNamePrefix, originalName) {
  if (!base64Data || typeof base64Data !== "string") return "";
  if (!base64Data.startsWith("data:")) {
    // Hanya terima nama file teks aman, tolak skema URL berbahaya
    const safeText = String(base64Data).trim().slice(0, 150);
    if (/^(javascript:|vbscript:|data:)/i.test(safeText)) return "";
    return safeText;
  }

  try {
    const parts = base64Data.split(",");
    if (parts.length < 2) return "";
    const header = parts[0];
    const encoded = parts[1];
    const mimeMatch = header.match(/^data:([^;]+);base64$/i);
    if (!mimeMatch) return "";
    const mimeType = mimeMatch[1];

    const decodedBytes = Utilities.base64Decode(encoded);
    if (decodedBytes.length > 3 * 1024 * 1024) {
      throw new Error("Ukuran file melebihi batas server (maks. 2.5 MB).");
    }

    const cleanOrig = String(originalName || "upload_file").replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 80);
    const safeName = (fileNamePrefix ? fileNamePrefix + "_" : "") + cleanOrig;
    const blob = Utilities.newBlob(decodedBytes, mimeType, safeName);

    const folder = getOrCreateUploadFolder_();
    const file = folder.createFile(blob);
    // File tetap privat (hanya pemilik akun Drive / Admin internal yang memiliki akses)
    return file.getUrl();
  } catch (err) {
    Logger.log("Gagal simpan file ke Drive: " + err.message);
    return "";
  }
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

function updateUserPasswordCell_(ss, userId, hashedPassword) {
  const sheet = ss.getSheetByName("Users");
  if (!sheet) return;
  const values = sheet.getDataRange().getValues();
  if (values.length < 2) return;
  const headers = values[0].map(function (h) { return String(h).trim(); });
  const colId = headers.indexOf("User_ID");
  const colPass = headers.indexOf("Password");
  if (colId === -1 || colPass === -1) return;

  for (let r = 1; r < values.length; r++) {
    if (String(values[r][colId]).trim() === String(userId).trim()) {
      sheet.getRange(r + 1, colPass + 1).setValue(hashedPassword);
      break;
    }
  }
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
    if (rawPass && !rawPass.startsWith("sha256$")) {
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

// ============================================================================
// INISIALISASI 5 TAB SHEET & SEEDING AMAN
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
            Keterangan: "Potong keliling standar"
          },
          {
            Finishing_ID: "FIN-001",
            Nama_Finishing: "Mata Ayam",
            Tipe_Biaya: "Per_Qty",
            Tambahan_Harga: 2000,
            Keterangan: "Lubang ring besi 4 sudut per pcs"
          },
          {
            Finishing_ID: "FIN-002",
            Nama_Finishing: "Laminasi",
            Tipe_Biaya: "Per_Qty",
            Tambahan_Harga: 3000,
            Keterangan: "Laminasi Doff / Glossy per pcs"
          },
          {
            Finishing_ID: "FIN-003",
            Nama_Finishing: "Cutting Pola",
            Tipe_Biaya: "Tetap",
            Tambahan_Harga: 4000,
            Keterangan: "Biaya potong pola khusus per item"
          }
        ];
        seedFinishing.forEach(function (f) { appendObjectRow_(ss, "Finishing", f); });
      }
    }
  });

  // Pastikan minimal ada 1 akun Super Admin dengan password ter-hash
  const existingUsersList = sheetToObjects_(ss, "Users");
  const hasSuperAdmin = existingUsersList.some(function (u) {
    return normalizeRole_(u.Role) === "Super Admin";
  });
  if (!hasSuperAdmin) {
    const initialSuperPass = "123456";
    appendObjectRow_(ss, "Users", {
      User_ID: "SUP-001",
      Nama: "Super Admin Wajibku Fast",
      No_WA: "'6281100009999",
      Email: "superadmin@wajibkufast.id",
      Role: "Super Admin",
      Alamat: "Kantor Pusat",
      Password: hashPassword_(initialSuperPass)
    });
    Logger.log("SUPER ADMIN AWAL DIBUAT -> Email: superadmin@wajibkufast.id | Password: " + initialSuperPass);
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
    spreadsheetUrl: ss.getUrl(),
    driveFolderUrl: DRIVE_FOLDER_URL
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
  const recoveryKey = getOrCreateOwnerRecoveryKey_();
  result.migratedPlaintextPasswords = migrated;
  Logger.log("KODE PEMULIHAN PEMILIK (Simpan Rahasia untuk Reset Admin/Super Admin di Web): " + recoveryKey);
  Logger.log("Setup Database Selesai: " + JSON.stringify(result));
  return result;
}

function resetSuperAdminAccess(customPassword) {
  const ss = getSpreadsheet_();
  ensureSheetsInitialized_(ss);
  const users = sheetToObjects_(ss, "Users");
  const superAdmin = users.find(function (u) {
    return normalizeRole_(u.Role) === "Super Admin";
  });
  const newPass = (typeof customPassword === "string" && customPassword.trim().length >= 6)
    ? customPassword.trim()
    : "123456";
  const recoveryKey = getOrCreateOwnerRecoveryKey_();

  if (superAdmin) {
    updateUserPasswordCell_(ss, superAdmin.User_ID, hashPassword_(newPass));
    Logger.log("RESET SUPER ADMIN BERHASIL -> User_ID: " + superAdmin.User_ID + " | Email: " + superAdmin.Email + " | Password Baru: " + newPass);
  } else {
    appendObjectRow_(ss, "Users", {
      User_ID: "SUP-001",
      Nama: "Super Admin Wajibku Fast",
      No_WA: "'6281100009999",
      Email: "superadmin@wajibkufast.id",
      Role: "Super Admin",
      Alamat: "Kantor Pusat",
      Password: hashPassword_(newPass)
    });
    Logger.log("AKUN SUPER ADMIN DIBUAT -> User_ID: SUP-001 | Email: superadmin@wajibkufast.id | Password Baru: " + newPass);
  }
  Logger.log("KODE PEMULIHAN PEMILIK (OWNER RECOVERY KEY): " + recoveryKey);
  return {
    email: superAdmin ? superAdmin.Email : "superadmin@wajibkufast.id",
    userId: superAdmin ? superAdmin.User_ID : "SUP-001",
    recoveryKeyConfigured: true
  };
}

function migratePasswordsToHash() {
  const ss = getSpreadsheet_();
  const migrated = migratePlaintextPasswords_(ss);
  Logger.log("Password plaintext yang di-hash: " + migrated);
  return migrated;
}

function buatDatabaseBaru_() {
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
  Logger.log("Database Baru Dibuat: " + newSs.getUrl());
  return initResult;
}

// ============================================================================
// HTTP GET (HANYA DATA KATALOG PUBLIK: Produk & Finishing)
// ============================================================================

function doGet(e) {
  try {
    const action = (e && e.parameter && e.parameter.action) ? e.parameter.action : "getInitData";

    if (action === "getInitData") {
      const ss = getSpreadsheet_();
      if (!ss.getSheetByName("Produk") || !ss.getSheetByName("Finishing") || !ss.getSheetByName("Users")) {
        ensureSheetsInitialized_(ss);
      }
      // Hanya kirim katalog publik; JANGAN PERNAH kirim Users, Password, Pesanan, atau Detail_Pesanan secara publik
      return jsonResponse_({
        status: "success",
        data: {
          produk: sheetToObjects_(ss, "Produk").map(normalizeProductRow_).filter(function (p) { return Boolean(p.Produk_ID); }),
          finishing: sheetToObjects_(ss, "Finishing").map(normalizeFinishingRow_).filter(function (f) { return Boolean(f.Finishing_ID); })
        },
        meta: {
          driveFolderUrl: DRIVE_FOLDER_URL
        }
      });
    }

    return jsonResponse_({ status: "error", message: "Action GET tidak diizinkan atau tidak dikenal." });
  } catch (err) {
    return jsonResponse_({ status: "error", message: err.message });
  }
}

// ============================================================================
// HTTP POST (AUTENTIKASI, PELANGGAN, & OPERASI ADMIN TERPROTEKSI)
// ============================================================================

function doPost(e) {
  const lock = LockService.getScriptLock();
  try {
    lock.waitLock(15000);
    const body = JSON.parse(e.postData.contents);
    const action = body.action;
    const ss = getSpreadsheet_();
    if (!ss.getSheetByName("Pesanan") || !ss.getSheetByName("Detail_Pesanan") || !ss.getSheetByName("Users") || !ss.getSheetByName("Produk") || !ss.getSheetByName("Finishing")) {
      ensureSheetsInitialized_(ss);
    }

    // ------------------------------------------------------------------------
    // 1. LOGIN SERVER-SIDE -> Mengembalikan Token HMAC & Profil Tanpa Password
    // ------------------------------------------------------------------------
    if (action === "login") {
      const identifierRaw = String(body.identifier || "").trim();
      const identifier = identifierRaw.toLowerCase();
      const normIdentifierWa = normalizeWa_(identifierRaw);
      const password = String(body.password || "");

      if (!identifier || !password) {
        return jsonResponse_({ status: "error", message: "Email/WhatsApp dan kata sandi wajib diisi." });
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
        return jsonResponse_({ status: "error", message: "Email/No. WhatsApp atau kata sandi salah." });
      }

      const storedPass = String(matched.Password || "").trim();
      if (!storedPass) {
        return jsonResponse_({
          status: "error",
          message: "Akun checkout tamu ini belum memiliki kata sandi. Silakan daftar member baru atau hubungi Admin untuk mengaktifkan akun."
        });
      }

      const passCheck = verifyPassword_(password, storedPass);
      if (!passCheck.valid) {
        return jsonResponse_({ status: "error", message: "Email/No. WhatsApp atau kata sandi salah." });
      }

      if (passCheck.needsUpgrade) {
        updateUserPasswordCell_(ss, matched.User_ID, hashPassword_(password));
      }

      const token = createToken_(matched);
      return jsonResponse_({
        status: "success",
        message: "Login berhasil.",
        data: {
          token: token,
          user: sanitizeUser_(matched)
        }
      });
    }

    // ------------------------------------------------------------------------
    // 2. REGISTER MEMBER (Pendaftaran Mandiri -> Role: "User", Password Di-Hash)
    // ------------------------------------------------------------------------
    if (action === "registerMember") {
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
      if (password.length < 6) {
        return jsonResponse_({
          status: "error",
          message: "Kata sandi minimal 6 karakter."
        });
      }

      const existingUsers = sheetToObjects_(ss, "Users");
      const duplicate = existingUsers.find(function (u) {
        const uEmail = String(u.Email || "").trim().toLowerCase();
        const uNormWa = normalizeWa_(u.No_WA);
        return (uEmail && uEmail === email) || (uNormWa && uNormWa === normWa);
      });

      if (duplicate) {
        return jsonResponse_({
          status: "error",
          message: "Email atau Nomor WhatsApp sudah terdaftar. Silakan masuk atau hubungi Admin."
        });
      }

      const newUserId = "USR-" + String(existingUsers.length + 1).padStart(3, "0") + "-" + Date.now().toString().slice(-4);
      const newMember = {
        User_ID: newUserId,
        Nama: nama,
        No_WA: "'" + normWa,
        Email: email,
        Role: "User", // Paksa Role = User
        Alamat: alamat,
        Password: hashPassword_(password)
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
    // 2B. LUPA PASSWORD MANDIRI
    //     - Pelanggan (User): Nama + Email cocok
    //     - Admin / Super Admin: Email/User_ID cocok + Kode Pemulihan Pemilik valid
    // ------------------------------------------------------------------------
    if (action === "forgotPassword") {
      const accountType = String(body.accountType || "User").trim().toLowerCase();
      const nama = String(body.Nama || body.nama || "").trim();
      const emailOrId = String(body.Email || body.email || body.identifier || "").trim().toLowerCase();
      const newPassword = String(body.Password || body.newPassword || "");
      const recoveryKey = String(body.recoveryKey || body.Kode_Pemulihan || "").trim();

      if (newPassword.length < 6) {
        return jsonResponse_({
          status: "error",
          message: "Kata sandi baru minimal 6 karakter."
        });
      }

      const existingUsers = sheetToObjects_(ss, "Users");

      if (accountType === "admin" || recoveryKey) {
        if (!emailOrId) {
          return jsonResponse_({
            status: "error",
            message: "Email atau User_ID Admin/Super Admin wajib diisi."
          });
        }
        if (!recoveryKey) {
          return jsonResponse_({
            status: "error",
            message: "Kode Pemulihan Pemilik wajib diisi untuk mereset Admin / Super Admin."
          });
        }
        const expectedKey = getOrCreateOwnerRecoveryKey_();
        if (!constantTimeEqual_(recoveryKey, expectedKey)) {
          return jsonResponse_({
            status: "error",
            message: "Kode Pemulihan Pemilik tidak cocok. Solusi: cek Execution Log Apps Script setelah menjalankan resetSuperAdminAccess(), atau ubah sel Password langsung di tab Users Google Sheets lalu login."
          });
        }

        const matchedAdmin = existingUsers.find(function (u) {
          const uEmail = String(u.Email || "").trim().toLowerCase();
          const uId = String(u.User_ID || "").trim().toLowerCase();
          return (uEmail && uEmail === emailOrId) || (uId && uId === emailOrId);
        });
        if (!matchedAdmin) {
          return jsonResponse_({
            status: "error",
            message: "Akun dengan Email / User_ID tersebut tidak ditemukan di sheet Users."
          });
        }

        updateUserPasswordCell_(ss, matchedAdmin.User_ID, hashPassword_(newPassword));
        return jsonResponse_({
          status: "success",
          message: "Kata sandi " + normalizeRole_(matchedAdmin.Role) + " (" + matchedAdmin.Email + ") berhasil diperbarui. Silakan masuk."
        });
      }

      if (!nama || !emailOrId || emailOrId.indexOf("@") === -1) {
        return jsonResponse_({
          status: "error",
          message: "Nama lengkap dan Email terdaftar wajib diisi."
        });
      }

      const matched = existingUsers.find(function (u) {
        const uNama = String(u.Nama || "").trim().toLowerCase();
        const uEmail = String(u.Email || "").trim().toLowerCase();
        return Boolean(uEmail && uEmail === emailOrId && uNama && uNama === nama.toLowerCase());
      });

      if (!matched) {
        return jsonResponse_({
          status: "error",
          message: "Nama dan Email tidak cocok dengan akun terdaftar."
        });
      }

      const roleNorm = normalizeRole_(matched.Role);
      if (roleNorm !== "User") {
        return jsonResponse_({
          status: "error",
          message: "Akun " + roleNorm + " memerlukan Kode Pemulihan Pemilik. Pilih opsi 'Admin / Super Admin' pada tab Lupa Sandi."
        });
      }

      updateUserPasswordCell_(ss, matched.User_ID, hashPassword_(newPassword));
      return jsonResponse_({
        status: "success",
        message: "Kata sandi berhasil diperbarui. Silakan masuk dengan kata sandi baru Anda."
      });
    }

    // ------------------------------------------------------------------------
    // 3. TRACK ORDER PUBLIK TERPROTEKSI (Wajib Order_ID persis + 4 digit WA)
    // ------------------------------------------------------------------------
    if (action === "trackOrder") {
      const reqOrderId = String(body.orderId || "").trim().toUpperCase();
      const reqWaLast4 = String(body.waLast4 || "").replace(/\D/g, "");

      if (!reqOrderId || !/^\d{4}$/.test(reqWaLast4)) {
        return jsonResponse_({
          status: "error",
          message: "Masukkan ID Pesanan lengkap dan 4 digit terakhir Nomor WhatsApp."
        });
      }

      const allOrders = sheetToObjects_(ss, "Pesanan");
      const order = allOrders.find(function (o) {
        return String(o.Order_ID || "").trim().toUpperCase() === reqOrderId;
      });
      if (!order) {
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
        return jsonResponse_({
          status: "error",
          message: "Pesanan tidak ditemukan atau 4 digit terakhir WhatsApp tidak cocok."
        });
      }

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
    // 4. GET MY ORDERS (Riwayat Pesanan Khusus Member yang Login)
    // ------------------------------------------------------------------------
    if (action === "getMyOrders") {
      const auth = requireRole_(ss, body, ["User", "Admin", "Super Admin"]);
      const myOrders = sheetToObjects_(ss, "Pesanan").filter(function (o) {
        return String(o.User_ID || "").trim() === String(auth.session.uid).trim();
      });
      const myOrderIds = {};
      myOrders.forEach(function (o) {
        myOrderIds[String(o.Order_ID || "").trim()] = true;
      });
      const myDetails = sheetToObjects_(ss, "Detail_Pesanan").filter(function (d) {
        return Boolean(myOrderIds[String(d.Order_ID || "").trim()]);
      });
      return jsonResponse_({
        status: "success",
        data: {
          user: sanitizeUser_(auth.user),
          pesanan: myOrders,
          detail_pesanan: myDetails
        }
      });
    }

    // ------------------------------------------------------------------------
    // 5. ADMIN GET DATA (Terproteksi Admin / Super Admin, Tanpa Password)
    // ------------------------------------------------------------------------
    if (action === "adminGetData") {
      const auth = requireRole_(ss, body, ["Admin", "Super Admin"]);
      const users = sheetToObjects_(ss, "Users").map(sanitizeUser_);
      const metaObj = {
        spreadsheetUrl: ss.getUrl(),
        driveFolderUrl: DRIVE_FOLDER_URL,
        role: auth.role
      };
      if (auth.role === "Super Admin") {
        metaObj.ownerRecoveryKey = getOrCreateOwnerRecoveryKey_();
      }
      return jsonResponse_({
        status: "success",
        data: {
          users: users,
          produk: sheetToObjects_(ss, "Produk").map(normalizeProductRow_).filter(function (p) { return Boolean(p.Produk_ID); }),
          finishing: sheetToObjects_(ss, "Finishing").map(normalizeFinishingRow_).filter(function (f) { return Boolean(f.Finishing_ID); }),
          pesanan: sheetToObjects_(ss, "Pesanan"),
          detail_pesanan: sheetToObjects_(ss, "Detail_Pesanan")
        },
        meta: metaObj
      });
    }

    if (action === "regenerateOwnerRecoveryKey") {
      requireRole_(ss, body, ["Super Admin"]);
      const props = PropertiesService.getScriptProperties();
      const nextKey = "WF-KEY-" + Utilities.getUuid().replace(/-/g, "").slice(0, 12).toUpperCase();
      props.setProperty("OWNER_RECOVERY_KEY", nextKey);
      return jsonResponse_({
        status: "success",
        message: "Kode Pemulihan Pemilik baru berhasil dibuat.",
        data: { ownerRecoveryKey: nextKey }
      });
    }

    // ------------------------------------------------------------------------
    // 6. CREATE ORDER (Kalkulasi Harga & Pembuatan Order_ID di Server)
    // ------------------------------------------------------------------------
    if (action === "createOrder") {
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

      // Bangun lookup Produk & Finishing dari database server (abaikan harga dari klien)
      const produkList = sheetToObjects_(ss, "Produk").map(normalizeProductRow_);
      const finishingList = sheetToObjects_(ss, "Finishing").map(normalizeFinishingRow_);
      const produkMap = {};
      produkList.forEach(function (p) { if (p.Produk_ID) produkMap[p.Produk_ID] = p; });
      const finishingMap = {};
      finishingList.forEach(function (f) { if (f.Finishing_ID) finishingMap[f.Finishing_ID] = f; });

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
        if (finId && !finishingMap[finId] && finId !== "FIN-000") {
          return jsonResponse_({
            status: "error",
            message: "Opsi finishing tidak ditemukan: " + finId
          });
        }

        const hargaDasar = Number(prod.Harga_Dasar) || 0;
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

      // Identifikasi / Buat User (JANGAN pernah menyimpan atau menimpa Password dari checkout)
      let authSession = body.token ? verifyToken_(String(body.token)) : null;
      const existingUsers = sheetToObjects_(ss, "Users");
      let userId = "";
      let matchedUser = null;

      if (authSession) {
        matchedUser = existingUsers.find(function (u) {
          return String(u.User_ID || "").trim() === String(authSession.uid).trim();
        });
      }
      if (!matchedUser) {
        matchedUser = existingUsers.find(function (u) {
          const uWa = normalizeWa_(u.No_WA);
          const uEmail = String(u.Email || "").trim().toLowerCase();
          return (reqNormWa && uWa === reqNormWa) || (reqEmail && uEmail === reqEmail);
        });
      }

      if (matchedUser) {
        userId = String(matchedUser.User_ID);
      } else {
        userId = "USR-" + String(existingUsers.length + 1).padStart(3, "0") + "-" + Date.now().toString().slice(-4);
        appendObjectRow_(ss, "Users", {
          User_ID: userId,
          Nama: namaPelanggan,
          No_WA: "'" + reqNormWa,
          Email: reqEmail,
          Role: "User",
          Alamat: reqAlamat,
          Password: "" // Tamu tanpa password tidak diizinkan login
        });
      }

      const existingOrders = sheetToObjects_(ss, "Pesanan");
      const orderId = generateUniqueOrderId_(existingOrders);
      const tanggal = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyyy-MM-dd HH:mm");

      let buktiBayarUrl = "";
      if (orderPayload.Bukti_Bayar) {
        buktiBayarUrl = saveBase64ToDrive_(
          orderPayload.Bukti_Bayar,
          orderId + "_BUKTI",
          orderPayload.Bukti_Bayar_Name || "bukti_bayar.jpg"
        );
      }

      const savedOrder = {
        Order_ID: orderId,
        Tanggal: tanggal,
        User_ID: userId,
        Status_Order: "Menunggu Bayar",
        Total_Tagihan: serverTotal,
        Bukti_Bayar: buktiBayarUrl,
        Status_Bayar: buktiBayarUrl ? "Menunggu Verifikasi" : "Belum Bayar",
        Catatan: String(orderPayload.Catatan || "").slice(0, 500)
      };
      appendObjectRow_(ss, "Pesanan", savedOrder);

      const savedDetails = [];
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

        const detailRow = {
          Detail_ID: detailId,
          Order_ID: orderId,
          Produk_ID: item.Produk_ID,
          Panjang_m: item.Panjang_m,
          Lebar_m: item.Lebar_m,
          Qty: item.Qty,
          Finishing_ID: item.Finishing_ID,
          File_Desain: fileDesainUrl,
          Keterangan_Item: item.Keterangan_Item,
          Subtotal: item.Subtotal
        };
        appendObjectRow_(ss, "Detail_Pesanan", detailRow);
        savedDetails.push(detailRow);
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
          pesanan: savedOrder,
          detail_pesanan: savedDetails
        }
      });
    }

    // ------------------------------------------------------------------------
    // 7. UPDATE STATUS (Hanya Admin / Super Admin)
    // ------------------------------------------------------------------------
    if (action === "updateStatus") {
      requireRole_(ss, body, ["Admin", "Super Admin"]);
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
      if (!sheet) throw new Error("Sheet Pesanan tidak ditemukan.");
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
      return jsonResponse_({ status: "success", message: "Status pesanan diperbarui." });
    }

    // ------------------------------------------------------------------------
    // 8. SAVE PRODUCT (Hanya Admin / Super Admin)
    // ------------------------------------------------------------------------
    if (action === "saveProduct") {
      requireRole_(ss, body, ["Admin", "Super Admin"]);
      const prod = body.produk || body;
      const sheet = ss.getSheetByName("Produk");
      if (!sheet) throw new Error("Sheet Produk tidak ditemukan.");

      const prodId = String(prod.Produk_ID || "").trim() || ("PRD-" + Date.now().toString().slice(-4));
      const hargaDasar = Math.round(parseSheetNumber_(prod.Harga_Dasar));
      const minOrder = Math.floor(parseSheetNumber_(prod.Min_Order));
      const tipeHitung = String(prod.Tipe_Hitung || "").trim().toLowerCase() === "dimensi" ? "Dimensi" : "Unit";
      const statusProd = String(prod.Status || "").trim().toLowerCase() === "habis" ? "Habis" : "Tersedia";

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

      const productData = {
        Produk_ID: prodId,
        Nama_Produk: String(prod.Nama_Produk || "").trim(),
        Kategori: String(prod.Kategori || "").trim(),
        Tipe_Hitung: tipeHitung,
        Harga_Dasar: hargaDasar,
        Satuan: String(prod.Satuan || "").trim(),
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
    // 9. SAVE FINISHING (Hanya Admin / Super Admin)
    // ------------------------------------------------------------------------
    if (action === "saveFinishing") {
      requireRole_(ss, body, ["Admin", "Super Admin"]);
      const fin = body.finishing || body;
      const sheet = ss.getSheetByName("Finishing");
      if (!sheet) throw new Error("Sheet Finishing tidak ditemukan.");

      const finId = String(fin.Finishing_ID || "").trim() || ("FIN-" + Date.now().toString().slice(-4));
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

      const finData = {
        Finishing_ID: finId,
        Nama_Finishing: String(fin.Nama_Finishing || "").trim(),
        Tipe_Biaya: fin.Tipe_Biaya === "Per_Qty" ? "Per_Qty" : "Tetap",
        Tambahan_Harga: tambahanHarga,
        Keterangan: String(fin.Keterangan || "").trim()
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
    // 10. SAVE USER (Hanya Super Admin, Password Di-Hash & Tidak Dikembalikan)
    // ------------------------------------------------------------------------
    if (action === "saveUser") {
      requireRole_(ss, body, ["Super Admin"]);
      const usr = body.user || body;
      const sheet = ss.getSheetByName("Users");
      if (!sheet) throw new Error("Sheet Users tidak ditemukan.");

      const userId = String(usr.User_ID || "").trim() || ("USR-" + Date.now().toString().slice(-4));
      const roleVal = normalizeRole_(usr.Role);
      if (ALLOWED_USER_ROLES.indexOf(roleVal) === -1) {
        return jsonResponse_({ status: "error", message: "Role tidak valid." });
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

      const rawPassword = String(usr.Password || "").trim();
      if (rowIndex === -1 && rawPassword.length < 6) {
        return jsonResponse_({ status: "error", message: "Akun baru wajib memiliki kata sandi minimal 6 karakter." });
      }
      if (rowIndex > 0 && rawPassword && !rawPassword.startsWith("sha256$") && rawPassword.length < 6) {
        return jsonResponse_({ status: "error", message: "Kata sandi baru minimal 6 karakter." });
      }

      const hashedPass = rawPassword
        ? (rawPassword.startsWith("sha256$") ? rawPassword : hashPassword_(rawPassword))
        : "";
      const normWa = normalizeWa_(usr.No_WA);

      const userData = {
        User_ID: userId,
        Nama: String(usr.Nama || "").trim(),
        No_WA: normWa ? ("'" + normWa) : ("'" + String(usr.No_WA || "").replace(/^'/, "")),
        Email: String(usr.Email || "").trim().toLowerCase(),
        Role: roleVal,
        Alamat: String(usr.Alamat || "").trim(),
        Password: hashedPass
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

      return jsonResponse_({
        status: "success",
        message: rowIndex > 0 ? "Data pengguna diperbarui" : "Pengguna ditambahkan",
        data: sanitizeUser_(userData)
      });
    }

    // ------------------------------------------------------------------------
    // 11. DELETE RECORD (Admin: Produk/Finishing/Pesanan; Super Admin: + Users)
    // ------------------------------------------------------------------------
    if (action === "deleteRecord") {
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

      const allowed = sheetName === "Users" ? ["Super Admin"] : ["Admin", "Super Admin"];
      const auth = requireRole_(ss, body, allowed);
      if (sheetName === "Users" && recordId === String(auth.session.uid).trim()) {
        return jsonResponse_({ status: "error", message: "Akun yang sedang aktif login tidak dapat dihapus." });
      }

      const sheet = ss.getSheetByName(sheetName);
      if (!sheet) throw new Error("Sheet '" + sheetName + "' tidak ditemukan.");

      const values = sheet.getDataRange().getValues();
      const headers = values[0].map(function (h) { return String(h).trim(); });
      const colIdx = headers.indexOf(idColName);
      if (colIdx === -1) throw new Error("Kolom '" + idColName + "' tidak ditemukan.");

      let deletedCount = 0;
      for (let r = values.length - 1; r >= 1; r--) {
        if (String(values[r][colIdx]).trim() === recordId) {
          sheet.deleteRow(r + 1);
          deletedCount++;
        }
      }

      if (sheetName === "Pesanan") {
        const detailSheet = ss.getSheetByName("Detail_Pesanan");
        if (detailSheet) {
          const dValues = detailSheet.getDataRange().getValues();
          if (dValues.length > 1) {
            const dHeaders = dValues[0].map(function (h) { return String(h).trim(); });
            const dColOrderId = dHeaders.indexOf("Order_ID");
            if (dColOrderId !== -1) {
              for (let dr = dValues.length - 1; dr >= 1; dr--) {
                if (String(dValues[dr][dColOrderId]).trim() === recordId) {
                  detailSheet.deleteRow(dr + 1);
                }
              }
            }
          }
        }
      }

      return jsonResponse_({
        status: "success",
        message: "Data berhasil dihapus (" + deletedCount + " baris).",
        deletedCount: deletedCount
      });
    }

    // ------------------------------------------------------------------------
    // 12. INIT SHEETS & CREATE NEW DATABASE (Hanya Super Admin)
    // ------------------------------------------------------------------------
    if (action === "initSheets") {
      requireRole_(ss, body, ["Super Admin"]);
      const initResult = ensureSheetsInitialized_(ss);
      const migrated = migratePlaintextPasswords_(ss);
      initResult.migratedPlaintextPasswords = migrated;
      return jsonResponse_({
        status: "success",
        message: "Inisialisasi 5 tab & hash password selesai.",
        data: initResult
      });
    }

    if (action === "createNewDatabase") {
      requireRole_(ss, body, ["Super Admin"]);
      const createdResult = buatDatabaseBaru_();
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
    try { lock.releaseLock(); } catch (e) {}
  }
}
