/**
 * ============================================================================
 * Wajibku Fast — Backend Google Apps Script (Code.gs)
 * ============================================================================
 * Petunjuk Setup:
 * 1. Buka Google Sheets Anda, salin ID Spreadsheet dari URL browser:
 *    https://docs.google.com/spreadsheets/d/[SPREADSHEET_ID]/edit
 *    Tempelkan ke konstanta SPREADSHEET_ID di bawah (atau biarkan kosong jika
 *    script dibuat langsung dari menu Extensions > Apps Script di dalam Sheet).
 * 2. Pastikan terdapat 5 tab sheet dengan nama PERSIS:
 *    - Users
 *    - Produk
 *    - Finishing
 *    - Pesanan
 *    - Detail_Pesanan
 * 3. Klik Deploy > New deployment > Type: Web app
 *    - Execute as: Me (Email Anda)
 *    - Who has access: Anyone
 * 4. Salin URL Web App (/exec) dan tempelkan pada menu Admin > Koneksi Database.
 */

const SPREADSHEET_ID = "MASUKKAN_ID_SPREADSHEET_ANDA_DI_SINI";
const DRIVE_FOLDER_NAME = "WajibkuFast_Upload_Files";

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

/**
 * Mengambil referensi Spreadsheet aktif atau berdasarkan ID
 */
function getSpreadsheet_() {
  if (SPREADSHEET_ID && SPREADSHEET_ID !== "MASUKKAN_ID_SPREADSHEET_ANDA_DI_SINI") {
    return SpreadsheetApp.openById(SPREADSHEET_ID);
  }
  const active = SpreadsheetApp.getActiveSpreadsheet();
  if (!active) {
    throw new Error("Spreadsheet tidak ditemukan. Isi SPREADSHEET_ID pada Code.gs.");
  }
  return active;
}

/**
 * Mengambil atau membuat folder Google Drive untuk penyimpanan File Desain & Bukti Bayar
 */
function getOrCreateUploadFolder_() {
  const folders = DriveApp.getFoldersByName(DRIVE_FOLDER_NAME);
  if (folders.hasNext()) {
    return folders.next();
  }
  const folder = DriveApp.createFolder(DRIVE_FOLDER_NAME);
  return folder;
}

/**
 * Menyimpan string Base64 (Data URL) ke Google Drive dan mengembalikan URL aksesnya
 */
function saveBase64ToDrive_(base64Data, fileNamePrefix, originalName) {
  if (!base64Data || typeof base64Data !== "string") return "";
  if (!base64Data.startsWith("data:")) {
    // Sudah berupa URL atau nama file teks biasa
    return base64Data;
  }

  try {
    const parts = base64Data.split(",");
    const header = parts[0];
    const encoded = parts[1];
    const mimeMatch = header.match(/data:([^;]+);base64/);
    const mimeType = mimeMatch ? mimeMatch[1] : "application/octet-stream";

    const decodedBytes = Utilities.base64Decode(encoded);
    const safeName = (fileNamePrefix ? fileNamePrefix + "_" : "") + (originalName || "upload_file");
    const blob = Utilities.newBlob(decodedBytes, mimeType, safeName);

    const folder = getOrCreateUploadFolder_();
    const file = folder.createFile(blob);
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    return file.getUrl();
  } catch (err) {
    Logger.log("Gagal simpan file ke Drive: " + err.message);
    return "";
  }
}

/**
 * Membaca seluruh baris dari satu sheet menjadi Array of Objects (Case-Sensitive sesuai Header)
 */
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
    // Lewati baris yang benar-benar kosong
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

/**
 * Helper menambah baris ke sheet mengikuti urutan kolom header persis
 */
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

/**
 * Membuat JSON Response untuk Web App
 */
function jsonResponse_(payload) {
  return ContentService
    .createTextOutput(JSON.stringify(payload))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * Memastikan 5 tab sheet beserta header kolom (Case-Sensitive) tersedia otomatis.
 * Jika tab belum ada atau baris header kosong, otomatis dibuatkan.
 */
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
    }

    // Seed data minimal untuk Spreadsheet yang benar-benar baru
    if (isNewSheet || sheet.getLastRow() <= 1) {
      if (sheetName === "Users" && sheet.getLastRow() <= 1) {
        appendObjectRow_(ss, "Users", {
          User_ID: "SUP-001",
          Nama: "Super Admin Wajibku Fast",
          No_WA: "'081100009999",
          Email: "superadmin@wajibkufast.id",
          Role: "Super Admin",
          Alamat: "Kantor Pusat",
          Password: "super123"
        });
      }
      if (sheetName === "Finishing" && sheet.getLastRow() <= 1) {
        appendObjectRow_(ss, "Finishing", {
          Finishing_ID: "FIN-000",
          Nama_Finishing: "Tanpa Finishing",
          Tipe_Biaya: "Tetap",
          Tambahan_Harga: 0,
          Keterangan: "Tanpa biaya tambahan"
        });
      }
    }
  });

  return {
    createdSheets: createdSheets,
    initializedHeaders: initializedHeaders
  };
}

/**
 * Fungsi manual yang dapat langsung dijalankan (Run) dari editor Google Apps Script
 * untuk menginisialisasi 5 tab database dan seluruh header kolomnya.
 */
function setupDatabaseSheets() {
  const ss = getSpreadsheet_();
  const result = ensureSheetsInitialized_(ss);
  Logger.log("Setup Database Selesai: " + JSON.stringify(result));
  return result;
}

/**
 * Handler HTTP GET
 * Endpoint: ?action=getInitData | ?action=initSheets
 */
function doGet(e) {
  try {
    const action = (e && e.parameter && e.parameter.action) ? e.parameter.action : "getInitData";
    const ss = getSpreadsheet_();

    if (action === "initSheets") {
      const initResult = ensureSheetsInitialized_(ss);
      return jsonResponse_({
        status: "success",
        message: "Inisialisasi 5 tab sheet dan header berhasil diperiksa.",
        data: initResult
      });
    }

    if (action === "getInitData") {
      ensureSheetsInitialized_(ss);
      const data = {
        users: sheetToObjects_(ss, "Users"),
        produk: sheetToObjects_(ss, "Produk"),
        finishing: sheetToObjects_(ss, "Finishing"),
        pesanan: sheetToObjects_(ss, "Pesanan"),
        detail_pesanan: sheetToObjects_(ss, "Detail_Pesanan")
      };
      return jsonResponse_({ status: "success", data: data });
    }

    return jsonResponse_({ status: "error", message: "Action GET tidak dikenal: " + action });
  } catch (err) {
    return jsonResponse_({ status: "error", message: err.message });
  }
}

/**
 * Handler HTTP POST
 * Actions: createOrder, updateStatus, saveProduct
 */
function doPost(e) {
  const lock = LockService.getScriptLock();
  try {
    lock.waitLock(15000);
    const body = JSON.parse(e.postData.contents);
    const action = body.action;
    const ss = getSpreadsheet_();

    // ------------------------------------------------------------------------
    // 1. CREATE ORDER (Simpan User baru jika belum ada, Pesanan, & Detail_Pesanan)
    // ------------------------------------------------------------------------
    if (action === "createOrder") {
      const userPayload = body.user || {};
      const orderPayload = body.pesanan || {};
      const detailsPayload = body.detail_pesanan || [];

      // Cek / Simpan User berdasarkan No_WA
      const existingUsers = sheetToObjects_(ss, "Users");
      let userId = userPayload.User_ID || "";
      const matchedUser = existingUsers.find(function (u) {
        return String(u.No_WA).trim() === String(userPayload.No_WA || "").trim();
      });

      if (matchedUser) {
        userId = matchedUser.User_ID;
      } else {
        userId = userId || ("USR-" + Math.floor(100 + Math.random() * 900) + "-" + Date.now().toString().slice(-3));
        appendObjectRow_(ss, "Users", {
          User_ID: userId,
          Nama: userPayload.Nama || "Pelanggan",
          No_WA: "'" + String(userPayload.No_WA || ""),
          Email: userPayload.Email || "",
          Role: "User",
          Alamat: userPayload.Alamat || ""
        });
      }

      const orderId = orderPayload.Order_ID || ("ORD-" + Date.now().toString().slice(-4));
      const tanggal = orderPayload.Tanggal || Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyyy-MM-dd HH:mm");

      // Upload Bukti_Bayar ke Drive jika berupa Base64
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
        Status_Order: orderPayload.Status_Order || "Menunggu Bayar",
        Total_Tagihan: Number(orderPayload.Total_Tagihan) || 0,
        Bukti_Bayar: buktiBayarUrl,
        Status_Bayar: orderPayload.Status_Bayar || (buktiBayarUrl ? "Menunggu Verifikasi" : "Belum Bayar"),
        Catatan: orderPayload.Catatan || ""
      };
      appendObjectRow_(ss, "Pesanan", savedOrder);

      // Simpan setiap item ke Detail_Pesanan
      const savedDetails = [];
      for (let i = 0; i < detailsPayload.length; i++) {
        const item = detailsPayload[i];
        const detailId = item.Detail_ID || ("DTL-" + orderId.replace("ORD-", "") + "-" + (i + 1));
        let fileDesainUrl = "";
        if (item.File_Desain_Base64) {
          fileDesainUrl = saveBase64ToDrive_(
            item.File_Desain_Base64,
            detailId,
            item.File_Desain || "desain_cetak"
          );
        } else if (item.File_Desain) {
          fileDesainUrl = item.File_Desain;
        }

        const detailRow = {
          Detail_ID: detailId,
          Order_ID: orderId,
          Produk_ID: item.Produk_ID,
          Panjang_m: Number(item.Panjang_m) || 0,
          Lebar_m: Number(item.Lebar_m) || 0,
          Qty: Number(item.Qty) || 1,
          Finishing_ID: item.Finishing_ID || "FIN-000",
          File_Desain: fileDesainUrl,
          Keterangan_Item: item.Keterangan_Item || "",
          Subtotal: Number(item.Subtotal) || 0
        };
        appendObjectRow_(ss, "Detail_Pesanan", detailRow);
        savedDetails.push(detailRow);
      }

      return jsonResponse_({
        status: "success",
        message: "Pesanan berhasil disimpan",
        data: {
          User_ID: userId,
          pesanan: savedOrder,
          detail_pesanan: savedDetails
        }
      });
    }

    // ------------------------------------------------------------------------
    // 2. UPDATE STATUS (Admin ubah Status_Order & Status_Bayar di sheet Pesanan)
    // ------------------------------------------------------------------------
    if (action === "updateStatus") {
      const sheet = ss.getSheetByName("Pesanan");
      if (!sheet) throw new Error("Sheet Pesanan tidak ditemukan.");
      const dataRange = sheet.getDataRange();
      const values = dataRange.getValues();
      const headers = values[0].map(function (h) { return String(h).trim(); });

      const colOrderId = headers.indexOf("Order_ID");
      const colStatusOrder = headers.indexOf("Status_Order");
      const colStatusBayar = headers.indexOf("Status_Bayar");

      if (colOrderId === -1) throw new Error("Kolom Order_ID tidak ditemukan.");

      let updated = false;
      for (let r = 1; r < values.length; r++) {
        if (String(values[r][colOrderId]).trim() === String(body.Order_ID).trim()) {
          if (body.Status_Order && colStatusOrder !== -1) {
            sheet.getRange(r + 1, colStatusOrder + 1).setValue(body.Status_Order);
          }
          if (body.Status_Bayar && colStatusBayar !== -1) {
            sheet.getRange(r + 1, colStatusBayar + 1).setValue(body.Status_Bayar);
          }
          updated = true;
          break;
        }
      }

      if (!updated) {
        return jsonResponse_({ status: "error", message: "Order_ID tidak ditemukan: " + body.Order_ID });
      }
      return jsonResponse_({ status: "success", message: "Status pesanan diperbarui." });
    }

    // ------------------------------------------------------------------------
    // 3. SAVE PRODUCT (Admin tambah / edit produk di sheet Produk)
    // ------------------------------------------------------------------------
    if (action === "saveProduct") {
      const prod = body.produk || body;
      const sheet = ss.getSheetByName("Produk");
      if (!sheet) throw new Error("Sheet Produk tidak ditemukan.");

      const values = sheet.getDataRange().getValues();
      const headers = values[0].map(function (h) { return String(h).trim(); });
      const colProdId = headers.indexOf("Produk_ID");

      let rowIndex = -1;
      for (let r = 1; r < values.length; r++) {
        if (String(values[r][colProdId]).trim() === String(prod.Produk_ID).trim()) {
          rowIndex = r + 1;
          break;
        }
      }

      const productData = {
        Produk_ID: prod.Produk_ID || ("PRD-" + Date.now().toString().slice(-3)),
        Nama_Produk: prod.Nama_Produk,
        Kategori: prod.Kategori,
        Tipe_Hitung: prod.Tipe_Hitung,
        Harga_Dasar: Number(prod.Harga_Dasar) || 0,
        Satuan: prod.Satuan,
        Min_Order: Number(prod.Min_Order) || 1,
        Status: prod.Status || "Tersedia"
      };

      if (rowIndex > 0) {
        // Update baris yang ada
        headers.forEach(function (h, idx) {
          if (productData.hasOwnProperty(h)) {
            sheet.getRange(rowIndex, idx + 1).setValue(productData[h]);
          }
        });
      } else {
        // Tambah produk baru
        appendObjectRow_(ss, "Produk", productData);
      }

      return jsonResponse_({
        status: "success",
        message: rowIndex > 0 ? "Produk diperbarui" : "Produk ditambahkan",
        data: productData
      });
    }

    // ------------------------------------------------------------------------
    // 4. SAVE USER (Super Admin kelola akun & role di sheet Users)
    // ------------------------------------------------------------------------
    if (action === "saveUser") {
      const usr = body.user || body;
      const sheet = ss.getSheetByName("Users");
      if (!sheet) throw new Error("Sheet Users tidak ditemukan.");

      const values = sheet.getDataRange().getValues();
      const headers = values[0].map(function (h) { return String(h).trim(); });
      const colUserId = headers.indexOf("User_ID");

      let rowIndex = -1;
      for (let r = 1; r < values.length; r++) {
        if (String(values[r][colUserId]).trim() === String(usr.User_ID).trim()) {
          rowIndex = r + 1;
          break;
        }
      }

      const userData = {
        User_ID: usr.User_ID || ("USR-" + Date.now().toString().slice(-3)),
        Nama: usr.Nama || "",
        No_WA: "'" + String(usr.No_WA || "").replace(/^'/, ""),
        Email: usr.Email || "",
        Role: usr.Role || "User",
        Alamat: usr.Alamat || "",
        Password: usr.Password || ""
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
        data: userData
      });
    }

    // ------------------------------------------------------------------------
    // 5. SAVE FINISHING (Admin tambah / edit opsi finishing di sheet Finishing)
    // ------------------------------------------------------------------------
    if (action === "saveFinishing") {
      const fin = body.finishing || body;
      const sheet = ss.getSheetByName("Finishing");
      if (!sheet) throw new Error("Sheet Finishing tidak ditemukan.");

      const values = sheet.getDataRange().getValues();
      const headers = values[0].map(function (h) { return String(h).trim(); });
      const colFinId = headers.indexOf("Finishing_ID");

      let rowIndex = -1;
      for (let r = 1; r < values.length; r++) {
        if (String(values[r][colFinId]).trim() === String(fin.Finishing_ID).trim()) {
          rowIndex = r + 1;
          break;
        }
      }

      const finData = {
        Finishing_ID: fin.Finishing_ID || ("FIN-" + Date.now().toString().slice(-3)),
        Nama_Finishing: fin.Nama_Finishing || "",
        Tipe_Biaya: fin.Tipe_Biaya === "Per_Qty" ? "Per_Qty" : "Tetap",
        Tambahan_Harga: Number(fin.Tambahan_Harga) || 0,
        Keterangan: fin.Keterangan || ""
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
    // 6. DELETE RECORD (Hapus Produk, Finishing, Users, atau Pesanan + Detail)
    // ------------------------------------------------------------------------
    if (action === "deleteRecord") {
      const sheetName = body.sheetName;
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

      // Jika Pesanan dihapus, hapus juga baris terkait di Detail_Pesanan
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
    // 7. INIT SHEETS (Auto-setup 5 tab & header kolom spreadsheet baru)
    // ------------------------------------------------------------------------
    if (action === "initSheets") {
      const initResult = ensureSheetsInitialized_(ss);
      return jsonResponse_({
        status: "success",
        message: "Inisialisasi 5 tab & header sheet selesai.",
        data: initResult
      });
    }

    return jsonResponse_({ status: "error", message: "Action POST tidak dikenal: " + action });
  } catch (err) {
    return jsonResponse_({ status: "error", message: err.message });
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}
