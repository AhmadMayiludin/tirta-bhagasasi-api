// File: index.js (VERSI FINAL LENGKAP - PROSES 1, 2, & 3)

const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer'); // Panggil multer
const path = require('path');   // Panggil path (bawaan Node.js)
const fs = require('fs');     // Panggil fs (bawaan Node.js)

// --- Konfigurasi Multer untuk Upload Foto ---
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir);
}
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir); // Folder penyimpanan foto
  },
  filename: function (req, file, cb) {
    // Buat nama file unik: fieldname-timestamp.extension
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });
// -------------------------------------------

const app = express();
app.use(cors());
app.use(express.json());
// Middleware untuk menyajikan file statis (gambar) dari folder 'uploads'
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'magang_db' // Pastikan nama DB ini benar
});

db.connect(err => {
  if (err) { console.error('Error connecting to database:', err); return; }
  console.log('Successfully connected to database!');
});

// --- Middleware untuk Verifikasi Token ---
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) { return res.status(401).send({ message: 'Tidak ada token, akses ditolak!' }); }

  jwt.verify(token, 'rahasia-banget', (err, decoded) => {
    if (err) { return res.status(401).send({ message: 'Token tidak valid!' }); }
    req.userId = decoded.id; // Simpan id user di request
    next(); // Lanjutkan
  });
};
// ---------------------------------------

// --- Pintu Autentikasi ---

// Pintu #1: Register
app.post('/register', async (req, res) => {
 const { nama, email, password } = req.body;
 if (!nama || !email || !password) {
    return res.status(400).send({ message: 'Nama, email, dan password wajib diisi.' });
 }
 try {
    const hashedPassword = await bcrypt.hash(password, 8);
    db.query('INSERT INTO users SET ?', { nama: nama, email: email, password: hashedPassword }, (err, results) => {
      if (err) {
        console.error("Database insert error:", err);
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).send({ message: 'Email sudah terdaftar.' });
        }
        return res.status(500).send({ message: 'Gagal mendaftarkan user', error: err.message });
      }
      return res.status(201).send({ message: 'User berhasil didaftarkan!' });
    });
 } catch (hashError) {
    console.error("Bcrypt hash error:", hashError);
    return res.status(500).send({ message: 'Gagal mengamankan password.' });
 }
});

// Pintu #2: Login (Versi sudah diperbaiki)
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
     return res.status(400).send({ message: 'Email dan password wajib diisi.' });
  }

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).send({ message: 'Kesalahan server saat mencari user.' });
    }
    if (results.length === 0) {
      return res.status(401).send({ message: 'Email atau password salah!' });
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (bcryptErr, isPasswordMatch) => {
      if (bcryptErr) {
        console.error("Bcrypt compare error:", bcryptErr);
        return res.status(500).send({ message: 'Kesalahan server saat verifikasi password.' });
      }
      if (!isPasswordMatch) {
        return res.status(401).send({ message: 'Email atau password salah!' });
      }

      const token = jwt.sign({ id: user.id }, 'rahasia-banget', { expiresIn: '24h' });
      res.send({ message: 'Login berhasil!', token: token });
    });
  });
});

// Pintu #3: User Profile
app.get('/user-profile', verifyToken, (req, res) => {
  const userId = req.userId;
  db.query('SELECT id, nama, email FROM users WHERE id = ?', [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).send({ message: 'User tidak ditemukan' });
    }
    res.send(results[0]);
  });
});
// -------------------------

// --- Pintu Inventaris Barang ---

// Pintu #4: Input Item Baru (Sudah termasuk harga)
app.post('/items', verifyToken, upload.single('itemPhoto'), (req, res) => {
  const userId = req.userId;
  const { nama_item, scan_code, item_condition, permendagri_code, harga } = req.body;
  const photo_path = req.file ? req.file.path : null;

  if (!nama_item || !scan_code) {
    if (photo_path) try { fs.unlinkSync(photo_path); } catch (e) { console.error("Gagal hapus foto:", e); }
    return res.status(400).send({ message: 'Nama item dan kode scan wajib diisi.' });
  }

  const newItem = {
    nama_item,
    photo_path,
    user_id: userId,
    scan_code,
    item_condition: item_condition || null,
    permendagri_code: permendagri_code || null,
    harga: harga || null
  };

  db.query('INSERT INTO items SET ?', newItem, (err, results) => {
    if (err) {
      console.error('Error inserting item:', err);
      if (photo_path) try { fs.unlinkSync(photo_path); } catch (e) { console.error("Gagal hapus foto:", e); }
      if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).send({ message: 'Kode Scan sudah terpakai.' });
      }
      return res.status(500).send({ message: 'Gagal menyimpan item ke database.' });
    }
    res.status(201).send({ message: 'Item berhasil ditambahkan!', itemId: results.insertId });
  });
});

// Pintu #5: Ambil Detail Item berdasarkan Scan Code
app.get('/items/:scan_code', verifyToken, (req, res) => {
  const scanCode = req.params.scan_code;
  const query = `
    SELECT
      i.id, i.nama_item, i.photo_path, i.upload_date, i.scan_code,
      i.item_condition, i.permendagri_code, i.harga,
      u.nama as user_nama
    FROM items i
    JOIN users u ON i.user_id = u.id
    WHERE i.scan_code = ?
  `;

  db.query(query, [scanCode], (err, results) => {
    if (err) {
      console.error('Error fetching item:', err);
      return res.status(500).send({ message: 'Gagal mengambil data item.' });
    }
    if (results.length === 0) {
      return res.status(404).send({ message: 'Item dengan kode scan tersebut tidak ditemukan.' });
    }
    const item = results[0];
    if (item.photo_path) {
        // Paksa https:// untuk URL ngrok
        item.photo_url = `https://${req.get('host')}/${item.photo_path.replace(/\\/g, '/')}`;
    }
    res.send(item);
  });
});

// ✅ --- Pintu #6 (BARU): Update Kondisi Item ---
app.put('/items/update-status/:scan_code', verifyToken, (req, res) => {
  const scanCode = req.params.scan_code;
  // Ambil 'new_condition' dari body request yang dikirim Ionic
  const { new_condition } = req.body; 

  if (!new_condition) {
    return res.status(400).send({ message: 'Kondisi baru (new_condition) wajib diisi.' });
  }

  // Gunakan nama kolom yang benar: 'item_condition'
  const query = "UPDATE items SET item_condition = ? WHERE scan_code = ?";
  
  db.query(query, [new_condition, scanCode], (err, results) => {
    if (err) {
      console.error('Error updating item condition:', err);
      return res.status(500).send({ message: 'Gagal update kondisi item.' });
    }
    if (results.affectedRows === 0) {
      return res.status(404).send({ message: 'Barang dengan kode scan tersebut tidak ditemukan.' });
    }
    res.send({ message: 'Kondisi barang berhasil diperbarui!' });
  });
});
// -----------------------------------------------------------

// ✅ Jalankan dapurnya di 0.0.0.0 agar bisa diakses dari HP
app.listen(3000, '0.0.0.0', () => {
  console.log('Server API berjalan di http://0.0.0.0:3000 (siap menerima koneksi jaringan)');
});