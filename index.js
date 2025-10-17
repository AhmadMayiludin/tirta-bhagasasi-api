// File: index.js (VERSI FINAL LENGKAP)

// 1. Panggil semua "alat masak" yang kita butuhkan
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// 2. Siapkan dapurnya (Express App)
const app = express();
app.use(cors()); // Izinkan semua permintaan dari luar
app.use(express.json()); // Izinkan dapur menerima data format JSON

// 3. Siapkan koneksi ke "gudang" (Database)
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root', // default user XAMPP/Laragon
  password: '', // default password XAMPP/Laragon
  database: 'magang_db' // Pastikan nama DB ini benar
});

db.connect(err => {
  if (err) {
    console.error('Error connecting to database:', err);
    return;
  }
  console.log('Successfully connected to database!');
});

// --- INI "PINTU-PINTU" LAYANAN DAPUR KITA ---

// Pintu #1: Untuk Daftar (Register)
app.post('/register', async (req, res) => {
  const { nama, email, password } = req.body;

  // Acak passwordnya dulu sebelum disimpan
  const hashedPassword = await bcrypt.hash(password, 8);

  // Simpan data ke tabel 'users'
  db.query('INSERT INTO users SET ?', { nama: nama, email: email, password: hashedPassword }, (err, results) => {
    if (err) {
      return res.status(500).send({ message: 'Gagal mendaftarkan user', error: err });
    }
    return res.status(201).send({ message: 'User berhasil didaftarkan!' });
  });
});

// Pintu #2: Untuk Masuk (Login)
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Cari user berdasarkan email
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).send({ message: 'Email atau password salah!' });
    }

    const user = results[0];
    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      return res.status(401).send({ message: 'Email atau password salah!' });
    }
    
    // Kalau password cocok, buatkan "tiket" (token)
    const token = jwt.sign({ id: user.id }, 'rahasia-banget', { expiresIn: '24h' });

    res.send({ message: 'Login berhasil!', token: token });
  });
});

// PINTU #3 (BARU): Untuk Mengambil Data Profil User (butuh token)
app.get('/user-profile', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send({ message: 'Tidak ada token, akses ditolak!' });
  }

  jwt.verify(token, 'rahasia-banget', (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: 'Token tidak valid!' });
    }

    const userId = decoded.id;
    db.query('SELECT id, nama, email FROM users WHERE id = ?', [userId], (err, results) => {
      if (err || results.length === 0) {
        return res.status(404).send({ message: 'User tidak ditemukan' });
      }
      res.send(results[0]);
    });
  });
});

// 4. Jalankan dapurnya di port 3000
app.listen(3000, () => {
  console.log('Server API berjalan di http://localhost:3000');
});