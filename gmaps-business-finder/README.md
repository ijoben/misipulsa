# 🗺️ GMaps Business Finder

Aplikasi pencarian bisnis & nomor HP menggunakan Google Maps API resmi.

## 📋 Fitur

- ✅ Pencarian bisnis real-time dari Google Maps
- ✅ Menampilkan: nama, alamat, nomor HP, rating, website
- ✅ Filter berdasarkan jenis bisnis
- ✅ Salin nomor HP dengan satu klik
- ✅ Export hasil pencarian ke CSV
- ✅ Simpan kontak favorit
- ✅ Link langsung ke Google Maps

## 🚀 Cara Menggunakan

### 1. Setup Google Maps API Key

1. Buka [Google Cloud Console](https://console.cloud.google.com/)
2. Login dengan Google Account
3. Buat project baru
4. Aktifkan **Places API**
5. Buat API Key
6. Masukkan API Key di aplikasi

### 2. Buka Aplikasi

Buka `index.html` di browser.

### 3. Mulai Pencarian

- Ketik nama atau jenis bisnis
- Pilih filter (restoran, cafe, toko, dll)
- Klik "Cari"
- Lihat hasil dan salin nomor HP

## 💰 Estimasi Biaya Google API

| Item | Harga |
|------|-------|
| Free tier | $200/bulan (≈ 4,000 pencarian gratis) |
| Per pencarian | ~$0.049 (≈ Rp 750) |

## 📁 Struktur File

```
gmaps-business-finder/
├── index.html      # Halaman utama
├── style.css       # Styles
├── app.js          # JavaScript logic
└── README.md       # Dokumentasi
```

## ⚠️ Catatan

- API Key disimpan di localStorage browser
- Tidak semua bisnis memiliki nomor HP di Google Maps
- Pastikan API Key memiliki izin Places API

## 📞 Support

Jika ada masalah:
- Cek API Key benar
- Pastikan Places API aktif
- Pastikan billing aktif di Google Cloud Console
