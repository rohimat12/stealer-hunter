# 🛡️ StealerHunter: Anti-Infostealer & Browser Credential Guardian

[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://microsoft.com)
[![Framework](https://img.shields.io/badge/Framework-.NET%208%20WPF-purple.svg)](https://dotnet.microsoft.com/)
[![Security](https://img.shields.io/badge/Focus-Anti--Infostealer-red.svg)](#)
[![Built With](https://img.shields.io/badge/Built%20With-AI%20Pair%20Programming-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#)

**StealerHunter** adalah aplikasi desktop keamanan modern berbasis **C# (.NET 8 WPF)** yang dirancang khusus untuk memburu, menghentikan, dan membersihkan malware pencuri kata sandi (**Infostealer**) seperti **Lumma Stealer, RedLine, Stealc, Vidar, dan Raccoon**, serta mengamankan basis data kredensial dan *session cookies* peramban (browser).

---

## 🎯 Mengapa Dikhususkan untuk Infostealer?
Infostealer memiliki karakteristik serangan cepat berantai (*hit-and-run*):
1. **Menyerang Berkas Kredensial Browser**: Menyasar database SQLite (`Login Data`, `Cookies`, `Web Data`, `Local State`).
2. **Mengekstrak Kunci Windows DPAPI**: Membaca kata sandi tersimpan dan token sesi login akun.
3. **Mencuri Sesi Aplikasi**: Mengambil token Discord, file sesi Telegram (`tdata`), dan *crypto wallet extension*.
4. **Staging & Eksfiltrasi**: Mengumpulkan data curian ke folder `%TEMP%` atau `%APPDATA%` lalu mengunggahnya ke server C2 / bot Telegram pelaku.

**StealerHunter** memutus rantai serangan ini secara langsung dari akarnya.

---

## 🚀 Fitur Utama

1. **Auto-Start with Windows & System Tray Guard**:
   * Opsi toggle **"Run on Windows Startup"** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
   * Mode **Silent Boot**: Berjalan otomatis di latar belakang tanpa memunculkan jendela besar yang mengganggu saat Windows menyala.
   * **Minimize to System Tray**: Bersembunyi di area notifikasi pojok kanan bawah dengan menu konteks klik kanan.
   * **Boot Quick Scan**: Pemindaian otomatis seketika saat komputer dinyalakan.

2. **Realtime %TEMP% & Staging Watcher**:
   * Memantau folder `%TEMP%` dan staging directory menggunakan `FileSystemWatcher`.
   * Memergoki pembuatan file dump curian (`passwords.txt`, `cookies.txt`, `wallets`, atau arsip zip mencurigakan) dan memunculkan notifikasi Windows Toast seketika.

3. **Browser Vault Integrity Shield**:
   * Memeriksa integritas database kredensial untuk **Google Chrome, Microsoft Edge, Brave, Mozilla Firefox, Opera Stable, Opera GX, dan Vivaldi**.
   * Mendeteksi penguncian berkas (*file lock*) mencurigakan oleh program asing di saat browser sedang ditutup.

4. **Process & Memory Hunter**:
   * Memindai proses aktif yang berjalan dari direktori berisiko tinggi (`%TEMP%`, `%APPDATA%`, `Downloads`, `Public`).
   * Mendeteksi proses yang menyamar (*masquerading system processes* seperti `svchost.exe` palsu).
   * Mendeteksi eksekusi skrip tersembunyi (PowerShell `-w hidden -enc`, skrip obfuscated).

5. **Persistence & Autorun Hunter**:
   * Memeriksa entri autorun di Registry (`HKCU` & `HKLM` `Run` / `RunOnce`).
   * Memeriksa entri Task Scheduler dan Windows Startup dari skrip atau executable asing.

6. **One-Click Neutralize & Quarantine**:
   * Mematikan seluruh pohon proses malware seketika (*Process Tree Termination*).
   * Mengisolasi file berbahaya ke folder karantina aman (`%APPDATA%\StealerHunter\Quarantine`).
   * Menghapus entri autorun dan service jahat dari registry secara bersih.

7. **Emergency Security Checklist**:
   * Panduan langkah darurat pasca-infeksi: pencabutan sesi web aktif (*Revoke Google/Microsoft sessions*), pergantian password master email, aktivasi 2FA aplikasi, dan pengamanan aset digital.

8. **Dual-Engine Threat Intelligence (Abuse.ch MalwareBazaar Integration)**:
   * **1,230+ Hash Signatures**: Terintegrasi langsung dengan database signature ancaman global dari **Abuse.ch MalwareBazaar**.
   * **Live Threat DB Updater**: Fitur pembaruan daring (*Live Update*) sekali klik untuk mengunduh intelijen malware teranyar dari server siber.
   * **Memory & Directory Hash Matching**: Memvalidasi hash SHA-256 seluruh proses aktif dan direktori berisiko tinggi dengan pencarian instan O(1).

---

## 💻 Cara Menggunakan & Instalasi

### 1. Menggunakan File Installer (Rekomendasi Pengguna)
Unduh file **`StealerHunter_Setup.exe`** dari menu [Releases](https://github.com/rohimat12/stealer-hunter/releases), jalankan installer, dan aplikasi siap melindungi sistem Anda.

### 2. Mode Darurat Tanpa GUI (Batch Script)
Jika sistem Anda sedang dalam infeksi aktif dan butuh pembersihan cepat seketika:
Jalankan file **`BERSIHKAN_VIRUS.bat`** dengan **Run as Administrator**.

### 3. Menjalankan dari Source Code (Developer):
Pastikan .NET 8 SDK sudah terpasang, lalu jalankan:
```powershell
dotnet run --project StealerHunter
```

### 4. Mem-build File Executable Mandiri (.exe Tunggal):
```powershell
dotnet publish StealerHunter -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ./dist
```

### 5. Mem-build File Installer (Inno Setup):
Jalankan skrip pembangun:
```cmd
BUILD_INSTALLER.bat
```

---

## 🧪 Pengujian Unit (Unit Tests)
Proyek ini dilengkapi pengujian otomatis (MSTest):
```powershell
dotnet test
```
*Seluruh pengujian unit (7/7) terverifikasi sukses.*

---

## 🛠️ Struktur Proyek

```
stealer-hunter/
├── StealerHunter.sln            # Visual Studio / .NET Solution
├── StealerHunter_Setup.iss      # Skrip Inno Setup Installer
├── BERSIHKAN_VIRUS.bat          # Skrip darurat pembersihan sistem
├── BUILD_INSTALLER.bat          # Otomasi kompilasi installer
├── README.md                    # Dokumentasi proyek
├── StealerHunter/               # Proyek Aplikasi Utama (C# WPF .NET 8)
│   ├── Models/                  # ThreatItem, BrowserTarget, ScanLogItem, AppSettings
│   ├── Services/                # BrowserAudit, ProcessHunter, Persistence, Quarantine, AutoStartup, RealtimeWatcher, SystemTray, MalwareDatabase
│   ├── ViewModels/              # MainViewModel, RelayCommand, ValueConverters
│   ├── Resources/               # Styles.xaml (Modern Cyber Dark Theme), malware_db.json (Abuse.ch DB)
│   ├── MainWindow.xaml/.cs      # Tampilan UI Dashboard & Tray Integration
│   └── App.xaml/.cs             # Konfigurasi Aplikasi & Resource Dictionary
└── StealerHunter.Tests/         # Proyek Unit Test (MSTest)
```

---

## 👥 Pengembang & Kontribusi

* **Lead Developer**: [@rohimat12](https://github.com/rohimat12)
* **Engineering Workflow**: Dikembangkan bersama menggunakan pendekatan modern **AI Pair Programming** untuk analisis siber dan implementasi sistem.

---

## ⚖️ Disclaimer
Aplikasi ini dibuat murni untuk keperluan pertahanan keamanan (*defensive security*), analisis siber edukatif, dan membantu pembersihan malware pada komputer pengguna. Pengembang tidak bertanggung jawab atas penyalahgunaan atau modifikasi tidak sah dari perangkat lunak ini.
