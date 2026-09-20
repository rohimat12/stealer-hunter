# 📋 Changelog

Semua perubahan dan catatan rilis pada proyek **StealerHunter** didokumentasikan di berkas ini.
Format mengikuti standar [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) dan menganut [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-09-15

### 🚀 Ditambahkan (Added)
- **📦 Tab UI Quarantine Vault (Brankas Karantina):**
  - Layar antarmuka khusus untuk meninjau semua berkas ancaman yang telah diamankan ke brankas karantina `%APPDATA%\StealerHunter\Quarantine`.
  - Tombol **[Restore]** untuk memulihkan berkas secara aman (non-destruktif ke `.restored`).
  - Tombol **[Hapus Permanen]** untuk memusnahkan payload malware secara permanen langsung dari GUI.
- **🛡️ Single-Instance Process Guardian:**
  - Mekanisme `Mutex` lintas-proses untuk mencegah proses aplikasi berjalan ganda.
  - Sinyal antar-proses berbasis `EventWaitHandle` yang otomatis memunculkan dan memfokuskan jendela utama saat aplikasi dibuka kembali.
- **⚙️ Hybrid Windows Task Scheduler & Registry Autorun:**
  - Pendaftaran autorun ganda berbasis Task Scheduler (`schtasks.exe /SC ONLOGON /RL HIGHEST`) dan Registry `HKCU\...\Run` trigger.
  - Memungkinkan aplikasi berjalan otomatis dengan hak Administrator penuh tanpa terhambat blokir UAC Windows saat booting, sekaligus tetap tampil di tab *Startup apps* Windows Task Manager.
  - Penambahan argumen CLI *headless* `--register-startup` dan `--unregister-startup` untuk integrasi otomatis saat instalasi.
  - Mode background `--silent` / `--minimized` yang langsung aktif di System Tray saat login.
- **🔍 Deep NTFS MFT & USN Change Journal Hunter:**
  - Pemindaian struktur tingkat rendah NTFS untuk mendeteksi jejak dropper atau infostealer yang berusaha melakukan *self-deletion* atau bersembunyi di partisi sekunder.
- **🗜️ Archive Deep Inspector (.zip, .rar, .7z):**
  - Inspeksi isi berkas arsip di folder rentan (`Downloads`, `Desktop`, `%TEMP%`).
  - Dilengkapi **Zip-Bomb & Memory Guard** (kuota batas 100 MB dan 5.000 entri per arsip) untuk mencegah kehabisan memori (*OOM*).
- **📊 Real-Time Scan Progress & State Synchronization:**
  - Indikator persentase pemindaian akurat 0% – 100% secara real-time.
  - Sinkronisasi status tombol: tombol *Stop* hanya aktif saat pemindaian berlangsung, dan tombol scan terkunci saat aktif.

### ⚡ Ditingkatkan & Diperbaiki (Changed & Fixed)
- **🧠 Deep Credential Content Inspection (EDR Standard):**
  - Pemindaian struktur data curian nyata (*plaintext credentials*, format triplet `URL:`, `USER:`, `PASS:`, kunci privat kriptografi SSH/RSA, skema dump tabel SQLite browser, dan *crypto wallet seed phrases*) pada seluruh berkas temporer tanpa terpengaruh ekstensi.
- **🔬 Kontekstualisasi Shannon Entropy & Zero-False-Positive Engine:**
  - Membatasi kalkulasi Shannon Entropy khusus pada berkas yang menyamar sebagai teks/konfigurasi data normal (`.txt`, `.log`, `.csv`, `.json`, `.dat`, `.ini`).
  - Mengeliminasi *false positive* secara permanen pada proses Windows Update (`cab*.tmp`), kompilasi developer (**Flutter, Dart, Java Bytecode, Gradle, Android NDK, CMake, Ninja, WebAssembly, Inno Setup, NPM, PyInstaller**), dan *cache* biner resmi.
  - Menambahkan pengenalan *magic header* untuk Microsoft Cabinet (`MSCF`), InstallShield Cabinet (`ISc(`), JavaScript V8 engine (`v8`), WebAssembly (`wasm`), Linux/Android binary (`ELF`), dan DirectX Shader Bytecode (`DXBC`).
- **🛡️ Hardened Chunked XOR Quarantine Engine:**
  - Pengolahan streaming biner 64 KB per chunk untuk mencegah *OutOfMemoryException* pada berkas besar.
  - *Immunity Safeguards*: Proteksi mutlak agar database browser (*Login Data, Cookies*) dan direktori sistem (*System32, Program Files*) tidak terhapus tidak sengaja.
- **📸 Dokumentasi & Pratinjau UI:**
  - Pembaruan seluruh screenshot antarmuka (6 Tab Lengkap) pada folder `docs/screenshots/` dan `README.md`.
- **🧪 Peningkatan Suite Pengujian:**
  - Peningkatan cakupan unit test menjadi **25/25 Tests Passing (100% Passed)** pada MSTest suite.

---

## [1.0.0] - 2026-09-14

### 🚀 Rilis Perdana (Initial Release)
- **🛡️ Scanner & Dashboard:** Pemindaian instan malware Infostealer (Lumma, RedLine, Stealc, Vidar, Raccoon).
- **🌐 Browser Shields:** Perlindungan integritas database kredensial dan session cookies (Chrome, Edge, Brave, Opera Stable, Opera GX).
- **⚙️ DPAPI & Master Key Protection:** Deteksi ancaman ekstraksi master key kredensial peramban.
- **📜 Live Logs & Telemetri:** Konsol real-time pemantauan sistem dan database ancaman Abuse.ch MalwareBazaar.
- **🚨 Emergency Checklist:** Panduan darurat pasca-infeksi dan tautan pencabutan sesi web aktif.
- **📦 Inno Setup Installer:** Pembuatan installer mandiri x64 Windows dengan integrasi icon Cyber Shield.
