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
- **⚙️ Elevated Windows Task Scheduler Auto-Start:**
  - Pendaftaran autorun otomatis berbasis Task Scheduler (`schtasks.exe /SC ONLOGON /RL HIGHEST`) untuk mengatasi pembatasan UAC Windows saat komputer menyala.
  - Mode background `--silent` / `--minimized` yang langsung aktif di System Tray saat booting.
- **🔍 Deep NTFS MFT & USN Change Journal Hunter:**
  - Pemindaian struktur tingkat rendah NTFS untuk mendeteksi jejak dropper atau infostealer yang berusaha melakukan *self-deletion* atau bersembunyi di partisi sekunder.
- **🗜️ Archive Deep Inspector (.zip, .rar, .7z):**
  - Inspeksi isi berkas arsip di folder rentan (`Downloads`, `Desktop`, `%TEMP%`).
  - Dilengkapi **Zip-Bomb & Memory Guard** (kuota batas 100 MB dan 5.000 entri per arsip) untuk mencegah kehabisan memori (*OOM*).
- **📊 Real-Time Scan Progress & State Synchronization:**
  - Indikator persentase pemindaian akurat 0% – 100% secara real-time.
  - Sinkronisasi status tombol: tombol *Stop* hanya aktif saat pemindaian berlangsung, dan tombol scan terkunci saat aktif.

### ⚡ Ditingkatkan & Diperbaiki (Changed & Fixed)
- **🔬 Heuristik Entropi Shannon & Anti-False-Positive:**
  - Menambahkan pengenalan header runtime engine JavaScript V8/Chromium (`v8`) untuk mencegah deteksi keliru pada cache aplikasi (seperti IDE/Browser).
  - Menambahkan whitelist untuk struktur tabel biner terformat (*zero-padded headers*) dan DirectX Shader Bytecode (`DXBC`).
  - Menyesuaikan batas ukuran kandidat staging kredensial yang realistis (1 KB – 4 MB).
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
