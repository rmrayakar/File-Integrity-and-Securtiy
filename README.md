# 🔐 File Integrity Monitor with AES Encryption and Real-Time Alerts

A secure, real-time file monitoring system that detects file modifications, additions, and deletions using cryptographic integrity checks. Includes AES-256-CBC encryption for secure baseline storage, version control, email notifications, and PDF report generation — all wrapped in a modern, user-friendly GUI.

---

## 📁 Table of Contents

- [Features](#features)
- [System Architecture](#system-architecture)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Security Details](#security-details)
- [Screenshots](#screenshots)
- [To-Do / Enhancements](#to-do--enhancements)
- [License](#license)

---

## ✅ Features

- 📂 **Directory Monitoring (Real-Time)** – Detects changes to files using the `watchdog` observer
- 🛡️ **Cryptographic Hashing** – Uses SHA-512 for integrity and MD5 for filename tracking
- 🔐 **AES-256-CBC Encryption** – Secures baseline data with salt and IV
- 📜 **Version Control** – Saves previous versions of modified files automatically
- 📧 **Email Notifications** – Sends alerts for any file creation, deletion, or modification
- 📄 **PDF Report Generation** – Generates timestamped reports of file changes
- 🖥️ **GUI Interface** – User-friendly interface built with `customtkinter`
- ⚙️ **Error Handling** – Graceful exception management and status updates

---

## 🏗️ System Architecture

```
File Integrity Monitor
├── GUI Layer (customtkinter)
├── Monitoring Layer (watchdog)
├── Security Layer (pycryptodome)
├── File System Layer
└── Notification Layer (SMTP)
```

---

## 🧰 Tech Stack

| Component         | Library / Tool       |
|------------------|----------------------|
| GUI              | `customtkinter`      |
| Monitoring       | `watchdog`           |
| Hashing          | `hashlib`            |
| Encryption       | `pycryptodome`       |
| Email Alerts     | `smtplib` (SMTP TLS) |
| PDF Generation   | `fpdf`               |
| Versioning       | `os`, `shutil`       |

---

## 🛠️ Installation

```bash
git clone https://github.com/yourusername/file-integrity-monitor.git
cd file-integrity-monitor
pip install -r requirements.txt
```

### Requirements
- Python 3.8+
- Enable "Less secure apps" in Gmail or use App Password

### Required Python packages:
- customtkinter
- watchdog
- pycryptodome
- fpdf
- email, smtplib, hashlib, tkinter (standard libs)

---

## 🚀 Usage

```bash
python file_integrity_monitor.py
```

1. Launch the GUI.
2. Select a directory to monitor.
3. Click "Create Baseline" to initialize hashes and encryption.
4. Click "Start Monitoring" to begin real-time tracking.
5. View live changes, receive email alerts, and export reports as needed.

---

## ⚙️ How It Works

### 🔹 1. Baseline Creation
- Recursively scan all files in the selected directory
- Hash file contents with SHA-512
- Encrypt the baseline dictionary using AES-256-CBC
- Store encrypted baseline on disk

### 🔹 2. Real-Time Monitoring
- Monitor file creation, deletion, and modification using watchdog
- For each event:
  - Recalculate SHA-512 hash (if applicable)
  - Compare with baseline
  - Classify as Added / Removed / Modified

### 🔹 3. Change Logging & Versioning
- Automatically backup old versions of modified files to `versions/`
- Maintain change logs in memory and in reports

### 🔹 4. Alerts & Reporting
- Sends real-time email alerts using SMTP over TLS
- Generates PDF reports with:
  - Timestamp
  - File paths
  - Change types

---

## 🔐 Security Details

### 🔸 Encryption
**AES-256-CBC** with:
- 256-bit key derived via PBKDF2
- Salt-based key derivation (16 bytes)
- 100,000 iterations using SHA-256
- Unique IV for each encryption

### 🔸 Hashing
| Type    | Use Case |
|---------|----------|
| SHA-512 | File content hashing |
| MD5     | File name tracking (optional) |

### 🔸 Email
- SMTP server: smtp.gmail.com
- Port: 587 (TLS)
- Secure login credentials recommended

---

## 🖼️ Screenshots
📸 (Insert screenshots of GUI main window, alerts, PDF report, versioned files, etc.)

---

## 📌 To-Do / Enhancements
- [ ] Add logging system for audit trail
- [ ] Support SFTP or remote monitoring
- [ ] Add hash verification for report authenticity
- [ ] Integrate tray icon for background monitoring
- [ ] Dark/light theme toggle

---

## 📄 License
MIT License  
© 2025 Ankit Patil

---

## ✉️ Contact
For support or inquiries:

📧 Email: your_email@gmail.com  
📘 LinkedIn: linkedin.com/in/yourprofile  
🐙 GitHub: github.com/yourusername
