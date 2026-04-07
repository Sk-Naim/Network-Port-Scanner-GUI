# 🌐 Network Port Scanner (GUI-Based)

A modern, high-performance, multi-threaded network port scanner built using Python and Tkinter.  
This tool provides real-time scanning, banner grabbing, scan history, and export features in a clean graphical interface.

---

## 🚀 Features

### 🔍 Multi-threaded Port Scanning
- Uses Python threading for high-speed scanning
- Efficient scanning of large port ranges (1–65535)
- Controlled concurrency using semaphore

---

### 🌐 Target Resolution
- Accepts both:
  - IP addresses (e.g., `192.168.1.1`)
  - Hostnames (e.g., `google.com`)
- Automatically resolves hostname to IP

---

### 📡 Service Detection
- Identifies common services:
  - 80 → HTTP
  - 443 → HTTPS
  - 22 → SSH
  - 3306 → MySQL
- Unknown ports are labeled accordingly

---

### 🧠 Banner Grabbing
- Attempts to retrieve service banners
- Helps identify:
  - Server type
  - Running service
  - Partial version info

Example:
