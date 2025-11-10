# Syscall Integrity Monitor 🛡️
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📌 Overview

The **Syscall Integrity Monitor** detects advanced evasion techniques used by malware and sophisticated attacks. By monitoring direct syscall usage patterns, this PoC identifies attempts to bypass API hooks and EDR solutions through direct system call invocation, a technique commonly employed to evade security monitoring.

## 💎 Features

* **Direct Syscall Detection:** Identifies processes making direct syscalls instead of using standard ntdll.dll functions.
* **Pattern Analysis:** Analyzes syscall instruction patterns commonly used in evasion techniques.
* **Real-time Monitoring:** Continuously scans running processes for suspicious syscall behavior.
* **Detailed Reporting:** Provides comprehensive reports of detected syscall anomalies with memory addresses.

## 🔍 How It Works

The Syscall Integrity Monitor employs advanced detection techniques to identify direct syscall usage:

1. **Process Enumeration:**
   * Scans all running processes on the system.

2. **Memory Analysis:**
   * Examines executable memory regions for direct syscall instructions.
   * Identifies patterns like `MOV R10, RCX; MOV EAX, <syscall_number>; SYSCALL`.

3. **Anomaly Detection:**
   * Compares findings against expected ntdll.dll call patterns.
   * Flags processes exhibiting direct syscall behavior.

4. **Real-time Alerting:**
   * Reports suspicious processes with detailed syscall information.

## ⚠️ Important Notice

This is a **highly experimental proof of concept** for demonstration purposes. The current implementation performs system-wide scanning with basic signed binary exclusion. For production, you should implement:

* **Proper exclusion logic** for legitimate processes and system directories
* **Targeted monitoring** of specific executables or directories instead of system-wide scanning
* **Whitelist/blacklist mechanisms** to reduce false positives
* **Performance optimizations** to minimize system resource usage
* **Additional verification** beyond signature checking

System-wide memory scanning can be resource-intensive and may produce false positives. Consider focusing on specific processes of interest or implementing more sophisticated filtering mechanisms.

## 🧪 Usage

* Compile and run the provided main.cpp C++ application with administrator privileges.
* The monitor will scan all running processes every 5 seconds.
* Observe real-time alerts for processes using direct syscalls.
* Test by running shellcode loaders or other tools that use direct syscalls.

### Console Example
```
[!] DIRECT SYSCALL DETECTED [14:22:33] suspicious.exe (PID: 4892) at 0x7FF6A2C10050
```
## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
