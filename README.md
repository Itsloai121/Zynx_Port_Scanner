<div align="center">

# ⚡ Zynx Port Scanner

**Fast threaded TCP port scanning · Service detection · Banner grabbing**

`zynx` — a lightweight terminal tool for learning network reconnaissance.

</div>

---

## ✨ Overview

**Zynx Port Scanner** checks a target host for open TCP ports and makes a best-effort attempt to identify the service listening on each open port. When a service returns readable data, Zynx captures a short banner—for example, an SSH greeting or an HTTP response header.

It uses Python's built-in `socket` library for TCP connections and `ThreadPoolExecutor` for concurrent scanning. The terminal interface is powered by [Rich](https://github.com/Textualize/rich).

> **Use only on systems you own or have explicit permission to assess.** Unauthorized scanning may violate laws, contracts, or network policies.

## 🚀 Features

- **Threaded TCP connect scanning** with configurable concurrency.
- **Banner grabbing** for services that disclose a greeting, plus lightweight HTTP `HEAD` probes for common HTTP and HTTPS ports.
- **IPv4 and IPv6 support** (one resolved target address per scan).
- **Scan profiles:** quick, common ports, custom ports, custom range, and the full TCP range (`1–65535`).
- **Service labels** using common port mappings and the system TCP service database.
- **Live progress display** with scan duration, open-port count, and session uptime.
- **CSV and JSON reports** for the last scan.
- **Configurable timeout and worker count** to balance speed and reliability.
- **No stealth or exploitation features.** Zynx performs ordinary TCP connection checks and limited application-level banner probes.

## 🧰 Requirements

- Python **3.10 or newer**
- A terminal that supports Unicode (for the box-drawing interface)
- Network permission and connectivity to the target

## 📦 Installation

### 1. Get the project

```bash
git clone https://github.com/YOUR-USERNAME/zynx-port-scanner.git
cd zynx-port-scanner
```

Or download the files directly and place them in one folder.

### 2. (Recommended) Create a virtual environment

**Windows (PowerShell):**

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install the dependency

```bash
python -m pip install -r requirements.txt
```

### 4. Launch Zynx

**Windows:**

```powershell
py zynx_port_scanner.py
```

**Linux / macOS:**

```bash
python3 zynx_port_scanner.py
```

## 🖥️ TUI menu

| Key | Option | Description |
|---:|---|---|
| `1` | Quick scan | Checks 25 frequently exposed TCP ports. |
| `2` | Common ports | Checks a broader curated list of commonly used ports. |
| `3` | Custom ports | Checks the ports you enter, such as `22,80,443,8080`. |
| `4` | Custom range | Checks an inclusive range, such as `1-1024` or `8000-9000`. |
| `5` | Full TCP scan | Checks all ports from `1` through `65535`. |
| `6` | View last results | Displays the open ports and captured banners from the most recent scan. |
| `7` | Export last results | Writes the most recent scan to CSV or JSON. |
| `8` | Performance settings | Changes the connection timeout and worker count. |
| `0` | Exit | Closes the application. |

Every scan asks for a hostname or IP address and requires you to type `YES` to confirm that you are authorized to scan it.

## ⚙️ Performance settings

| Setting | Allowed range | Default behavior |
|---|---:|---|
| Connection timeout | `0.2–5.0` seconds | `0.8` seconds |
| Concurrent workers | `16–512` | Automatically selected based on CPU count, capped at `256` |

More workers can improve throughput on high-latency networks, but they also use more system resources. A shorter timeout makes scans faster against responsive hosts but can miss ports that respond slowly or are filtered. Start with the defaults, then tune for your environment.

A full-range scan can take significantly longer than a quick or common-port scan, especially when many ports silently drop connection attempts.

## 📊 Banner grabbing notes

- Some services (such as SSH, FTP, SMTP, and POP3) send a greeting immediately after a TCP connection is established.
- HTTP and HTTPS ports in Zynx's probe list receive a small `HEAD /` request so the server can return response headers.
- Some services do not disclose banners. Zynx will report `No banner received` or a protocol-specific note rather than guessing.
- A banner is **not definitive proof** of the exact software or version. It may be hidden, modified, proxied, or misleading.
- This is a **TCP connect scanner**. It does not perform UDP scans, SYN/raw-packet scans, OS fingerprinting, vulnerability exploitation, or stealth/evasion.

## 📁 Project structure

```text
zynx-port-scanner/
├── zynx_port_scanner.py   # Complete scanner and interactive TUI
├── requirements.txt       # Python dependency
└── README.md              # Documentation
```

## 🧪 Example custom inputs

```text
Ports: 22,80,443,8080
Range: 1-1024
Range: 8000-8100
```

## 🛡️ Responsible use

Only scan systems for which you have authorization. Keep scans within the scope approved by the system owner, use conservative settings on shared or production networks, and follow applicable laws and organizational policies.

---

<div align="center">

**zynx** · Learn networking. Measure exposure. Stay authorized.

</div>
