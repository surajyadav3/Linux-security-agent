# Linux Security Agent

A lightweight Go agent that collects installed packages and performs 12 CIS Benchmark
security checks on a Linux host, reporting results to an AWS backend with a web dashboard.

## Architecture

```
Linux VM (Go agent)
    ├─ Collects: hostname, OS, kernel, installed packages (dpkg/rpm/apk)
    ├─ Runs: 12 CIS Benchmark checks
    └─ POST JSON ──► API Gateway ──► Lambda (ingest) ──► DynamoDB
                                                              │
Browser (frontend)  ◄── GET ─── API Gateway ──► Lambda (query)
```

## CIS Checks Implemented (12 total)

| ID | Check | Severity |
|----|-------|----------|
| CIS-5.3.1   | Password complexity (pam_pwquality) | High |
| CIS-5.4.1.1 | Password max age ≤ 365 days | Medium |
| CIS-5.2.8   | Root SSH login disabled | High |
| CIS-1.1.1   | Unused filesystems (cramfs/squashfs) disabled | Low |
| CIS-3.5.1   | Firewall active (ufw/firewalld/iptables) | High |
| CIS-2.2.1.1 | Time synchronization (chrony/ntpd) | Medium |
| CIS-4.1.1   | Auditd running | Medium |
| CIS-1.6.1   | AppArmor/SELinux enabled | High |
| CIS-6.1.10  | No world-writable files in /etc /usr /bin | High |
| CIS-1.8.2   | GDM auto-login disabled | Medium |
| CIS-5.2.4   | SSH Protocol 2 only | High |
| CIS-1.3.1   | Filesystem integrity checker (AIDE) installed | Medium |

## Quick Start

### Step 1 — Deploy AWS backend (from Windows)

```powershell
# Requires: AWS CLI configured with your credentials
cd linux-security-agent\aws
.\deploy.ps1 -Region us-east-1
# Note the API Endpoint printed at the end
```

### Step 2 — Build the agent (from Windows, needs Go installed)

```powershell
.\build.ps1
# Produces: agent\linux-agent  (Linux amd64 binary)
```

**Install Go on Windows:** https://go.dev/dl/  (download the .msi installer)

### Step 3 — Copy to VM and run

```bash
# From Windows PowerShell
scp agent\linux-agent ubuntu@YOUR-VM-IP:/tmp/

# SSH into your VM
ssh ubuntu@YOUR-VM-IP

# Test locally first (prints JSON report)
chmod +x /tmp/linux-agent
/tmp/linux-agent -output -

# Send to AWS
/tmp/linux-agent -endpoint https://YOUR-API.execute-api.us-east-1.amazonaws.com/prod
```

### Step 4 — View dashboard

Open `frontend/index.html` in your browser, enter the API Gateway URL, click Connect.

---

### Install as .deb package (optional)

```bash
# On your Linux VM (needs dpkg-dev)
cd packaging
bash build-deb.sh
sudo dpkg -i linux-security-agent_1.0.0_amd64.deb
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /ingest | Agent posts its report here |
| GET  | /hosts | List all reporting agents |
| GET  | /apps/{agent_id} | Installed packages for a host |
| GET  | /cis-results/{agent_id} | CIS check results for a host |

## Project Structure

```
linux-security-agent/
├── agent/               # Go source — the agent binary
│   ├── main.go
│   ├── collector/
│   │   ├── system.go    # OS/hostname collection
│   │   ├── packages.go  # dpkg/rpm/apk enumeration
│   │   └── cis.go       # 12 CIS Benchmark checks
│   └── sender/
│       └── aws.go       # HTTP POST to API Gateway
├── lambda/
│   ├── ingest/handler.py  # Stores agent reports in DynamoDB
│   └── query/handler.py   # Serves REST API queries
├── frontend/            # Single-page dashboard (plain HTML/JS)
├── aws/
│   ├── cloudformation.yaml  # One-command infra deploy
│   └── deploy.ps1           # Deploy script (Windows)
├── packaging/           # .deb package builder
├── deploy/              # Systemd service + timer
└── build.ps1            # Cross-compile for Linux from Windows
```
# Linux-security-agent
