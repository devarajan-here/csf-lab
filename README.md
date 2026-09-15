# Cybersecurity Fundamentals Hands-on Lab

The CyberForge interface includes a landing page, operator dashboard, module cards, and individual mission pages. All 15 modules remain unlocked. Completion history migrates automatically from the original room on the same browser origin; Copy IP, progress reset, and service health remain available.

For a local development preview, install Flask and run `python run_lab.py`, then open `http://127.0.0.1:5050/`. This starts four training listeners and serves the supplied sample artifacts from `preview_assets/`. It does not emulate SSH or provision auditd. A banner identifies the preview; use the Ubuntu installer below for the real target. Set `PORT` to change the preview port. The preview defaults to loopback; use `HOST` only if you deliberately want another bind address. Lesson commands are designed for the Ubuntu target on HTTP port 80, so a port-5050 preview is not a substitute for completing the lab on Kali.

A self-hosted, beginner-friendly room with 15 Kali exercises against one Ubuntu VM. The deployed application uses no OpenAI API, CDN, external font, analytics, or cloud service. GPT-6 Astra is a development aid; see [ASTRA_DEVELOPMENT_PLAN.md](ASTRA_DEVELOPMENT_PLAN.md).

## Deploy the three files

Use a **dedicated Ubuntu Server 24.04 LTS VM** and a Kali VM on the same **host-only network**. These services deliberately expose weak credentials and vulnerable behavior. This is a training deployment, not a service to expose to the Internet or a corporate LAN. Take a clean VM snapshot first.

Keep these files together on Ubuntu:

```text
cyberlab-source/
├── setup_vulnerabilities.sh
├── app.py
└── templates/
    └── index.html
```

Provision from that directory:

```bash
sudo bash setup_vulnerabilities.sh
ip -4 -br address
```

Alternatively, clone this repository directly on the Ubuntu target:

```bash
sudo apt update
sudo apt install -y git
git clone https://github.com/devarajan-here/csf-lab.git
cd csf-lab
sudo bash setup_vulnerabilities.sh
```

For later updates, run `git pull --ff-only` in the same checkout and rerun the setup script. Rerunning setup regenerates the training artifacts and resets the managed lab account password. SSH credentials for your administrator account belong in your SSH client, not in this repository.

To apply only the CyberForge interface update to an already provisioned target, preserve its generated evidence by updating just the application files:

```bash
git pull --ff-only
sudo install -m 0644 app.py /cyberlab/app.py
sudo install -m 0644 templates/index.html /cyberlab/templates/index.html
sudo systemctl restart cyberlab-web
```

Open `http://<Ubuntu-host-only-IPv4>/` in Kali's browser. All displayed target commands use the browser's current hostname. Use the numeric IPv4 address rather than a name, since Netcat's `-n` option disables name resolution. If you change the VM's IP, open the room at the new address; commands update automatically. Browser completion history is per origin, so a changed IP has separate saved progress.

Initial Ubuntu package installation needs an apt mirror or a prepared offline package cache. A temporary NAT adapter can supply packages; remove that adapter before using the lab. After provisioning, both VMs can operate without Internet access. To distribute a completely offline installation, package the already-provisioned VM as an OVA along with a Kali VM containing the tools.

The script creates `/cyberlab`, a Python virtual environment using Ubuntu's packaged Flask/Gunicorn, an unprivileged SSH account `labuser` with password `dragon`, two service accounts, four Ncat systemd listeners, the web service, and an audit rule. Rerunning it resets generated lab artifacts and the managed lab password. It refuses to repurpose an unrelated existing `labuser`. It never runs the vulnerability setup on the developer's Windows host.

Flask is served by Gunicorn on port 80 under an unprivileged account with only the bind-port capability. `python app.py` is a development fallback, not the deployment command.

If UFW is already enabled, permit only the host-only interface. For example, **replace `enp0s8` with the actual host-only interface**:

```bash
sudo ufw allow in on enp0s8 to any port 22 proto tcp
sudo ufw allow in on enp0s8 to any port 80 proto tcp
sudo ufw allow in on enp0s8 to any port 2121 proto tcp
sudo ufw allow in on enp0s8 to any port 7777 proto tcp
sudo ufw allow in on enp0s8 to any port 8080 proto tcp
sudo ufw allow in on enp0s8 to any port 9001 proto tcp
```

The installer leaves the existing firewall policy intact. Its loopback health check cannot prove reachability from Kali. Existing custom SSH access restrictions may also require adjustment by the VM administrator; the intended target is a clean Ubuntu VM.

## Kali preparation

Before disconnecting Internet access, install the tool packages your Kali image lacks:

```bash
sudo apt update
sudo apt install nmap netcat-openbsd tcpdump wireshark gobuster nikto burpsuite \
  hydra john openssl metasploit-framework yara auditd sleuthkit autopsy curl
```

Snort is version-sensitive: install Snort 3 using the package available for your Kali release or the [official Snort distribution](https://www.snort.org/downloads), then check `snort -V`. The room provides both a Snort 3 command and a Snort 2 alternative. The supplied packet capture needs no network access. Run Wireshark as your regular user on a saved capture; if its permissions prevent reading, use `sudo chmod a+r /tmp/cyberlab-http.pcap` after stopping tcpdump.

## Exercises and evidence

| # | Tool | Actual target / evidence | Completion evidence |
|---|---|---|---|
| 1 | Nmap | TCP 7777 Ncat banner service | Open state |
| 2 | Netcat | TCP 9001 Ncat greeting | Banner token |
| 3 | Tcpdump | Kali-generated ICMP echo traffic | Echo request type |
| 4 | Wireshark | TCP 8080 HTTP Basic listener | Response session cookie |
| 5 | Gobuster | `/static/hidden_vault/` and local wordlist | Vault token |
| 6 | Nikto | `/static/config.php.bak` | Backup token; direct confirmation included |
| 7 | Burp Suite | POST `/challenge/burp` form field | Token after role tampering |
| 8 | Hydra | Real SSH on TCP 22 | Weak labuser password |
| 9 | John Jumbo | `/static/hashes.txt` | Recovered raw-MD5 plaintext |
| 10 | OpenSSL | `/static/secret.enc` | Decrypted note token |
| 11 | Metasploit | TCP 2121 lab FTP-like disclosure | `SITE LABFLAG` response after banner scan |
| 12 | Snort | `/static/icmp.pcap` and student-written rule | Alert signature ID |
| 13 | YARA | Inert suspicious and benign samples | Matching rule name |
| 14 | Auditd | `/static/audit.log` from real permission changes | Responsible executable |
| 15 | Autopsy / Sleuth Kit | `/static/evidence.img` | Token carved from unallocated blocks |

The Metasploit exercise implements an intentional information-disclosure backdoor, **not vsftpd's historical CVE or a remote shell**. Scanner output alone is never claimed to prove an exploit. The HTTP 8080 listener implements just enough HTTP for its lesson, and the FTP-like listener implements a bounded set of commands.

The 2 MiB image is ext4 with journaling and selected modern metadata features disabled for size and Sleuth Kit compatibility. It contains a real file written and deleted through debugfs. Provisioning fails if `blkls` cannot recover its token. The image has no partition table; analyze at offset zero. SHA-256 checksums for generated non-audit artifacts are at `/static/SHA256SUMS`.

Auditd records real Linux kernel events. The installer applies a watch, temporarily changes a harmless text file to 4755, restores 0644, and exports matching records. It fails if real audit evidence cannot be obtained. It does not grant labuser sudo access or pretend Ubuntu hosts Windows Sysmon. To generate another event on Ubuntu:

```bash
sudo /cyberlab/venv/bin/python /cyberlab/lab_support.py audit-refresh
```

The interface exposes lesson metadata but does not serialize the private answer dictionary. Several conceptual lessons necessarily show information used in their answers. This is a learning aid with localStorage progress, not an exam system or an authenticated multi-user scoreboard. `/api/verify` checks submitted answers, not whether the student executed a command.

## Operate and troubleshoot

```bash
curl http://127.0.0.1/api/health
sudo systemctl status cyberlab-web
sudo systemctl status cyberlab-listener@7777 cyberlab-listener@9001 \
  cyberlab-listener@8080 cyberlab-listener@2121
sudo journalctl -u cyberlab-web -n 50 --no-pager
sudo ss -lntp
sudo auditctl -l
```

“Active” means the web app can connect to every expected TCP port; it is a reachability check, not full protocol or artifact verification. “Partial” lists unavailable ports on hover. If another web server occupies port 80, stop or reconfigure that server before provisioning.

For a clean restart:

```bash
sudo systemctl restart cyberlab-web cyberlab-listener@7777 cyberlab-listener@9001 \
  cyberlab-listener@8080 cyberlab-listener@2121
```

On Kali, Burp's `127.0.0.1:8080` is the local proxy; the target's `<Ubuntu-IP>:8080` is a separate HTTP exercise. When capturing live packets, start the capture before generating traffic and use a second terminal. Nikto findings depend on its installed database; the direct backup request is included to confirm the underlying exposure.

## Development verification

The repository includes Flask behavior tests and browser checks. They do not provision vulnerable host services:

```bash
python -m venv .venv
source .venv/bin/activate
pip install Flask pytest
pytest -q
bash -n setup_vulnerabilities.sh
```

Full release acceptance requires running the installer on a fresh Ubuntu VM, completing all 15 commands from Kali, rebooting Ubuntu, and repeating the network checks. A container can validate artifact generation and protocol handlers but cannot replace the real SSH/auditd/systemd VM check.
