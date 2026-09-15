#!/usr/bin/env bash
# Provision only a dedicated Ubuntu training VM on an isolated host-only network.
set -Eeuo pipefail
umask 022
trap 'printf "Provisioning failed at line %s. Correct the error and rerun.\n" "$LINENO" >&2' ERR

[[ $EUID -eq 0 ]] || { echo 'Run with sudo bash setup_vulnerabilities.sh' >&2; exit 1; }
source /etc/os-release
[[ ${ID:-} == ubuntu ]] || { echo 'This installer requires Ubuntu Server.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'A booted systemd Ubuntu VM is required (not an ordinary container).' >&2; exit 1; }
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SOURCE_DIR/app.py" && -f "$SOURCE_DIR/templates/index.html" ]] || { echo 'Keep app.py and templates/index.html beside this script.' >&2; exit 1; }
LAB_ROOT=/cyberlab
if id labuser >/dev/null 2>&1 && [[ ! -f /var/lib/cyberlab/managed-labuser ]]; then
    echo 'An existing labuser is not managed by this installer. Use a fresh dedicated VM.' >&2
    exit 1
fi
echo 'Installing local lab dependencies. Package installation requires an apt mirror or a prefilled apt cache.'
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-flask python3-gunicorn ncat openssh-server \
    openssl e2fsprogs sleuthkit auditd curl tcpdump
install -d -m 0755 "$LAB_ROOT/templates" "$LAB_ROOT/static/hidden_vault" "$LAB_ROOT/static/samples" \
    "$LAB_ROOT/evidence" /var/lib/cyberlab
if [[ "$SOURCE_DIR" != "$LAB_ROOT" ]]; then
    install -m 0644 "$SOURCE_DIR/app.py" "$LAB_ROOT/app.py"
    install -m 0644 "$SOURCE_DIR/templates/index.html" "$LAB_ROOT/templates/index.html"
fi
python3 -m venv --system-site-packages "$LAB_ROOT/venv"
"$LAB_ROOT/venv/bin/python" -c 'import flask, gunicorn'
id cyberlab-web >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin cyberlab-web
id cyberlab-svc >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin cyberlab-svc
if ! id labuser >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash labuser
    touch /var/lib/cyberlab/managed-labuser
fi
printf 'labuser:dragon\n' | chpasswd
chmod 0700 /home/labuser
install -d -m 0755 /etc/ssh/sshd_config.d /run/sshd
cat > /etc/ssh/sshd_config.d/00-cyberlab.conf <<'SSH'
# Intentionally weak credentials apply only to the dedicated training account.
Match User labuser
    PasswordAuthentication yes
    KbdInteractiveAuthentication no
    AllowTcpForwarding no
    X11Forwarding no
Match all
SSH
ssh-keygen -A
/usr/sbin/sshd -t
if ! /usr/sbin/sshd -T -C user=labuser,host=localhost,addr=127.0.0.1 | grep -q '^passwordauthentication yes$'; then
    echo 'Your SSH configuration overrides the lab drop-in. Enable its Include directive and rerun.' >&2
    exit 1
fi
systemctl enable --now ssh
systemctl restart ssh

# Ncat owns the TCP listeners. This bounded protocol handler runs per connection.
cat > "$LAB_ROOT/lab_support.py" <<'PY'
import base64
import hashlib
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path('/cyberlab')
STATIC = ROOT / 'static'


def send(data):
    sys.stdout.buffer.write(data if isinstance(data, bytes) else data.encode())
    sys.stdout.buffer.flush()


def listener(port):
    if port == 7777:
        send('CYBERLAB Recon Service 1.0\r\nTraining TCP port is open.\r\n')
    elif port == 9001:
        send('Welcome to CyberLab raw sockets.\r\nLAB{socket_sleuth}\r\n')
    elif port == 8080:
        first = sys.stdin.buffer.readline(4097)
        if not first or len(first) > 4096:
            return
        headers = {}
        for _ in range(40):
            line = sys.stdin.buffer.readline(4097)
            if not line or line in (b'\r\n', b'\n'):
                break
            if len(line) > 4096:
                return
            name, sep, value = line.partition(b':')
            if sep:
                headers[name.strip().lower()] = value.strip()
        else:
            return
        expected = b'Basic ' + base64.b64encode(b'student:learning')
        authorized = headers.get(b'authorization') == expected
        if authorized:
            status = '200 OK'
            extra = 'Set-Cookie: lab_session=LAB{http_is_a_postcard}; Path=/\r\n'
            body = b'Authenticated. Inspect the HTTP response headers in your packet capture.\n'
        else:
            status = '401 Unauthorized'
            extra = 'WWW-Authenticate: Basic realm="CyberLab"\r\n'
            body = b'Lab HTTP Basic authentication required.\n'
        send((f'HTTP/1.1 {status}\r\nServer: CyberLab-Cleartext/1.0\r\n'
              f'Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n'
              f'{extra}Connection: close\r\n\r\n').encode() + body)
    elif port == 2121:
        send('220 CyberLab FTP Training 1.0 - intentional SITE LABFLAG disclosure\r\n')
        for _ in range(12):
            line = sys.stdin.buffer.readline(1025)
            if not line or len(line) > 1024:
                return
            command = line.decode('ascii', errors='replace').strip().upper()
            if command == 'SITE LABFLAG':
                send('200 LAB{verify_dont_assume}\r\n')
            elif command == 'QUIT':
                send('221 Goodbye\r\n')
                return
            elif command.startswith('USER '):
                send('331 Password required\r\n')
            elif command.startswith('PASS '):
                send('530 Login disabled; training disclosure is unauthenticated\r\n')
            elif command == 'SYST':
                send('215 UNIX Type: L8 (training protocol)\r\n')
            elif command == 'FEAT':
                send('211 No optional features\r\n')
            else:
                send('502 Command not implemented\r\n')


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def artifacts():
    (STATIC / 'hidden_vault/index.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><title>Hidden vault</title><h1>Vault discovered</h1><p>LAB{unlinked_is_not_private}</p></html>\n')
    (STATIC / 'config.php.bak').write_text('<?php\n// Inert training backup; these credentials are dummy data.\n$DB_USER = "demo";\n$DB_PASSWORD = "not_a_real_secret";\n$LAB_TOKEN = "LAB{backups_belong_offline}";\n?>\n')
    (STATIC / 'directories.txt').write_text('images\ncss\njs\nbackups\nhidden_vault\nassets\n')
    (STATIC / 'passwords.txt').write_text('password\nsummer\nletmein\ndragon\nadmin\nwelcome\n')
    (STATIC / 'hashes.txt').write_text(hashlib.md5(b'admin').hexdigest() + '\n')
    (STATIC / 'samples/suspicious.bin').write_bytes(b'\x00\x01INERT TRAINING DATA\x00CYBERLAB_BEACON_V1\x00' + bytes(range(256)))
    (STATIC / 'samples/benign.bin').write_bytes(b'\x00\x01BENIGN CONTROL FILE\x00' + bytes(range(128)))
    subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-salt', '-pbkdf2', '-iter', '100000', '-md', 'sha256',
                    '-pass', 'pass:cyber123', '-out', str(STATIC / 'secret.enc')],
                   input=b'LAB{keys_unlock_evidence}\n', check=True)
    image = STATIC / 'evidence.img'
    with image.open('wb') as handle:
        handle.truncate(2 * 1024 * 1024)
    subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext4', '-b', '1024', '-I', '128', '-m', '0',
                    '-O', 'extent,filetype,^has_journal,^64bit,^metadata_csum,^orphan_file', str(image)], check=True)
    with tempfile.TemporaryDirectory(prefix='cyberlab-') as directory:
        note = Path(directory) / 'deleted-note.txt'
        note.write_text('Investigator note: LAB{deleted_is_not_erased}\n')
        subprocess.run(['debugfs', '-w', '-R', f'write {note} /deleted-note.txt', str(image)], check=True)
        subprocess.run(['debugfs', '-w', '-R', 'rm /deleted-note.txt', str(image)], check=True)
    recovered = subprocess.check_output(['blkls', str(image)])
    if b'LAB{deleted_is_not_erased}' not in recovered:
        raise RuntimeError('Deleted-file recovery self-test failed; refusing to publish a broken exercise')
    # Ethernet PCAP, two valid ICMP echo requests and two valid replies.
    with (STATIC / 'icmp.pcap').open('wb') as capture:
        capture.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index in range(4):
            reply = index % 2
            src, dst = ('192.0.2.20', '192.0.2.10') if reply else ('192.0.2.10', '192.0.2.20')
            payload = b'CYBERLAB_ICMP_DEMO'
            icmp = struct.pack('!BBHHH', 0 if reply else 8, 0, 0, 4242, index // 2 + 1) + payload
            icmp = icmp[:2] + struct.pack('!H', checksum(icmp)) + icmp[4:]
            ipv4 = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), index + 1, 0, 64, 1, 0,
                               socket.inet_aton(src), socket.inet_aton(dst))
            ipv4 = ipv4[:10] + struct.pack('!H', checksum(ipv4)) + ipv4[12:]
            frame = bytes.fromhex('0200000000020200000000010800') + ipv4 + icmp
            capture.write(struct.pack('<IIII', 1700000000 + index, 0, len(frame), len(frame)) + frame)
    manifest = []
    for artifact in sorted(STATIC.rglob('*')):
        if artifact.is_file() and artifact.name not in ('SHA256SUMS', 'audit.log'):
            manifest.append(f'{hashlib.sha256(artifact.read_bytes()).hexdigest()}  {artifact.relative_to(STATIC)}')
    (STATIC / 'SHA256SUMS').write_text('\n'.join(manifest) + '\n')


def audit_refresh():
    if os.geteuid() != 0:
        raise RuntimeError('audit-refresh must run as root on Ubuntu')
    note = ROOT / 'evidence/permission-demo.txt'
    note.write_text('Harmless text file for a real permission-change audit event.\n')
    subprocess.run(['/usr/bin/chmod', '4755', str(note)], check=True)
    subprocess.run(['/usr/bin/chmod', '0644', str(note)], check=True)
    # Audit delivery is asynchronous. Wait up to ten seconds for the event.
    for _ in range(20):
        result = subprocess.run(['ausearch', '-k', 'cyberlab_privilege', '-ts', 'recent', '--raw'], capture_output=True)
        if result.returncode == 0 and b'chmod' in result.stdout and b'success=yes' in result.stdout:
            temp = STATIC / 'audit.log.tmp'
            temp.write_bytes(result.stdout)
            temp.chmod(0o644)
            temp.replace(STATIC / 'audit.log')
            print('Exported real kernel audit records to /cyberlab/static/audit.log')
            return
        time.sleep(0.5)
    raise RuntimeError('No real audit event was recorded. Check auditd and auditctl -l; no fabricated log was substituted.')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'listener':
        try:
            listener(int(sys.argv[2]))
        except (BrokenPipeError, ConnectionResetError):
            pass
    elif sys.argv[1:] == ['artifacts']:
        artifacts()
    elif sys.argv[1:] == ['audit-refresh']:
        audit_refresh()
    else:
        raise SystemExit('Usage: lab_support.py {listener PORT|artifacts|audit-refresh}')
PY
chmod 0644 "$LAB_ROOT/lab_support.py"
"$LAB_ROOT/venv/bin/python" "$LAB_ROOT/lab_support.py" artifacts
cat > /etc/audit/rules.d/cyberlab.rules <<'AUDIT'
-w /cyberlab/evidence -p wa -k cyberlab_privilege
AUDIT
systemctl enable auditd
service auditd start
augenrules --load
auditctl -l | grep -q cyberlab_privilege || { echo 'The lab audit rule did not load; immutable audit rules may require a reboot.' >&2; exit 1; }
"$LAB_ROOT/venv/bin/python" "$LAB_ROOT/lab_support.py" audit-refresh

cat > /etc/systemd/system/cyberlab-listener@.service <<'SERVICE'
[Unit]
Description=CyberLab Ncat training listener on TCP %i
After=network.target

[Service]
Type=simple
User=cyberlab-svc
Group=cyberlab-svc
WorkingDirectory=/cyberlab
ExecStart=/usr/bin/ncat --listen --keep-open --max-conns 32 --idle-timeout 8s --sh-exec "/cyberlab/venv/bin/python /cyberlab/lab_support.py listener %i" 0.0.0.0 %i
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictSUIDSGID=true
TasksMax=80
MemoryMax=256M

[Install]
WantedBy=multi-user.target
SERVICE
cat > /etc/systemd/system/cyberlab-web.service <<'SERVICE'
[Unit]
Description=CyberLab offline Flask room
After=network.target

[Service]
Type=simple
User=cyberlab-web
Group=cyberlab-web
WorkingDirectory=/cyberlab
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/cyberlab/venv/bin/python -m gunicorn --bind 0.0.0.0:80 --workers 2 --threads 4 --timeout 30 --access-logfile - --error-logfile - app:app
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
SERVICE
chown root:root "$LAB_ROOT" "$LAB_ROOT/app.py" "$LAB_ROOT/lab_support.py" "$LAB_ROOT/templates/index.html"
chmod 0644 "$LAB_ROOT/app.py" "$LAB_ROOT/lab_support.py" "$LAB_ROOT/templates/index.html"
find "$LAB_ROOT/static" -type d -exec chmod 0755 {} +
find "$LAB_ROOT/static" -type f -exec chmod 0644 {} +
systemctl daemon-reload
for port in 7777 9001 8080 2121; do
    systemctl enable "cyberlab-listener@$port"
    systemctl restart "cyberlab-listener@$port"
done
systemctl enable cyberlab-web
systemctl restart cyberlab-web
for attempt in {1..20}; do
    if curl -fsS http://127.0.0.1/api/health | "$LAB_ROOT/venv/bin/python" -c 'import json,sys; sys.exit(json.load(sys.stdin)["status"] != "ready")'; then break; fi
    if [[ $attempt -eq 20 ]]; then
        echo 'Services did not become healthy. Inspect journalctl -u cyberlab-web and listener units.' >&2
        exit 1
    fi
    sleep 1
done
curl -fsS --user student:learning http://127.0.0.1:8080/ >/dev/null
printf 'SITE LABFLAG\r\nQUIT\r\n' | ncat --idle-timeout 3s 127.0.0.1 2121 | grep -q 'LAB{verify_dont_assume}'
echo
echo 'CyberLab is ready. Open http://<Ubuntu-host-only-IP>/ from Kali.'
echo 'Find the address with: ip -4 -br address'
echo 'Services start automatically after reboot. No cloud service is used at runtime.'
echo 'If UFW is active, allow ports 22,80,2121,7777,8080,9001 only on your host-only interface.'
echo 'Refresh the audit exercise: sudo /cyberlab/venv/bin/python /cyberlab/lab_support.py audit-refresh'
