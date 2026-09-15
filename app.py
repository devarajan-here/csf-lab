"""Offline Cybersecurity Fundamentals room. Provision on Ubuntu with the setup script."""
import hmac
import os
import socket
from pathlib import Path

from flask import Flask, jsonify, render_template, request

ROOT = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=str(ROOT / "static"))
app.config.update(MAX_CONTENT_LENGTH=4096, TEMPLATES_AUTO_RELOAD=True)
app.jinja_env.auto_reload = True


def task(number, title, category, minutes, analogy, theory, steps, command, flags,
         question, answer, hint, flow):
    return dict(id=number, title=title, category=category, minutes=minutes,
                analogy=analogy, theory=theory, steps=steps, command=command,
                flags=[dict(argument=a, meaning=b) for a, b in flags],
                question=question, answer=answer, hint=hint, flow=flow)


MODULES = [
    task(1, "Nmap · Map the attack surface", "Reconnaissance", 8,
         "Imagine checking which doors in a building are open. A port is a numbered door; a listening service is someone answering it.",
         "A TCP connect scan completes the TCP handshake. Service detection then sends probes to identify what is answering. An open port is exposure, not proof of a vulnerability. Our training service listens on TCP 7777.",
         ["Open a Kali terminal. Only scan your Ubuntu lab VM.", "Run the command and find the PORT and STATE columns.", "Submit the state of port 7777."],
         "nmap -sT -sV -Pn -p 7777 {IP}",
         [("nmap", "Network discovery and service-scanning tool."), ("-sT", "Complete a TCP connection; no raw-socket privileges required."), ("-sV", "Probe the service to identify its banner/version."), ("-Pn", "Skip host discovery and treat the target as online."), ("-p 7777", "Scan only TCP port 7777."), ("{IP}", "Your Ubuntu target address.")],
         "What STATE does Nmap report for TCP port 7777?", "open",
         "Read the STATE column, not the service name. If filtered, check the VM network and firewall.",
         ["TCP connect + probes", "7777 · training banner", "Port state + service"]),
    task(2, "Netcat · Talk to a socket", "Networking", 6,
         "Netcat is a telephone for a network port: dial an address and listen to what the other side says.",
         "A TCP socket transports bytes without interpreting them. Banner grabbing reads a service's greeting. Banners can disclose information, but the text is an untrusted claim about the service.",
         ["Connect to port 9001.", "Read the greeting before the server closes the connection.", "Copy the complete LAB{...} token."],
         "nc -nv -w 3 {IP} 9001",
         [("nc", "Netcat reads and writes a network socket."), ("-n", "Use numeric addresses without DNS resolution; open this room using the numeric VM IP."), ("-v", "Show connection diagnostics."), ("-w 3", "Use a three-second timeout."), ("{IP}", "Ubuntu's numeric address."), ("9001", "Destination TCP port.")],
         "Which token does the banner reveal?", "LAB{socket_sleuth}",
         "The token appears on its own line after the welcome banner.",
         ["TCP connection", "9001 · Netcat listener", "Greeting + token"]),
    task(3, "Tcpdump · See ICMP packets", "Packet analysis", 10,
         "Packet capture is a camera at a doorway. A capture filter tells the camera which visitors to record.",
         "Tcpdump uses Berkeley Packet Filter expressions to select packets. ICMP echo request is type 8 and echo reply is type 0 for IPv4. Capture on Kali while generating traffic from Kali so the packets actually pass your sensor.",
         ["Run the capture in terminal A; leave it waiting.", "In terminal B run the displayed ping command.", "Find the outgoing echo request and submit its ICMP type number. Stop a waiting capture with Ctrl+C if needed."],
         "# Terminal A\nsudo tcpdump -i any -nn -v -c 4 'icmp and host {IP}'\n# Terminal B\nping -c 2 {IP}",
         [("sudo", "Allow packet capture using elevated privileges on Kali."), ("tcpdump", "Print captured packet summaries."), ("-i any", "Capture across Kali's interfaces."), ("-nn", "Do not resolve addresses or port numbers into names."), ("-v", "Show additional packet details."), ("-c 4", "Stop after four matching packets (two requests and two replies)."), ("'icmp and host {IP}'", "BPF: capture only ICMP involving the target."), ("ping", "Generate ICMP echo requests."), ("-c 2", "Send two echo requests."), ("{IP}", "The host to ping.")],
         "What is the IPv4 ICMP type number for an echo request?", "8",
         "Request is type 8; reply is type 0. Capture filters differ from Wireshark display filters.",
         ["ICMP echo request", "Ubuntu IP stack", "ICMP echo reply"]),
    task(4, "Wireshark · Inspect cleartext authentication", "Packet analysis", 12,
         "HTTP without TLS is a postcard: anyone who can observe the route can read its contents, including credentials and session cookies.",
         "HTTP Basic authentication encodes username:password in Base64; it does not encrypt it. The listener on 8080 accepts student:learning and returns a lab session cookie. Inspect both the Authorization request header and Set-Cookie response header. Only the second contains your answer.",
         ["Start terminal A's capture, then run curl in terminal B.", "After curl finishes, stop tcpdump with Ctrl+C and open the saved capture in Wireshark as your normal Kali user.", "Apply http as the display filter. If necessary, use Analyze → Decode As → HTTP for TCP 8080. Follow the TCP stream and find Set-Cookie."],
         "# Terminal A\nsudo tcpdump -i any -s 0 -U -w /tmp/cyberlab-http.pcap 'tcp port 8080 and host {IP}'\n# Terminal B\ncurl --http1.1 --user student:learning http://{IP}:8080/\n# After stopping the capture\nwireshark -r /tmp/cyberlab-http.pcap",
         [("sudo tcpdump", "Capture packets with the required privileges."), ("-i any", "Listen on Kali's interfaces."), ("-s 0", "Capture complete packets."), ("-U", "Flush each packet into the capture file."), ("-w /tmp/cyberlab-http.pcap", "Save a PCAP file to this path."), ("'tcp port 8080 and host {IP}'", "Capture only the lab HTTP conversation."), ("curl", "Send an HTTP request."), ("--http1.1", "Use HTTP/1.1 for readable text headers."), ("--user student:learning", "Send the provided demonstration Basic credentials."), ("http://{IP}:8080/", "The deliberately cleartext lab endpoint."), ("wireshark -r /tmp/cyberlab-http.pcap", "Open the saved capture in Wireshark.")],
         "What is the value of the lab_session cookie (without the cookie name)?", "LAB{http_is_a_postcard}",
         "Look at the server's HTTP 200 response, then Set-Cookie: lab_session=...; Path=/.",
         ["HTTP Basic credentials", "8080 · cleartext HTTP", "Set-Cookie header"]),
    task(5, "Gobuster · Discover a hidden directory", "Web discovery", 8,
         "A website is a building with rooms. Even if a room is absent from the map, trying likely door labels can reveal it.",
         "Directory enumeration requests candidate paths and compares responses. A hidden URL is not access control. The supplied small wordlist makes the exercise repeatable without downloading external lists.",
         ["Download the lab wordlist.", "Enumerate under /static/, then request the discovered hidden_vault directory.", "Submit the token in that directory's page."],
         "curl -fsS http://{IP}/static/directories.txt -o /tmp/cyberlab-directories.txt\ngobuster dir -u http://{IP}/static/ -w /tmp/cyberlab-directories.txt -t 5\ncurl -fsS http://{IP}/static/hidden_vault/",
         [("curl -fsS", "Download; fail on HTTP errors, hide progress, show errors."), ("-o /tmp/cyberlab-directories.txt", "Save the small local wordlist."), ("gobuster dir", "Run directory enumeration."), ("-u http://{IP}/static/", "Base URL to enumerate."), ("-w /tmp/cyberlab-directories.txt", "Read candidate names from this file."), ("-t 5", "Use five concurrent workers."), ("http://{IP}/static/hidden_vault/", "Read the discovered directory's index page.")],
         "What token is inside the hidden vault?", "LAB{unlinked_is_not_private}",
         "Scan /static/, not just /. The wordlist contains the directory name.",
         ["Candidate GET requests", "/static/hidden_vault/", "HTTP 200 + vault"]),
    task(6, "Nikto · Find an exposed backup", "Web assessment", 10,
         "A backup left in a shop window is still readable, even if the original document is locked away.",
         "Nikto checks for common server weaknesses and exposed files. Scan the /static prefix where this room deliberately stores a configuration backup. Scanner databases differ; confirm any finding with a direct request. A .php.bak file here is served as text, never executed as PHP.",
         ["Run Nikto against the target with /static as its root prefix.", "Review its findings; directly request config.php.bak to verify exposure even if your Nikto database does not report that filename.", "Locate the backup token."],
         "nikto -nocheck -h http://{IP} -root /static -Tuning 123b\ncurl -fsS http://{IP}/static/config.php.bak",
         [("nikto", "Web server assessment tool."), ("-nocheck", "Skip the Internet update check for this offline exercise."), ("-h http://{IP}", "The target HTTP server."), ("-root /static", "Prefix scan requests with /static."), ("-Tuning 123b", "Select interesting files, misconfigurations, information disclosure, and software identification checks."), ("curl -fsS", "Fetch the evidence and report HTTP failures."), ("http://{IP}/static/config.php.bak", "Intentionally exposed text backup.")],
         "What LAB token appears in the exposed backup?", "LAB{backups_belong_offline}",
         "Read the LAB_TOKEN assignment in the downloaded backup. Other credentials there are dummy data.",
         ["Misconfiguration probes", "/static/config.php.bak", "Readable backup"]),
    task(7, "Burp Suite · Tamper with a request", "Web exploitation", 12,
         "Changing a visitor badge from guest to admin should not unlock a vault. This endpoint makes the mistake of trusting the badge you supply.",
         "Client-controlled form fields are untrusted. The challenge intentionally grants access when the role form parameter is admin. This demonstrates broken access control; a real service must derive authorization from a server-validated identity.",
         ["Open Burp Suite → Proxy and confirm the listener at 127.0.0.1:8080. Turn Intercept off for the first request.", "Send this command through Burp, find it in Proxy → HTTP history, and send it to Repeater.", "Change role=guest to role=admin in Repeater, send again, and inspect the JSON response."],
         "curl --noproxy '' -x http://127.0.0.1:8080 -X POST http://{IP}/challenge/burp -H 'Content-Type: application/x-www-form-urlencoded' --data 'role=guest'",
         [("curl", "Create a request visible to Burp."), ("--noproxy ''", "Ensure environment proxy exclusions do not bypass Burp."), ("-x http://127.0.0.1:8080", "Use Burp's proxy on Kali, not the target's port 8080."), ("-X POST", "Use the POST method."), ("http://{IP}/challenge/burp", "The dedicated authorization challenge."), ("-H 'Content-Type: application/x-www-form-urlencoded'", "Declare form-encoded data."), ("--data 'role=guest'", "Send a role field for you to edit in Repeater.")],
         "What flag does the tampered request return?", "LAB{never_trust_client_roles}",
         "The endpoint expects a form field, not JSON. Replace only guest with admin.",
         ["POST role=guest → admin", "/challenge/burp", "Authorization bypass"]),
    task(8, "Hydra · Test weak SSH credentials", "Password security", 10,
         "A weak lock can be opened by trying a few common keys. Online password guessing tests keys against a live login service.",
         "Hydra tries credentials against SSH. This target has a deliberately weak, unprivileged labuser account. Low concurrency keeps the exercise predictable. Password length, stronger authentication, and throttling reduce this exposure.",
         ["Download the tiny password list supplied by this room.", "Run Hydra only against your lab target. It stops on the first valid password.", "Submit the discovered password. The account has no sudo rights."],
         "curl -fsS http://{IP}/static/passwords.txt -o /tmp/cyberlab-passwords.txt\nhydra -l labuser -P /tmp/cyberlab-passwords.txt -t 2 -f ssh://{IP}",
         [("curl -fsS", "Download the lab password list and show errors."), ("-o /tmp/cyberlab-passwords.txt", "Save the password candidates."), ("hydra", "Test credentials against a supported login protocol."), ("-l labuser", "Use this one username."), ("-P /tmp/cyberlab-passwords.txt", "Read passwords from a file; uppercase P means a list."), ("-t 2", "Use two concurrent tasks."), ("-f", "Stop after a valid login is found for the host."), ("ssh://{IP}", "Target SSH on its default TCP port 22.")],
         "What is labuser's SSH password?", "dragon",
         "Find Hydra's successful login line. If SSH refuses connections, check the ssh service on Ubuntu.",
         ["Small password list", "22 · SSH / labuser", "Successful login"]),
    task(9, "John the Ripper · Crack a hash", "Password security", 10,
         "A hash is a fingerprint of a password. Offline cracking fingerprints candidate words and looks for a match.",
         "The supplied file contains one unsalted raw MD5 digest. MD5 is fast and unsuitable for password storage. John Jumbo supports the raw-md5 format. Unlike Hydra, cracking happens entirely on Kali after the files are downloaded.",
         ["Download the digest and supplied candidates.", "Run John and then its --show command, which also works if a previous attempt already cracked the hash.", "Submit the recovered plaintext password."],
         "curl -fsS http://{IP}/static/hashes.txt -o /tmp/cyberlab-hashes.txt\ncurl -fsS http://{IP}/static/passwords.txt -o /tmp/cyberlab-passwords.txt\njohn --format=raw-md5 --wordlist=/tmp/cyberlab-passwords.txt /tmp/cyberlab-hashes.txt\njohn --show --format=raw-md5 /tmp/cyberlab-hashes.txt",
         [("curl -fsS", "Fetch each evidence file, failing on HTTP errors."), ("-o /tmp/cyberlab-hashes.txt", "Save the raw hash."), ("-o /tmp/cyberlab-passwords.txt", "Save the candidate words."), ("john", "John the Ripper Jumbo password recovery tool."), ("--format=raw-md5", "Interpret the input as an unsalted MD5 hash."), ("--wordlist=/tmp/cyberlab-passwords.txt", "Try the supplied words."), ("/tmp/cyberlab-hashes.txt", "Input hash file."), ("--show", "Display previously recovered plaintext from John's pot file.")],
         "What plaintext password matches the MD5 digest?", "admin",
         "Use raw-md5, not md5crypt. If the format is unavailable, install Kali's John Jumbo package.",
         ["Download hash", "Static evidence", "Kali · offline cracking"]),
    task(10, "OpenSSL · Decrypt a file", "Cryptography", 10,
         "Encryption puts a document in a locked box. The cipher is the lock design; the password helps derive the key that opens it.",
         "This file uses AES-256-CBC with a salted PBKDF2 key derivation, SHA-256, and 100,000 iterations. Decryption must match those settings. CBC does not authenticate data; this exercise teaches compatibility, not a recommended format for new secure applications.",
         ["Download the encrypted file.", "Run the decryption command. At the password prompt enter cyber123; nothing appears while typing.", "Read the decrypted note and submit its token."],
         "curl -fsS http://{IP}/static/secret.enc -o /tmp/cyberlab-secret.enc\nopenssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -md sha256 -in /tmp/cyberlab-secret.enc -out /tmp/cyberlab-secret.txt\ncat /tmp/cyberlab-secret.txt",
         [("curl -fsS", "Download the encrypted artifact."), ("-o /tmp/cyberlab-secret.enc", "Save the ciphertext."), ("openssl enc", "Use OpenSSL's symmetric encryption utility."), ("-d", "Decrypt instead of encrypt."), ("-aes-256-cbc", "Select AES with a 256-bit key in CBC mode."), ("-pbkdf2", "Derive key and IV with PBKDF2."), ("-iter 100000", "Use the same iteration count as provisioning."), ("-md sha256", "Use SHA-256 in key derivation."), ("-in /tmp/cyberlab-secret.enc", "Read ciphertext from this file."), ("-out /tmp/cyberlab-secret.txt", "Write the plaintext here."), ("cat /tmp/cyberlab-secret.txt", "Display the recovered note.")],
         "What token is inside the decrypted note?", "LAB{keys_unlock_evidence}",
         "The passphrase is cyber123. Keep PBKDF2, iterations, and digest identical to the displayed command.",
         ["Download ciphertext", "AES-256-CBC artifact", "Kali · decryption"]),
    task(11, "Metasploit · Verify a lab backdoor", "Service assessment", 12,
         "A sign on a door tells you its name. Testing a hidden latch tells you whether it actually opens. Evidence is stronger than a label.",
         "Metasploit's FTP version scanner identifies our explicitly named CyberLab FTP training service on 2121. The service deliberately exposes a fixed SITE LABFLAG command without authentication. This is a real unauthorized information-disclosure path, not an implementation of the vsftpd CVE or an operating-system shell.",
         ["Run the Metasploit auxiliary scanner to collect the service banner.", "Verify the deliberately unauthenticated SITE command with Netcat.", "Submit the returned token. A banner alone cannot prove a real-world CVE."],
         "msfconsole -q -x 'use auxiliary/scanner/ftp/ftp_version; set RHOSTS {IP}; set RPORT 2121; run; exit'\nprintf 'SITE LABFLAG\\r\\nQUIT\\r\\n' | nc -w 3 {IP} 2121",
         [("msfconsole", "Start the Metasploit console."), ("-q", "Suppress the startup banner."), ("-x '...'; use auxiliary/scanner/ftp/ftp_version", "Execute console commands and select the FTP version scanner."), ("set RHOSTS {IP}", "Set the single authorized lab target."), ("set RPORT 2121", "Override FTP's default destination port."), ("run; exit", "Run the scanner, then exit the console."), ("printf 'SITE LABFLAG\\r\\nQUIT\\r\\n'", "Construct two FTP-style commands with CRLF line endings."), ("|", "Pipe those bytes into Netcat."), ("nc -w 3 {IP} 2121", "Connect to the lab FTP listener with a three-second timeout.")],
         "What does the unauthenticated SITE LABFLAG command disclose?", "LAB{verify_dont_assume}",
         "Read the response beginning 200. The banner is intentionally labelled as a training service.",
         ["FTP scan + SITE LABFLAG", "2121 · lab backdoor", "Unauthenticated token"]),
    task(12, "Snort · Write an intrusion rule", "Detection engineering", 15,
         "An intrusion rule is a smoke-alarm setting. It tells a sensor which event should cause an alert, but an alert still needs interpretation.",
         "Snort evaluates packet traffic against signatures. This exercise uses Snort 3 and a local deterministic PCAP with ICMP echo traffic between documentation-only addresses. The rule's itype:8 selects requests. The SID identifies your local rule; a detection is evidence of a match, not automatically an attack.",
         ["Check snort -V: this command targets Snort 3.", "Create the rule and download the supplied PCAP; no external traffic is needed.", "Read the alert's message. For Snort 2 use: sudo snort -q -c /tmp/cyberlab.rules -r /tmp/cyberlab-icmp.pcap -A console."],
         "cat > /tmp/cyberlab.rules <<'RULE'\nalert icmp any any -> any any (msg:\"CYBERLAB ICMP ECHO\"; itype:8; sid:1000001; rev:1;)\nRULE\ncurl -fsS http://{IP}/static/icmp.pcap -o /tmp/cyberlab-icmp.pcap\nsnort -q -R /tmp/cyberlab.rules -r /tmp/cyberlab-icmp.pcap -A alert_fast",
         [("cat > ... <<'RULE' ... RULE", "Write the literal rule into a file using a quoted shell heredoc."), ("alert icmp", "Generate an alert for matching ICMP packets."), ("any any -> any any", "Match any source and destination addresses/ports; ICMP itself has no ports."), ("msg:\"CYBERLAB ICMP ECHO\"", "Text emitted in the alert."), ("itype:8", "Select IPv4 echo request packets."), ("sid:1000001; rev:1", "Unique local signature ID and rule revision."), ("curl -fsS ... -o /tmp/cyberlab-icmp.pcap", "Download the offline packet evidence."), ("snort -q", "Run Snort with reduced startup output."), ("-R /tmp/cyberlab.rules", "Load this rule file in Snort 3."), ("-r /tmp/cyberlab-icmp.pcap", "Read the saved capture instead of a live interface."), ("-A alert_fast", "Print brief alerts to the console."), ("sudo; -c /tmp/cyberlab.rules; -A console", "Snort 2 alternative: elevate, read a configuration/rule file, and print console alerts.")],
         "What signature ID appears in the alert, between 1: and :1?", "1000001",
         "Look for [1:1000001:1]. If no alert appears, check your Snort major version and rule syntax.",
         ["Download PCAP + write rule", "Static ICMP evidence", "Kali · Snort alert"]),
    task(13, "YARA · Match a suspicious pattern", "Malware analysis", 12,
         "YARA is a detector dog trained on specific scents. Matching a marker identifies a sample worth examining; it does not prove malicious behavior.",
         "YARA rules combine byte or string patterns with Boolean conditions. The downloaded .bin files are inert training data and contain no executable malware. Your rule should match the distinctive marker in one sample and ignore the benign control.",
         ["Download both inert samples.", "Write the rule, scan each sample, and compare the results.", "Submit the rule name printed for the suspicious sample."],
         "curl -fsS http://{IP}/static/samples/suspicious.bin -o /tmp/cyberlab-suspicious.bin\ncurl -fsS http://{IP}/static/samples/benign.bin -o /tmp/cyberlab-benign.bin\ncat > /tmp/cyberlab.yar <<'RULE'\nrule CyberLabBeacon {\n  strings:\n    $marker = \"CYBERLAB_BEACON_V1\" ascii\n  condition:\n    $marker\n}\nRULE\nyara -s /tmp/cyberlab.yar /tmp/cyberlab-suspicious.bin\nyara -s /tmp/cyberlab.yar /tmp/cyberlab-benign.bin",
         [("curl -fsS ... -o ...", "Download each inert sample to its displayed output path."), ("cat > ... <<'RULE' ... RULE", "Write a literal YARA rule without shell expansion of $marker."), ("rule CyberLabBeacon", "Name the detection rule."), ("strings: $marker = ... ascii", "Define an ASCII string to find in the file."), ("condition: $marker", "Match when the defined string is present."), ("yara -s", "Scan and print matched strings with offsets."), ("/tmp/cyberlab.yar", "Path to your rule file."), ("/tmp/cyberlab-suspicious.bin; /tmp/cyberlab-benign.bin", "Scan targets, one per invocation.")],
         "Which rule name matches the suspicious sample?", "CyberLabBeacon",
         "The benign file should produce no matches. Match the rule name's capitalization exactly.",
         ["Download inert samples", "Marker + benign control", "Kali · YARA match"]),
    task(14, "Auditd · Investigate a permission change", "Host investigation", 15,
         "An audit log is a security desk's event book: who changed something, what they changed, and whether it succeeded.",
         "Linux auditd records kernel audit events. During provisioning, a rule watches /cyberlab/evidence and records chmod setting a harmless file to mode 4755, then restoring 0644. A regular text file is not a usable setuid program. Investigate the chmod process, the success field, and the cyberlab_privilege key. This is the Linux auditd branch; Windows Sysmon is not installed on Ubuntu.",
         ["Download the real audit records exported during provisioning.", "Use ausearch on Kali (from the auditd package) to interpret the syscall event.", "Find the executable that made the permission change. For another live event, run the provided refresh command at the Ubuntu console as its administrator."],
         "curl -fsS http://{IP}/static/audit.log -o /tmp/cyberlab-audit.log\nausearch -if /tmp/cyberlab-audit.log -k cyberlab_privilege -i",
         [("curl -fsS", "Download the exported audit evidence."), ("-o /tmp/cyberlab-audit.log", "Save the records locally."), ("ausearch", "Search and interpret Linux audit records."), ("-if /tmp/cyberlab-audit.log", "Read this input file rather than the system audit log."), ("-k cyberlab_privilege", "Select events tagged with this audit key."), ("-i", "Interpret numeric fields when possible.")],
         "What executable basename performed the permission change?", "chmod",
         "Look for exe=\"/usr/bin/chmod\" (or /bin/chmod) and success=yes. Ubuntu refresh: sudo /cyberlab/venv/bin/python /cyberlab/lab_support.py audit-refresh",
         ["Ubuntu permission change", "Kernel → auditd records", "Kali · ausearch"]),
    task(15, "Autopsy / Sleuth Kit · Recover deleted evidence", "Disk forensics", 18,
         "Deleting a file often removes its catalog entry before its contents are overwritten. Forensics looks for the remaining pages.",
         "The image is a 2 MiB raw ext4 filesystem with its journal disabled to fit the tiny disk. A text file was written and deleted with debugfs. Preserve the evidence: work on a copy, never mount it read-write. Sleuth Kit can inspect deleted entries; blkls extracts unallocated blocks for content carving. Autopsy can ingest the same raw image as a disk-image data source at offset zero.",
         ["Download and hash the original image, then make a working copy.", "Inspect deleted entries with fls. Extract unallocated space with blkls and locate the remaining text with strings.", "For GUI practice, create an Autopsy case, add the working image, select the filesystem, and examine deleted files/unallocated space. Submit the recovered LAB token."],
         "curl -fsS http://{IP}/static/evidence.img -o /tmp/cyberlab-evidence.img\nsha256sum /tmp/cyberlab-evidence.img\ncp /tmp/cyberlab-evidence.img /tmp/cyberlab-working.img\nfls -rd /tmp/cyberlab-working.img\nblkls /tmp/cyberlab-working.img > /tmp/cyberlab-unallocated.bin\nstrings -a /tmp/cyberlab-unallocated.bin | grep 'LAB{'",
         [("curl -fsS ... -o /tmp/cyberlab-evidence.img", "Download the original disk artifact."), ("sha256sum", "Record a SHA-256 hash to detect later changes."), ("cp original working", "Create a working copy."), ("fls -rd", "Recursively list deleted filesystem entries with Sleuth Kit."), ("/tmp/cyberlab-working.img", "Raw filesystem image; no partition-table offset is needed."), ("blkls", "Extract unallocated filesystem blocks by default."), ("> /tmp/cyberlab-unallocated.bin", "Save those blocks as raw bytes."), ("strings -a", "Search all input bytes for printable strings."), ("| grep 'LAB{'", "Keep lines containing the expected token prefix.")],
         "What token survives in the deleted file's unallocated blocks?", "LAB{deleted_is_not_erased}",
         "Use blkls on the working image, then strings on its output. Deleted metadata varies; unallocated-block recovery is the repeatable path.",
         ["Download raw image", "Deleted ext4 file", "Kali · recover contents"]),
]
TASKS = {module["id"]: module for module in MODULES}


@app.get("/")
def index():
    public = [{k: v for k, v in module.items() if k != "answer"} for module in MODULES]
    return render_template("index.html", modules=public, lab_preview=app.config.get("LAB_PREVIEW", False))


@app.get("/static/hidden_vault/")
def vault():
    return app.send_static_file("hidden_vault/index.html")


@app.get("/api/health")
def health():
    services = {}
    for port in (22, 7777, 9001, 8080, 2121):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                services[str(port)] = True
        except OSError:
            services[str(port)] = False
    return jsonify(status="ready" if all(services.values()) else "partial", services=services)


@app.post("/api/verify")
def verify():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(correct=False, message="Send a JSON object with task_id and answer."), 400
    task_id, answer = data.get("task_id"), data.get("answer")
    if type(task_id) is not int or task_id not in TASKS:
        return jsonify(correct=False, message="Unknown task."), 400
    if not isinstance(answer, str) or len(answer) > 256:
        return jsonify(correct=False, message="Enter an answer of at most 256 characters."), 400
    correct = hmac.compare_digest(answer.strip().encode(), TASKS[task_id]["answer"].encode())
    return jsonify(correct=correct, message=("Correct. Evidence verified — task complete." if correct
                   else "That does not match yet. Check the evidence and try the hint."))


@app.post("/challenge/burp")
def burp():
    if request.form.get("role") == "admin":
        return jsonify(access="granted", flag=TASKS[7]["answer"])
    return jsonify(access="denied", message="Guest role cannot access the lab vault."), 403


@app.errorhandler(413)
def too_large(_error):
    return jsonify(correct=False, message="Request too large; maximum body size is 4 KiB."), 413


@app.after_request
def response_headers(response):
    if request.path.startswith("/api/") or request.path == "/":
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "80")), debug=False)
