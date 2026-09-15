"""
Local CyberForge preview with sample artifacts and training TCP listeners.
Real SSH and auditd require setup_vulnerabilities.sh on Ubuntu.
"""
import base64
import os
import socket
import threading
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from app import app

HOST = os.environ.get('HOST', '127.0.0.1')


def handle_client(conn, addr, port):
    try:
        conn.settimeout(4.0)
        if port == 7777:
            conn.sendall(b"CYBERLAB Recon Service 1.0\r\nTraining TCP port is open.\r\n")
        elif port == 9001:
            conn.sendall(b"Welcome to CyberLab raw sockets.\r\nLAB{socket_sleuth}\r\n")
        elif port == 8080:
            request_data = b""
            while b"\r\n\r\n" not in request_data and len(request_data) < 4096:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                request_data += chunk

            headers = {}
            for line in request_data.split(b"\r\n"):
                if b":" in line:
                    k, v = line.split(b":", 1)
                    headers[k.strip().lower()] = v.strip()

            expected = b"Basic " + base64.b64encode(b"student:learning")
            if headers.get(b"authorization") == expected:
                status = "200 OK"
                extra = "Set-Cookie: lab_session=LAB{http_is_a_postcard}; Path=/\r\n"
                body = b"Authenticated. Inspect the HTTP response headers in your packet capture.\n"
            else:
                status = "401 Unauthorized"
                extra = 'WWW-Authenticate: Basic realm="CyberLab"\r\n'
                body = b"Lab HTTP Basic authentication required.\n"

            response = (
                f"HTTP/1.1 {status}\r\n"
                f"Server: CyberLab-Cleartext/1.0\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"{extra}Connection: close\r\n\r\n"
            ).encode() + body
            conn.sendall(response)
        elif port == 2121:
            conn.sendall(b"220 CyberLab FTP Training 1.0 - intentional SITE LABFLAG disclosure\r\n")
            buffer = b""
            for _ in range(12):
                chunk = conn.recv(1024)
                if not chunk:
                    break
                buffer += chunk
                while b"\r\n" in buffer:
                    line, buffer = buffer.split(b"\r\n", 1)
                    cmd = line.decode("ascii", errors="replace").strip().upper()
                    if cmd == "SITE LABFLAG":
                        conn.sendall(b"200 LAB{verify_dont_assume}\r\n")
                    elif cmd == "QUIT":
                        conn.sendall(b"221 Goodbye\r\n")
                        return
                    elif cmd.startswith("USER "):
                        conn.sendall(b"331 Password required\r\n")
                    elif cmd.startswith("PASS "):
                        conn.sendall(b"530 Login disabled; training disclosure is unauthenticated\r\n")
                    elif cmd == "SYST":
                        conn.sendall(b"215 UNIX Type: L8 (training protocol)\r\n")
                    elif cmd == "FEAT":
                        conn.sendall(b"211 No optional features\r\n")
                    else:
                        conn.sendall(b"502 Command not implemented\r\n")
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def start_listener(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((HOST, port))
        sock.listen(16)
        print(f"[+] Listener active on port {port}")
    except Exception as e:
        print(f"[-] Could not bind port {port}: {e}")
        sock.close()
        return

    while True:
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, port), daemon=True)
            t.start()
        except Exception:
            break


def main():
    app.config['LAB_PREVIEW'] = True
    app.static_folder = str(Path(__file__).resolve().parent / 'preview_assets')
    ports = [7777, 9001, 8080, 2121]
    for p in ports:
        t = threading.Thread(target=start_listener, args=(p,), daemon=True)
        t.start()

    http_port = int(os.environ.get("PORT", "5050"))
    print(f"\n=======================================================")
    print(f"  Cybersecurity Fundamentals Lab is starting...")
    print(f"  Web Interface: http://{HOST}:{http_port}")
    print('  Preview only: real SSH, auditd, and target setup require the Ubuntu installer.')
    print(f"=======================================================\n")

    app.run(host=HOST, port=http_port, debug=False)


if __name__ == "__main__":
    main()
