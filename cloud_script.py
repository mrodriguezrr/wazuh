#!/usr/bin/env python3

import socket
import ssl
import sys
import time
from struct import pack
import concurrent.futures

DEFAULT_TCP_PORT = 1514
DEFAULT_TLS_PORT = 1515
DEFAULT_TIMEOUT = 10


def tcp_ping(addr, port):
    ping_str = b"#ping"
    pong_str = b"#pong"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(DEFAULT_TIMEOUT)
        sock.connect((addr, port))

        buffer = pack("<I", len(ping_str)) + ping_str
        sock.send(buffer)

        response = sock.recv(64)
        sock.close()
        if response[4:] != pong_str:
            print(f"[✗] Invalid response: {response[4:]}")
            return False
        else:
            print("[✓] Valid response")
            return True

    except Exception as e:
        print(f"[!] TCP ping error: {e}")
        return False


def tls_ping(addr, port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    message = "Echo\n"

    try:
        t0 = time.time()
        raw_sock = socket.create_connection((addr, port), timeout=DEFAULT_TIMEOUT)
        t1 = time.time()

        ssl_sock = context.wrap_socket(raw_sock, server_hostname=addr)
        t2 = time.time()

        ssl_sock.sendall(message.encode())

        response = ssl_sock.recv(4096)
        t3 = time.time()

        ssl_sock.shutdown(socket.SHUT_RDWR)
        ssl_sock.close()

        print(f"[+] TCP connection time: {t1 - t0:.4f}s")
        print(f"[+] TLS handshake time: {t2 - t1:.4f}s")
        print(f"[+] Message+Response time: {t3 - t2:.4f}s")
        print(f"[+] Total time: {t3 - t0:.4f}s")
        if response.startswith(b"ERROR: Invalid request for new agent"):
            print("[!] Server response: OK")
            return True
        else:
            print(f"[+] Server response:\n{response.decode(errors='ignore')}")

        return True

    except Exception as e:
        print(f"[!] TLS ping error: {e}")
        return False


def run_with_timeout(func, *args, timeout=DEFAULT_TIMEOUT):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(func, *args)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            print(f"[!] Timeout reached ({timeout} seconds)")
            return False


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <address>[:<port>]")
        sys.exit(1)

    address_input = sys.argv[1]

    if ":" in address_input:
        host, port = address_input.split(":", 1)
        port = int(port)
    else:
        host = address_input
        port = DEFAULT_TCP_PORT

    print(f"[+] Connecting to {host}:{port}")

    if port == DEFAULT_TCP_PORT:
        print("[+] Mode detected: TCP Ping (#ping/#pong)")
        success = run_with_timeout(tcp_ping, host, port)
    elif port == DEFAULT_TLS_PORT:
        print("[+] Mode detected: TLS Echo Test")
        success = run_with_timeout(tls_ping, host, port)
    else:
        print(f"[!] Unknown port {port}, only 1514=TCP or 1515=TLS supported")
        sys.exit(1)

    if success:
        print("[✓] Ping successful")
        sys.exit(0)
    else:
        print("[✗] Ping failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
