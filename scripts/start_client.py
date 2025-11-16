#!/usr/bin/env python3
import socket
import ssl
import sys

HOST = "127.0.0.1"
PORT = 8443

CERT_DIR = "certs"
CLIENT_CERT = f"{CERT_DIR}/client.cert.pem"
CLIENT_KEY  = f"{CERT_DIR}/client.key.pem"
CA_CERT     = f"{CERT_DIR}/ca.cert.pem"

def main(message="hello server"):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    # Trust CA that signed server cert
    context.load_verify_locations(CA_CERT)
    # Present client cert to server
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname="server") as ssock:
            print("[client] TLS established. sending message...")
            ssock.sendall(message.encode())
            data = ssock.recv(4096)
            print("[client] received:", data.decode())

if __name__ == "__main__":
    msg = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "hello server"
    main(msg)
