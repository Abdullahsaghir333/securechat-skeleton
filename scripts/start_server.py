#!/usr/bin/env python3
import socket
import ssl

HOST = "127.0.0.1"
PORT = 8443

CERT_DIR = "certs"
SERVER_CERT = f"{CERT_DIR}/server.cert.pem"
SERVER_KEY  = f"{CERT_DIR}/server.key.pem"
CA_CERT     = f"{CERT_DIR}/ca.cert.pem"

def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # Server presents its cert + key
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    # Trust the CA that signed client certs
    context.load_verify_locations(CA_CERT)
    # Require client to present a valid certificate signed by the CA
    context.verify_mode = ssl.CERT_REQUIRED

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[server] listening on {HOST}:{PORT} ... (CTRL+C to stop)")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    client_conn, addr = ssock.accept()
                except KeyboardInterrupt:
                    print("\n[server] shutting down")
                    break

                print(f"[server] connection from {addr}")
                try:
                    data = client_conn.recv(4096)
                    if not data:
                        client_conn.close()
                        continue
                    print(f"[server] received: {data.decode().strip()}")
                    client_conn.sendall(b"ACK: " + data)
                except Exception as e:
                    print("[server] error:", e)
                finally:
                    client_conn.close()

if __name__ == "__main__":
    main()
