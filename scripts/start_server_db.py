#!/usr/bin/env python3
import socket
import ssl
import traceback
from .db import insert_message

HOST = "127.0.0.1"
PORT = 8443

CERT_DIR = "certs"
SERVER_CERT = f"{CERT_DIR}/server.cert.pem"
SERVER_KEY  = f"{CERT_DIR}/server.key.pem"
CA_CERT     = f"{CERT_DIR}/ca.cert.pem"

def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.load_verify_locations(CA_CERT)
    context.verify_mode = ssl.CERT_REQUIRED

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[server-db] listening on {HOST}:{PORT} ... (CTRL+C to stop)")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    client_conn, addr = ssock.accept()
                except KeyboardInterrupt:
                    print("\n[server-db] shutting down")
                    break

                print(f"[server-db] connection from {addr}")
                try:
                    data = client_conn.recv(4096)
                    if not data:
                        client_conn.close()
                        continue
                    msg = data.decode().strip()
                    print(f"[server-db] received: {msg}")

                    # save to DB (safe)
                    try:
                        insert_message(sender_ip=addr[0], message=msg)
                        client_conn.sendall(b"ACK: " + data)
                        print("[server-db] saved to DB")
                    except Exception as e:
                        # print full traceback for debugging
                        print("[server-db] DB error:")
                        traceback.print_exc()
                        client_conn.sendall(b"NACK: DB error")

                except Exception:
                    print("[server-db] unexpected error:")
                    traceback.print_exc()
                finally:
                    client_conn.close()

if __name__ == "__main__":
    main()
