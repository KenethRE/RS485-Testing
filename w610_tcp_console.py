#!/usr/bin/env python3
"""
W610 TCP Console
----------------
Connect to a TCP server (e.g., USR-W610 Socket A in TCP Server mode) and send/receive raw data.

Features
- Interactive console or one-shot send.
- Send text or hex bytes.
- Optional CRLF append for text.
- Shows incoming as text and/or hex.
- Works with Python 3.7+ (stdlib only).

Examples
- Interactive (defaults to 10.10.100.254:8899):
    python w610_tcp_console.py -i

- Send one Modbus-RTU read request (hex), wait 2s for a reply:
    python w610_tcp_console.py --hex-send "01 03 00 00 00 02 C4 0B" --recv-timeout 2

- Send ASCII text with CRLF:
    python w610_tcp_console.py --send "STATUS" --append-crlf --recv-timeout 1

Interactive commands
- :hex <hexstring>   -> send raw hex bytes (spaces allowed)
- :text <string>     -> send text (use --append-crlf at launch if you want CRLF after each send)
- :quit              -> exit
"""
import argparse
import socket
import sys
import threading
import time
import select

def hex_to_bytes(s: str) -> bytes:
    clean = ''.join(c for c in s if c.strip())  # remove whitespace
    # allow spaces; also allow 0x prefix anywhere (strip it)
    clean = clean.replace('0x', '').replace('0X', '')
    clean = ''.join(c for c in clean if c in '0123456789abcdefABCDEF')
    if len(clean) % 2 != 0:
        raise ValueError("Hex string must have even length")
    return bytes(int(clean[i:i+2], 16) for i in range(0, len(clean), 2))

def bytes_to_hex(b: bytes) -> str:
    return ' '.join(f'{x:02X}' for x in b)

class Receiver(threading.Thread):
    def __init__(self, sock: socket.socket, show_hex: bool, show_text: bool):
        super().__init__(daemon=True)
        self.sock = sock
        self.alive = True
        self.show_hex = show_hex
        self.show_text = show_text

    def run(self):
        while self.alive:
            try:
                r, _, _ = select.select([self.sock], [], [], 0.25)
                if not r:
                    continue
                data = self.sock.recv(4096)
                if not data:
                    print("[i] Connection closed by remote.", flush=True)
                    break
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                if self.show_text:
                    # Replace undecodable bytes with dot
                    try:
                        text = data.decode('utf-8', errors='replace')
                    except Exception:
                        text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
                    print(f"[{ts}] <= {text}", flush=True)
                if self.show_hex:
                    print(f"[{ts}] <= [HEX] {bytes_to_hex(data)}", flush=True)
            except (OSError, ValueError) as e:
                print(f"[!] Receiver error: {e}", flush=True)
                break

def connect(ip: str, port: int, timeout: float = 5.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((ip, port))
    # optional: enable TCP keepalive
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    s.settimeout(None)  # use blocking + select
    return s

def interactive_loop(sock: socket.socket, append_crlf: bool, show_hex: bool, show_text: bool):
    rx = Receiver(sock, show_hex=show_hex, show_text=show_text)
    rx.start()
    print("Interactive mode. Commands: ':hex <hex>', ':text <msg>', ':quit'")
    try:
        while True:
            line = input(">> ").strip()
            if not line:
                continue
            if line.lower() in (":q", ":quit", "quit", "exit"):
                break
            if line.lower().startswith(":hex "):
                payload = line[5:].strip()
                try:
                    b = hex_to_bytes(payload)
                except ValueError as e:
                    print(f"[!] {e}")
                    continue
                sock.sendall(b)
                print(f"=> [HEX] {bytes_to_hex(b)}")
            elif line.lower().startswith(":text "):
                text = line[6:]
                if append_crlf:
                    text = text + "\r\n"
                b = text.encode('utf-8', errors='replace')
                sock.sendall(b)
                show = text.replace("\r", "\\r").replace("\n", "\\n")
                print(f"=> {show}")
            else:
                # default: treat as text
                text = line
                if append_crlf:
                    text = text + "\r\n"
                b = text.encode('utf-8', errors='replace')
                sock.sendall(b)
                show = text.replace("\r", "\\r").replace("\n", "\\n")
                print(f"=> {show}")
    except (KeyboardInterrupt, EOFError):
        print("\n[i] Exiting...")
    finally:
        rx.alive = False
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

def one_shot(sock: socket.socket, send_data: bytes, recv_timeout: float, show_hex: bool, show_text: bool):
    # Send
    sock.sendall(send_data)
    print(f"=> Sent {len(send_data)} bytes")
    # Receive for up to recv_timeout seconds
    end = time.time() + recv_timeout
    total = 0
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], 0.2)
        if not r:
            continue
        data = sock.recv(4096)
        if not data:
            print("[i] Connection closed by remote.")
            break
        total += len(data)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        if show_text:
            try:
                text = data.decode('utf-8', errors='replace')
            except Exception:
                text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
            print(f"[{ts}] <= {text}")
        if show_hex:
            print(f"[{ts}] <= [HEX] {bytes_to_hex(data)}")
    print(f"[i] Done. Received {total} bytes.")

def main():
    ap = argparse.ArgumentParser(description="W610 TCP Console (send/receive raw data)")
    ap.add_argument("--ip", default="192.168.0.115", help="Target IP (default: 10.10.100.254)")
    ap.add_argument("--port", type=int, default=8899, help="Target TCP port (default: 8899)")

    group = ap.add_mutually_exclusive_group()
    group.add_argument("--send", help="Send ASCII text once (use --append-crlf to add CRLF)")
    group.add_argument("--hex-send", help="Send raw bytes specified as hex once (e.g., '01 03 00 00 00 02 C4 0B')")
    ap.add_argument("-i", "--interactive", action="store_true", help="Interactive console mode")

    ap.add_argument("--append-crlf", action="store_true", help="Append CRLF (\\r\\n) after text sends")
    ap.add_argument("--recv-timeout", type=float, default=2.0, help="Seconds to wait for responses in one-shot mode (default: 2.0)")
    ap.add_argument("--show-hex", action="store_true", help="Print incoming bytes as HEX")
    ap.add_argument("--hide-text", action="store_true", help="Do not print incoming as text")

    args = ap.parse_args()

    if not (args.send or args.hex_send or args.interactive):
        ap.print_help()
        sys.exit(1)

    try:
        sock = connect(args.ip, args.port)
        print(f"[i] Connected to {args.ip}:{args.port}")
    except Exception as e:
        print(f"[!] Could not connect to {args.ip}:{args.port} - {e}")
        sys.exit(2)

    show_text = not args.hide_text
    show_hex = args.show_hex

    try:
        if args.interactive:
            interactive_loop(sock, append_crlf=args.append_crlf, show_hex=show_hex, show_text=show_text)
        else:
            if args.send is not None:
                data = args.send
                if args.append_crlf:
                    data += "\r\n"
                payload = data.encode('utf-8', errors='replace')
            else:
                try:
                    payload = hex_to_bytes(args.hex_send)
                except ValueError as e:
                    print(f"[!] {e}")
                    sock.close()
                    sys.exit(3)
            one_shot(sock, payload, args.recv_timeout, show_hex=show_hex, show_text=show_text)
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
    except KeyboardInterrupt:
        print("\n[i] Interrupted, closing.")
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

if __name__ == "__main__":
    main()
