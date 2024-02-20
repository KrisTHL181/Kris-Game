"""A module to processing WebSocket server and HTTP server."""

import threading
import socket
import time
import typing
import json
import os
import asyncio
from mimetypes import types_map as mime_types
from contextlib import suppress
from loguru import logger
import utils
import commands
import websockets


# TODO-later: 优化HTTP服务器性能
class HTTPServer(threading.Thread):
    """A basic HTTP server."""

    class ResponseBuilder:
        """A response builder for HTTP server."""

        def __init__(self):
            self.headers = []
            self.status = None
            self.content = None

        def add_header(self, header_key, header_value) -> None:
            """Add a response header."""
            head = f"{header_key}: {header_value}"
            self.headers.append(head)
            logger.debug(eval(utils.get_message("network.http_server.set_header", 0)))

        def set_status(self, status_code, status_message) -> None:
            """Setting response status."""
            self.status = f"HTTP/1.1 {status_code} {status_message}"
            logger.debug(eval(utils.get_message("network.http_server.set_status", 0)))

        def set_content(self, content) -> None:
            """Setting response content."""
            if isinstance(content, (bytes, bytearray)):
                self.content = content
                logger.debug(
                    eval(utils.get_message("network.http_server.set_string_content", 0))
                )

            else:
                self.content = content.encode("utf-8")
                logger.debug(
                    eval(utils.get_message("network.http_server.set_content", 0))
                )

        def build(self) -> bytes:
            """Build fully response."""
            response = f"{self.status}\r\n"
            for i in self.headers:
                response += i + "\r\n"
            response = f"{response}\r\n\r\n".encode("utf-8") + self.content
            logger.debug(eval(utils.get_message("network.http_server.reply_build", 0)))
            return response

    def __init__(self, host, port):
        threading.Thread.__init__(self)
        logger.debug(eval(utils.get_message("network.http_server.listening", 0)))
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self) -> typing.NoReturn:
        """Start HTTP Server."""
        self.setup_socket()
        self.accept()

    def setup_socket(self) -> None:
        """Init socket."""
        self.sock.bind((self.host, self.port))
        self.sock.listen(int(utils.query_config("LISTENS_COUNT")))
        self.sock.settimeout(int(utils.query_config("HTTP_TIMEOUT")))
        self.sock.setblocking(True)

    def accept_request(self, client_sock, client_addr) -> None:
        """Accept requests, process response and send response."""
        logger.debug(eval(utils.get_message("network.http_server.connect", 0)))
        data = b""
        while True:
            try:
                _data = client_sock.recv(1024, socket.MSG_WAITALL)
            except Exception as conn_err:
                logger.error(
                    eval(utils.get_message("network.http_server.recv_error", 0))
                )
                logger.exception(conn_err)
                return None
            if not _data:
                break
            data += _data
        req = data.decode("utf-8")

        response = self.process_response(req)
        if not response:
            logger.warning(
                eval(utils.get_message("network.http_server.recv_no_msg", 0))
            )
            return None
        client_sock.sendall(response)
        logger.debug(eval(utils.get_message("network.http_server.send_back", 0)))
        # clean up
        logger.debug(eval(utils.get_message("network.http_server.full", 0)))
        client_sock.shutdown(socket.SHUT_WR)
        client_sock.close()
        return None

    def accept(self) -> typing.NoReturn:
        """Accept requests forever."""
        while True:
            (client, address) = self.sock.accept()
            threading.Thread(target=self.accept_request, args=(client, address)).start()

    def process_response(self, request) -> bytes:
        """Processing response."""
        logger.debug(eval(utils.get_message("network.http_server.process_response", 0)))
        formatted_data = request.strip().split("\n")
        request_words = formatted_data[0].split()

        if len(request_words) == 0:
            return b""

        requested_file = request_words[1][1:]
        if request_words[0] == "GET":
            return self.get_request(requested_file, formatted_data)
        if request_words[0] == "POST":
            return self.post_request(requested_file, formatted_data)
        if request_words[0] == "HEAD":
            return self.head_request(requested_file, formatted_data)
        return self.method_not_allowed()

    def has_permission_other(self, requested_file) -> bool:
        """Check readable permissions"""
        return os.access(requested_file, os.R_OK)

    def should_return_binary(self, filename) -> bool:
        """Check file is binary"""
        logger.debug(eval(utils.get_message("network.http_server.check_binary", 0)))
        with open(filename, "rb") as file:
            logger.debug(
                eval(utils.get_message("network.http_server.file_contents", 0))
            )
            return bool(
                file.read().translate(
                    None,
                    bytearray(
                        {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F}
                    ),
                )
            )

    def get_file_binary_contents(self, filename) -> bytes:
        """Get (binary) file content."""
        logger.debug(eval(utils.get_message("network.http_server.file_contents", 0)))
        with open(filename, "rb", encoding="utf-8") as file:
            return file.read()

    def get_file_contents(self, filename) -> str:
        """Get (plaintext) file content."""
        logger.debug(eval(utils.get_message("network.http_server.file_contents", 0)))
        with open(filename, "r", encoding="utf-8") as file:
            return file.read()

    def get_request(self, requested_file, data) -> bytes:
        """Get request messages."""
        if not requested_file:
            requested_file = "index.html"
        if not os.path.exists(requested_file):
            return self.resource_not_found()
        if not self.has_permission_other(requested_file):
            return self.resource_forbidden()
        builder = self.ResponseBuilder()

        if self.should_return_binary(requested_file):
            builder.set_content(self.get_file_binary_contents(requested_file))
        else:
            builder.set_content(self.get_file_contents(requested_file))

        builder.set_status("200", "OK")

        builder.add_header("Connection", "close")
        builder.add_header(
            "Content-Type",
            mime_types["." + requested_file.split(".")[-1]] + "; charset=utf8",
        )
        builder.add_header("Connection", "close")
        builder.add_header(
            "Date",
            time.strftime(
                "%a, %d %b %Y %H:%M:%S GMT",
                time.localtime(os.path.getctime(requested_file)),
            ),
        )
        builder.add_header(
            "Last-Modified",
            time.strftime(
                "%a, %d %b %Y %H:%M:%S GMT",
                time.localtime(os.path.getmtime(requested_file)),
            ),
        )
        builder.add_header("Server", utils.query_config("HTTP_SERVER_NAME"))
        return builder.build()

    def method_not_allowed(self) -> bytes:
        """
        Returns 405 not allowed status and gives allowed methods.
        """
        builder = self.ResponseBuilder()
        builder.set_status("405", "METHOD NOT ALLOWED")
        allowed = ", ".join(["GET", "POST", "HEAD"])
        builder.add_header("Allow", allowed)
        builder.add_header("Connection", "close")
        return builder.build()

    def resource_not_found(self) -> bytes:
        """
        Returns 404 not found status and sends back our 404.html page.
        """
        builder = self.ResponseBuilder()
        builder.set_status("404", "NOT FOUND")
        builder.add_header("Connection", "close")
        builder.add_header("Content-Type", mime_types[".html"])
        builder.set_content(self.get_file_contents("./html_error/404.html"))
        return builder.build()

    def resource_forbidden(self) -> bytes:
        """
        Returns 403 FORBIDDEN status and sends back our 403.html page.
        """
        builder = self.ResponseBuilder()
        builder.set_status("403", "FORBIDDEN")
        builder.add_header("Connection", "close")
        builder.add_header("Content-Type", mime_types[".html"])
        builder.set_content(self.get_file_contents("./html_error/403.html"))
        return builder.build()

    def post_request(self, requested_file, data) -> bytes:
        """Processing post request."""
        builder = self.ResponseBuilder()
        builder.set_status("200", "OK")
        builder.add_header("Connection", "close")
        builder.add_header("Content-Type", mime_types[requested_file.rsplit(".")[-1]])
        builder.set_content(self.get_file_contents(requested_file))
        return builder.build()

    def head_request(self, requested_file, data):
        """Processing head request."""
        builder = self.ResponseBuilder()
        builder.set_status("200", "OK")
        builder.add_header("Connection", "close")
        builder.add_header("Content-Type", mime_types[requested_file.rsplit(".")[-1]])
        return builder.build()


async def ws_server(websocket, path):
    """A async function to processing websocket server."""
    # 采用JSON式
    # 将新连接的客户端添加到clients集合中
    async for message in websocket:
        logger.debug(eval(utils.get_message("network.ws_server.recived", 0)))
        try:
            data: dict = json.loads(str(message.replace("'", '"')), strict=False)
        except json.JSONDecodeError:
            logger.warning(
                eval(utils.get_message("network.ws_server.json_decode_error", 0))
            )
            continue
        else:
            if data.get("type") is None or data.get("content") is None:
                logger.warning(
                    logger.warning(
                        eval(
                            utils.get_message(
                                "network.ws_server.json_missing_keyword", 0
                            )
                        )
                    )
                )
                continue
        # 在前端接收数据包并显示
        if data["type"] == "send":
            if len(players) != 0:  # asyncio.wait doesn't accept an empty list
                if data["sender"] in utils.get_players():
                    if data["content"].startswith(
                        "/"
                    ):  # 以/为指令运行 0为正常 -1没权限 -2命令错 -3东西没找到
                        exec_ = commands.execute(
                            data["sender"], data["content"].replace("/", "", 1)
                        )
                        # message = json.dumps({"type": "system", "content": exec_})
                        message = json.dumps(
                            {
                                "type": "send",
                                "content": data["content"],
                                "sender": data["sender"],
                                "color": data["color"],
                            }
                        )
                        await asyncio.wait(
                            [user.send(message) for user in utils.get_websockets()]
                        )
                        message = json.dumps(
                            {
                                "type": "private",
                                "sender": utils.query_config("SYSTEM_NAME"),
                                "to": data["sender"],
                                "content": exec_,
                                "color": "#808080",
                            }
                        )
                    else:
                        message = json.dumps(
                            {
                                "type": "send",
                                "content": data["content"],
                                "sender": data["sender"],
                                "color": data["color"],
                            }
                        )
                        logger.info(eval(utils.get_message("network.player.send", 0)))
                else:
                    logger.info(
                        eval(utils.get_message("network.player.anonymous_send", 0))
                    )
                    continue
        elif data["type"] == "login":
            if data["content"] in utils.get_players():
                logger.warning(
                    eval(utils.get_message("network.player.duplicate_login", 0))
                )
                commands.kick(data["content"])
            if data["content"] in utils.banlist:
                logger.info(eval(utils.get_message("network.player.banned", 0)))
                await websocket.close()
                continue
            if len(utils.players) != 0:  # asyncio.wait doesn't accept an empty list
                message = json.dumps(
                    {"type": "login", "content": data["content"]}
                )  # content是名字
                utils.login_player(data["content"], websocket)
                logger.info(eval(utils.get_message("network.player.login", 0)))
        elif data["type"] == "logout":
            if len(utils.players) != 0:  # asyncio.wait doesn't accept an empty list
                message = json.dumps({"type": "logout", "content": data["content"]})
                utils.delete_player(data["content"])
                logger.info(eval(utils.get_message("network.logout", 0)))
                continue
        elif data["type"] == "paint":
            if len(utils.players) != 0:
                message = json.dumps({"type": "paint", "content": data["content"]})
                logger.info(eval(utils.get_message("network.player.update_paint", 0)))
        elif data["type"] == "heartbeat":
            if len(utils.players) != 0:
                message = json.dumps({"type": "heartbeat", "content": data["content"]})
                utils.get_player(data["content"]).last_heartbeat = time.time()
                logger.debug(eval(utils.get_message("network.player.keep_alive", 0)))
                continue
        elif data["type"] == "ready":
            utils.ACCEPT_PLAYERS += 1
            if utils.ACCEPT_PLAYERS == len(utils.players) >= utils.MIN_PLAYERS:
                message = json.dumps({"type": "start", "content": "Game_start"})
                logger.info(eval(utils.get_message("Game.Game_start", 0)))
            else:
                logger.info(eval(utils.get_message("network.player.ready", 0)))
                message = json.dumps({"type": "ready", "content": data["content"]})
        with suppress(Exception):
            await asyncio.wait([user.send(message) for user in utils.get_websockets()])


def run_ws_server():
    """Run the websocket server."""
    asyncio.set_event_loop(asyncio.new_event_loop())
    start_server = websockets.serve(
        ws_server, "0.0.0.0", int(utils.query_config("WS_PORT"))
    )
    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()
