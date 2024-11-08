#!/usr/bin/env python
"""A draw&guess game, includes websocket server and http server."""
from __future__ import annotations

import __main__
import ast
import asyncio
import atexit
import functools
import inspect
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import typing
from abc import ABCMeta, abstractmethod
from contextlib import suppress
from mimetypes import types_map as mime_types
from pathlib import Path

import websockets
from colorama import Fore
from colorama import init as colorama_init
from fuzzywuzzy import process
from loguru import logger
from rich.traceback import install as install_rich_traceback

MIN_PLAYERS: int = 2
ACCESSES: dict = {"server": 4, "admin": 3, "player": 2, "spectators": 1, "banned": 0}


class player:
    """A class for player."""

    def __init__(self, name: str, websocket, access: int = 2) -> None:
        """Create variables."""
        self.name = name
        self.websocket = websocket
        self.access = access
        self.score = 0
        self.last_heartbeat = time.time()


players = []
plugins = []
colorama_init(autoreset=True)


class utils(metaclass=ABCMeta):
    """A class to encapsulates codes."""

    @staticmethod
    @abstractmethod
    @functools.cache
    def get_message(eqalname: str, value: float) -> str:
        """Query message in language file."""
        try:
            return str(lang[eqalname + "." + str(value)]).strip()
        except KeyError:
            return f"'未定义的文本: {eqalname}'"

    @staticmethod
    @abstractmethod
    def get_players() -> list:
        """Get all player's name."""
        return [iter_player.name for iter_player in players]

    @staticmethod
    @abstractmethod
    def get_player(name: str) -> player:
        """Get player object by name."""
        if name == utils.query_config("SYSTEM_NAME"):
            return player(utils.query_config("SYSTEM_NAME"), None, ACCESSES["server"])

        return next(
            iter(
                [iter_player for iter_player in players if iter_player.name == name],
            ),
        )

    @staticmethod
    @abstractmethod
    def delete_player(name: str) -> None:
        """Remove a player from players list."""
        players.remove(utils.get_player(name))

    @staticmethod
    @abstractmethod
    def login_player(name: str, websocket) -> player:
        """Add 1 player to players list."""
        logined_player = player(name, websocket)
        players.append(name)
        return logined_player

    @staticmethod
    @abstractmethod
    def get_websocket(name: str):
        """Get player's websocket object."""
        return next(
            iter(
                [
                    iter_player.websocket
                    for iter_player in players
                    if iter_player.name == name
                ],
            ),
        )

    @staticmethod
    @abstractmethod
    def get_websockets() -> list:
        """Get all the player's websocket object."""
        return [iter_player.websocket for iter_player in players]

    @staticmethod
    @abstractmethod
    @functools.cache
    def query_config(key: str) -> str:
        """Query config in config file."""
        return str(config.get(key, f"'未定义的配置项: {key}'")).strip()

    @staticmethod
    @abstractmethod
    def reverse_replace(string: str, old: str, new: str, max_count: int = -1) -> str:
        """Reverse string and replace string."""
        reversed_string = string[::-1]
        reversed_old = old[::-1]
        reversed_new = new[::-1]

        if max_count == -1:
            reversed_result = reversed_string.replace(reversed_old, reversed_new)
        else:
            reversed_result = reversed_string.replace(
                reversed_old,
                reversed_new,
                max_count,
            )

        return reversed_result[::-1]

    placeholder_replacer = re.compile("{(.*?)}")

    @staticmethod
    @abstractmethod
    def replace_escape_string(string: str) -> str:
        """Replace escape chars.."""
        string = string.replace("\\n", "\n")
        string = string.replace("\\a", "\a")
        string = string.replace("\\b", "\b")
        string = string.replace("\\t", "\t")
        string = string.replace("\\f", "\f")
        return string.replace("\\r", "\r")

    @staticmethod
    @abstractmethod
    def get_param_type(function: typing.Callable) -> list:
        """Get required type of parameter."""
        return [
            param[1].annotation
            for param in inspect.signature(function).parameters.items()
        ]

    @staticmethod
    @abstractmethod
    def get_param_count(function: typing.Callable) -> int:
        """Get required count of parameter."""
        return len(inspect.signature(function).parameters.items())

    @staticmethod
    @abstractmethod
    def hasvalue(types: object, value: typing.Any) -> bool:
        """Get whether this class has a specified value."""
        with suppress(TypeError):
            if value in vars(types).values():
                return True
        return False

    @staticmethod
    @abstractmethod
    def get_commands() -> list:
        """Get the command list of `commands`."""
        return [
            method
            for method in dir(commands)
            if not method.startswith("_")
            and callable(getattr(commands, method))
            and method not in commands.private_commands
        ]


class game(metaclass=ABCMeta):
    """A class to processing game's all event."""

    @staticmethod
    @abstractmethod
    def command_interpreter(prompt: str) -> typing.NoReturn:
        """Command interpreter."""
        while True:
            try:
                commands.execute(utils.query_config("SYSTEM_NAME"), str(input(prompt)))
            except NameError:
                logger.error(
                    eval(
                        utils.get_message("game.command_interpreter.name_error", 0),
                    ),
                )
            except TypeError:
                logger.error(
                    eval(
                        utils.get_message("game.command_interpreter.type_error", 0),
                    ),
                )
            except KeyboardInterrupt:
                game.stop()
            except SystemExit:
                logger.info(
                    eval(
                        utils.get_message("game.command_interpreter.server_stop", 0),
                    ),
                )
                os._exit(0)
            except EOFError:
                logger.error(
                    eval(
                        utils.get_message("game.command_interpreter.eof_error", 0),
                    ),
                )

    @staticmethod
    @abstractmethod
    def stop(exit_value: int = 0) -> typing.NoReturn:
        """Stop server normally."""
        logger.info(eval(utils.get_message("game.command_interpreter.server_stop", 0)))
        os._exit(exit_value)

    @staticmethod
    @abstractmethod
    def error_stop(error_level: int = -1) -> typing.NoReturn:
        """Stop server when error."""
        logger.error(eval(utils.get_message("game.command_interpreter.error_stop", 0)))
        os._exit(error_level)


class network(metaclass=ABCMeta):
    """A large class, includes http server and websocket server."""

    accept_players = 0

    @staticmethod
    @abstractmethod
    def recv(client_sock: socket.socket) -> list:
        """Non-Blocking recv socket data."""
        try:
            buffer = [client_sock.recv(1024)]
        except OSError:
            return []
        if buffer[0] in (0, -1):
            return []
        client_sock.setblocking(False)
        while True:
            try:
                data = client_sock.recv(1024)
                buffer.append(data)
            except BlockingIOError:  # BlockingIOError: 缓冲区没有剩余的数据
                break
            except ConnectionResetError:  # ConnectionResetError: 连接被关闭
                break
            except OSError:
                break
        client_sock.setblocking(True)
        return buffer

    class ResponseBuilder:
        """Response message builder."""

        def __init__(self) -> None:
            """Set variables."""
            self.headers = []
            self.status = None
            self.content = None

        def add_header(self, header_key: str, header_value: str) -> None:
            """Add a head to the headers."""
            head = f"{header_key}: {header_value}"
            self.headers.append(head)
            logger.debug(eval(utils.get_message("network.http_server.set_header", 0)))

        def set_status(self, status_code: str, status_message: str) -> None:
            """Set HTTP reply status."""
            self.status = f"HTTP/1.1 {status_code} {status_message}"
            logger.debug(eval(utils.get_message("network.http_server.set_status", 0)))

        def set_content(self, content: str | bytes | bytearray) -> None:
            """Set reply content."""
            if isinstance(content, (bytes, bytearray)):
                self.content = content
                logger.debug(
                    eval(
                        utils.get_message("network.http_server.set_string_content", 0),
                    ),
                )
                return

            self.content = content.encode("utf-8")
            if len(content) <= int(utils.query_config("MAX_CONTEXT_SIZE")):
                logger.debug(
                    eval(
                        utils.get_message("network.http_server.set_content", 0),
                    ),
                )
                return
            logger.debug(
                eval(
                    utils.get_message("network.http_server.set_content_no_data", 0),
                ),
            )

        def build(self, newline: str = "\r\n") -> bytes:
            """Build response text."""
            response = f"{self.status}{newline}"
            for head in self.headers:
                response += head + f"{newline}"
            return f"{response}{newline}{newline}".encode() + self.content

    class HTTP11Server(threading.Thread):
        """A basic http1.1 server allows [GET, POST] request."""

        def __init__(
            self,
            host: str,
            port: int,
            using_https: bool = False,
            cafile: str | None = None,
        ) -> None:
            """Set variables."""
            threading.Thread.__init__(self)
            logger.debug(eval(utils.get_message("network.http_server.listening", 0)))
            self.host = host
            self.port = port
            self.request_times = {}
            self.warnlist = []
            if using_https:
                try:
                    context = ssl.create_default_context(
                        ssl.Purpose.CLIENT_AUTH,
                        cafile=cafile,
                    )
                    self.sock = context.wrap_socket(
                        socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                        server_side=True,
                    )
                except ssl.SSLError:
                    logger.warning(
                        eval(utils.get_message("network.https_server.ssl_error", 0)),
                    )
                    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                logger.info(
                    eval(utils.get_message("network.https_server.start_http", 0)),
                )
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        def run(self) -> typing.NoReturn:
            """Start HTTP server."""
            self.setup_socket()
            self.change_dir()
            self.accept()

        def setup_socket(self) -> None:
            """Install&init socket object."""
            self.sock.bind((self.host, self.port))
            self.sock.listen(int(utils.query_config("LISTENS_COUNT")))
            self.sock.settimeout(int(utils.query_config("HTTP_TIMEOUT")))
            self.sock.setblocking(True)
            logger.debug(eval(utils.get_message("network.create_socket", 0)))

        def change_dir(self) -> None:
            """Change working directory."""
            os.chdir(utils.query_config("HTTP_PATH"))

        def accept_request(
            self,
            client_sock: socket.socket,
            client_addr: tuple,
        ) -> None:
            """Process response and send it."""
            logger.debug(eval(utils.get_message("network.http_server.connect", 0)))
            buffer = network.recv(client_sock)
            req = b"".join(buffer).decode("utf-8")
            response = self.process_response(req)
            if not response:
                logger.warning(
                    eval(utils.get_message("network.http_server.recv_no_msg", 0)),
                )
                return
            client_sock.sendall(response)
            logger.debug(eval(utils.get_message("network.http_server.send_back", 0)))
            logger.debug(eval(utils.get_message("network.http_server.full", 0)))
            client_sock.shutdown(socket.SHUT_WR)
            client_sock.close()
            return

        def accept(self) -> typing.NoReturn:
            """Accept request forever."""
            while True:
                with suppress(OSError):
                    self.create_conn()

        def create_conn(self) -> None:
            """Create a connection."""
            (client, address) = self.sock.accept()
            threading.Thread(target=self.accept_request, args=(client, address)).start()

        def process_response(self, request: str) -> bytes:
            """Process response text."""
            logger.debug(
                eval(utils.get_message("network.http_server.process_response", 0)),
            )
            formatted_data = request.strip().split("\n")
            request_words = formatted_data[0].split()

            if len(request_words) == 0:
                return b""

            requested_file = request_words[1][1:]
            try:
                if request_words[0] == "GET":
                    return self.get_request(requested_file, formatted_data)
                if request_words[0] == "POST":
                    return self.post_request(requested_file, formatted_data)
                return self.method_not_allowed()
            except Exception as exception:
                logger.exception(exception)
                logger.warning(
                    eval(utils.get_message("network.http_server.server_error", 0))
                )
                return self.server_error()

        def has_permission_other(self, requested_file: str) -> bool:
            """Check readable permissions."""
            return os.access(requested_file, os.R_OK)

        def should_return_binary(self, filename: str) -> bool:
            """Check file is binary."""
            logger.debug(eval(utils.get_message("network.http_server.check_binary", 0)))
            with Path(filename).open("rb") as file:
                logger.debug(
                    eval(
                        utils.get_message("network.http_server.file_contents", 0),
                    ),
                )
                return bool(
                    file.read().translate(
                        None,
                        bytearray(
                            {7, 8, 9, 10, 12, 13, 27}
                            | set(range(0x20, 0x100)) - {0x7F},
                        ),
                    ),
                )

        def get_file_binary_contents(self, filename: str) -> bytes:
            """Get (binary) file content."""
            logger.debug(
                eval(utils.get_message("network.http_server.file_contents", 0)),
            )
            with Path(filename).open("rb") as file:
                return file.read()

        def get_file_contents(self, filename: str) -> str:
            """Get (plaintext) file content."""
            logger.debug(
                eval(utils.get_message("network.http_server.file_contents", 0)),
            )
            with Path(filename).open(encoding="utf-8") as file:
                return file.read()

        def get_request(self, requested_file: str, data) -> bytes:
            """Get request messages."""
            if not requested_file.replace(".", "", 1).replace("/", "", 1):
                requested_file = "index.html"
            requested_file = "./" + requested_file
            requested_file = requested_file.split("?", 1)[0]
            logger.debug(
                eval(utils.get_message("network.http_server.requested_file", 0)),
            )
            if not Path(requested_file).exists():
                return self.resource_not_found()
            if not self.has_permission_other(requested_file):
                return self.resource_forbidden()
            builder = network.ResponseBuilder()

            if self.should_return_binary(requested_file):
                builder.set_content(self.get_file_binary_contents(requested_file))
            else:
                builder.set_content(self.get_file_contents(requested_file))

            builder.set_status("200", "OK")

            builder.add_header("Connection", "close")
            builder.add_header(
                "Content-Type",
                mime_types.get(
                    "." + requested_file.split(".")[-1],
                    "application/octet-stream",
                )
                + "; charset=utf8",
            )
            return builder.build()

        def method_not_allowed(self) -> bytes:
            """Return 405 not allowed status and gives allowed methods."""
            builder = network.ResponseBuilder()
            builder.set_status("405", "METHOD NOT ALLOWED")
            allowed = "GET, POST"
            builder.add_header("Allow", allowed)
            builder.add_header("Connection", "close")
            return builder.build()

        def resource_not_found(self) -> bytes:
            """Return 404 not found status and sends back our 404.html page."""
            builder = network.ResponseBuilder()
            builder.set_status("404", "NOT FOUND")
            builder.add_header("Connection", "close")
            builder.add_header("Content-Type", mime_types[".html"])
            builder.set_content(self.get_file_contents("./html_error/404.html"))
            return builder.build()

        def resource_forbidden(self) -> bytes:
            """Return 403 FORBIDDEN status and sends back our 403.html page."""
            builder = network.ResponseBuilder()
            builder.set_status("403", "FORBIDDEN")
            builder.add_header("Connection", "close")
            builder.add_header("Content-Type", mime_types[".html"])
            builder.set_content(self.get_file_contents("./html_error/403.html"))
            return builder.build()

        def post_request(self, requested_file: str, data) -> bytes:
            """Process POST request."""
            builder = network.ResponseBuilder()
            builder.set_status("200", "OK")
            builder.add_header("Connection", "close")
            builder.add_header(
                "Content-Type",
                mime_types.get(
                    requested_file.rsplit(".")[-1],
                    "application/octet-stream",
                ),
            )
            logger.debug(
                eval(utils.get_message("network.http_server.requested_file", 0)),
            )
            builder.set_content(self.get_file_contents(requested_file))
            return builder.build()

        def server_error(self) -> bytes:
            builder = network.ResponseBuilder()
            builder.set_status("500", "SERVER ERROR")
            builder.add_header("Connection", "close")
            builder.add_header("Content-Type", mime_types[".html"])
            builder.set_content(self.get_file_contents("./html_error/500.html"))
            return builder.build()

    @staticmethod
    @abstractmethod
    async def ws_server(websocket, path) -> typing.NoReturn:
        """Websocket server."""
        current_owner = ""
        async for message in websocket:
            messages = []
            with suppress(IndexError):
                logger.debug(eval(utils.get_message("network.ws_server.recived", 0)))
                try:
                    data: dict = json.loads(
                        str(message.replace("'", '"')),
                        strict=False,
                    )
                except json.JSONDecodeError:
                    logger.warning(
                        eval(
                            utils.get_message("network.ws_server.json_decode_error", 0),
                        ),
                    )
                    continue
                if (data.get("type") is None) or (data.get("content") is None):
                    logger.warning(
                        eval(
                            utils.get_message(
                                "network.ws_server.json_missing_keyword",
                                0,
                            ),
                        ),
                    )
                    continue
                # 在前端接收数据包并显示
                if data["type"] == "send":
                    if len(players) != 0:  # asyncio.wait doesn't accept an empty list
                        if data["sender"] in utils.get_players():
                            if data["content"].startswith(
                                "/",
                            ):  # 以/为指令运行 0为正常 -1没权限 -2命令错 -3东西没找到
                                executed = commands.execute(
                                    data["sender"],
                                    data["content"].replace("/", "", 1),
                                )
                                messages.append(
                                    json.dumps(
                                        {
                                            "type": "send",
                                            "content": data["content"],
                                            "sender": data["sender"],
                                            "color": data["color"],
                                        },
                                    ),
                                )

                                messages.append(
                                    json.dumps(
                                        {
                                            "type": "private",
                                            "sender": utils.query_config("SYSTEM_NAME"),
                                            "to": data["sender"],
                                            "content": executed,
                                            "color": "#808080",
                                        },
                                    ),
                                )
                            else:
                                messages.append(
                                    json.dumps(
                                        {
                                            "type": "send",
                                            "content": data["content"],
                                            "sender": data["sender"],
                                            "color": data["color"],
                                        },
                                    ),
                                )
                                logger.info(
                                    eval(utils.get_message("network.player.send", 0)),
                                )
                        else:
                            logger.info(
                                eval(
                                    utils.get_message(
                                        "network.player.anonymous_send",
                                        0,
                                    ),
                                ),
                            )
                            continue
                elif data["type"] == "login":
                    if data["content"] in utils.get_players():
                        logger.warning(
                            eval(
                                utils.get_message("network.player.duplicate_login", 0),
                            ),
                        )
                        await websocket.close()
                    if data["content"] in banlist:
                        logger.info(eval(utils.get_message("network.player.banned", 0)))
                        await websocket.close()
                        continue
                    if len(players) != 0:  # asyncio.wait doesn't accept an empty list
                        message.append(
                            json.dumps({"type": "login", "content": data["content"]}),
                        )  # content是名字
                        utils.login_player(data["content"], websocket)
                        logger.info(eval(utils.get_message("network.player.login", 0)))
                elif data["type"] == "logout":
                    if len(players) != 0:  # asyncio.wait doesn't accept an empty list
                        messages.append(
                            json.dumps({"type": "logout", "content": data["content"]}),
                        )
                        utils.delete_player(data["content"])
                        logger.info(eval(utils.get_message("network.logout", 0)))
                        continue
                elif data["type"] == "gamedata":
                    if len(players) != 0:
                        if data["uploader"] != current_owner:
                            logger.warning(
                                eval(
                                    utils.get_message(
                                        "network.player.anonymous_upload",
                                        0,
                                    ),
                                ),
                            )
                            continue
                        message.append(
                            json.dumps(
                                {
                                    "type": "gamedata",
                                    "content": data["content"],
                                    "uploader": data["sender"],
                                },
                            ),
                        )
                        logger.info(
                            eval(utils.get_message("network.player.update_paint", 0)),
                        )
                elif data["type"] == "heartbeat":
                    if len(players) != 0:
                        messages.append(
                            json.dumps(
                                {"type": "heartbeat", "content": data["content"]},
                            ),
                        )
                        utils.get_player(data["content"]).last_heartbeat = time.time()
                        logger.debug(
                            eval(utils.get_message("network.player.keep_alive", 0)),
                        )
                        continue
                elif data["type"] == "ready" and len(players) != 0:
                    network.accept_players += 1
                    if network.accept_players == len(players) >= MIN_PLAYERS:
                        messages.append(
                            json.dumps(
                                {
                                    "type": "start",
                                    "content": "game_start",
                                    "owner": secrets.choice(utils.get_players()),
                                    "mspf": utils.query_config(
                                        "MSPF",
                                    ),  # Milisecond per frame
                                },
                            ),
                        )

                        logger.info(eval(utils.get_message("game.game_start", 0)))
                    else:
                        logger.info(
                            eval(utils.get_message("network.player.ready", 0)),
                        )
                        message.append(
                            json.dumps(
                                {"type": "ready", "content": data["content"]},
                            ),
                        )
            for server_message in messages:
                with suppress(ValueError):
                    await asyncio.wait(
                        [user.send(server_message) for user in utils.get_websockets()],
                    )

    @staticmethod
    @abstractmethod
    def run_ws_server() -> None:
        """Run websocket server."""
        asyncio.set_event_loop(asyncio.new_event_loop())
        start_server = websockets.serve(
            network.ws_server,
            utils.query_config("LISTEN_IP"),
            int(utils.query_config("WS_PORT")),
        )
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()


class commands(metaclass=ABCMeta):
    """All the commands over here."""

    class _CommandError(Exception):
        """The basical Exception(Signal) class in commands."""

    class _CommandSignal(Exception):
        """Mean it is a signal of command."""

    class _CommandNotFoundError(_CommandError):
        """A signal means command not found."""

        def __init__(self, command: str) -> None:
            super().__init__(f"Command {command} not found.")

    class _RedirectToAlias(_CommandSignal):
        """A signal means executed command is defined in alias list."""

        def __init__(self, command: str) -> None:
            """Preset information."""
            super().__init__(f"Command {command} is defined in alias.")

    class _AsyncFunction(_CommandSignal):
        """is a async function, execute it using asyncio.run()."""

        def __init__(self, command: str) -> None:
            """Preset information."""
            super().__init__(f"Command {command} is an async function.")

    class _PrivateFunction(_CommandSignal):
        """command cannot call normally."""

        def __init__(self, command: str) -> None:
            """Preset information."""
            super().__init__(f"Command {command} is a private command.")

    command_access: typing.ClassVar[dict[str, int]] = {
        "execute": 1,  # 执行命令
        "kick": 3,  # 踢人
        "stop": 4,  # 停服
        "modify_access": 4,  # 修改命令权限
        "get_commands": 1,  # 获取命令列表
        "clean_logs": 3,  # 删除所有日志文件
        "player_list": 2,  # 获取玩家列表
        "player_access": 3,  # 修改玩家权限
        "new_alias": 3,  # 创建别名
        "del_alias": 3,  # 删除别名
        "get_alias": 1,  # 获取别名列表
        "ban": 3,  # 封人
        "unban": 3,  # 解封
        "banlist": 3,  # 获取封禁列表
        "say": 4,  # 服务器说话
    }  # 指令权限等级(服务器4级, 管理3级, 普通玩家2级, 旁观1级
    alias: typing.ClassVar[dict[str, str]] = {
        "clean": "clean_logs",
        "exit": "stop",
        "quit": "stop",
        "halt": "stop",
        "shutdown": "stop",
        "list": "player_list",
    }
    async_commands: typing.ClassVar[list[str]] = [
        "say",
    ]
    private_commands: typing.ClassVar[list[str]] = [  # 设置内部方法 禁止调用
        "execute",
        "call_async",
        "say",
    ]

    @staticmethod
    @abstractmethod
    def execute(executer: str, command: str) -> str | None:
        """Check access and parse, run commands."""
        command = command.strip()
        if not command:
            return None
        if executer == utils.query_config("SYSTEM_NAME"):
            players_access: int = ACCESSES["server"]
        else:
            players_access: int = utils.get_player(executer).access
        compiled: list = (
            command.split()
        )  # compiled[0][0]主命令, compiled[1][1:]为参数 [0]:正常传参 [1]:关键词传参
        try:
            if compiled[0] not in utils.get_commands():
                if compiled[0] in commands.alias:
                    raise commands._RedirectToAlias(
                        compiled[0],
                    )
                raise commands._CommandNotFoundError(
                    compiled[0],
                )
            run_compiled = f"commands.{compiled[0]}({(','.join(compiled[1:]))})"
            logger.debug(eval(utils.get_message("command.run_compiled", 0)))
            if players_access >= commands.command_access[compiled[0]]:
                logger.info(eval(utils.get_message("command.execute", 0)))
                return getattr(commands, compiled[0])(
                    *compiled[1:]
                )
            out = eval(utils.get_message("command.execute.access_denied", 0))
            logger.warning(out)  # 权限不足
            return out
        except commands._CommandNotFoundError:
            if (
                commands.command_access.get(compiled[0]) is None
                and commands.alias.get(compiled[0]) is None
                and command != ""
            ):
                out = eval(utils.get_message("command.execute.not_found", 0))
                logger.error(out)
                detect = process.extractOne(
                    command,
                    list(commands.command_access.keys()),
                )
                if detect[1] >= int(utils.query_config("MATCH_THRESHOULD")):
                    out += eval(
                        utils.get_message("command.execute.syntax_detect", 0),
                    )
                    logger.info(
                        eval(
                            utils.get_message("command.execute.syntax_detect", 0),
                        ),
                    )
                return out
        except commands._RedirectToAlias:
            compiled[0] = commands.alias[compiled[0]]
            if players_access >= commands.command_access[compiled[0]]:
                logger.info(eval(utils.get_message("command.alias_execute", 0)))
                run_compiled = f"commands.{compiled[0]}({(','.join(compiled[1:]))})"
                logger.debug(eval(utils.get_message("command.run_compiled", 0)))
                return getattr(commands, compiled[0])(
                    *compiled[1:]
                )
            out = eval(utils.get_message("command.execute.access_denied", 0))
            logger.warning(out)  # 权限不足
            return out
        except commands._AsyncFunction:
            if players_access >= commands.command_access[compiled[0]]:
                logger.info(eval(utils.get_message("command.execute", 0)))
                return asyncio.run(getattr(commands, compiled[0])(*compiled[1:]))
            out = eval(utils.get_message("command.execute.access_denied", 0))
            logger.warning(out)
            return out
        except commands._PrivateFunction:
            out = eval(utils.get_message("command.execute_private", 0))
            logger.warning(out)
            return out
        except NotImplementedError:
            out = eval(
                utils.get_message("commands.execute.function_not_implemented", 0),
            )
            logger.warning(out)
            return out
        return None

    @staticmethod
    @abstractmethod
    def call_async(function: typing.Coroutine | typing.Callable) -> typing.Any:
        """Execute a async function."""
        if asyncio.iscoroutine(function):
            return asyncio.run(function)
        return asyncio.run(function())

    @staticmethod
    @abstractmethod
    def kick(player_name: str) -> str:
        """Kick a player."""
        if player_name in utils.get_players():
            out = eval(utils.get_message("command.kick", 0))
            logger.info(out)
            commands.call_async(utils.get_player(player_name).websocket.close())
            utils.delete_player(player_name)
            return out
        out = eval(utils.get_message("command.kick.player_not_found", -3))
        logger.warning(out)
        return out

    @staticmethod
    @abstractmethod
    def stop(delay: int = 0) -> str:
        """Stop game server."""
        if delay > int(utils.query_config("MAX_SLEEP_TIME")):  # 它是固定的值吗..?
            out = eval(utils.get_message("command.stop.delay_too_large", 0))
            logger.error(out)
            return out
        if delay > 0:
            out = eval(utils.get_message("command.stop.delay_stop", 0))
            logger.info(out)
        elif delay < 0:
            out = eval(utils.get_message("command.stop.smaller_zero", 0))
            logger.error(out)
        elif delay == 0:
            out = eval(utils.get_message("command.stop", 0))
            logger.info(out)
        threading.Thread(
            target=lambda: exec(f"time.sleep({delay})\ngame.stop()"),
        ).start()
        return out

    @staticmethod
    @abstractmethod
    def modify_access(command: str, new_access: int) -> str:
        """Modify command access."""
        if new_access > int(utils.query_config("MAX_ACCESS_LEVEL")):
            out = eval(utils.get_message("command.modify_access", 1))
            logger.error(out)
            return out
        if new_access < 1:
            out = eval(utils.get_message("command.modify_access", 1.5))
            logger.error(out)
            return out
        commands.command_access[command] = new_access
        out = eval(utils.get_message("command.modify_access", 0))
        logger.warning(out)
        return out

    @staticmethod
    @abstractmethod
    def get_commands() -> str:
        """Get command list."""
        commands_list = [
            method
            for method in dir(commands)
            if not method.startswith("_")
            and callable(getattr(commands, method))
            and method not in commands.private_commands
        ]
        out = eval(utils.get_message("command.get_commands", 0))
        logger.info(out)
        return out

    @staticmethod
    @abstractmethod
    def clean_logs() -> str:
        """Remove all logs."""
        out = eval(utils.get_message("command.clean_logs", 0))
        logger.info(out)
        for filename in os.listdir(utils.query_config("LOG_PATH")):
            file_path = Path(utils.query_config("LOG_PATH")) / filename  # 获取文件路径
            if Path(file_path).is_file():  # 判断是否为文件
                try:
                    Path(file_path).unlink()  # 删除文件
                except PermissionError:
                    new_info = eval(utils.get_message("command.clean_logs", -1))
                    logger.warning(new_info)
                    out += new_info
        return out

    @staticmethod
    @abstractmethod
    def player_list() -> str:
        """Get player's list."""
        lists = utils.get_players()
        out = eval(utils.get_message("command.list", 0))
        logger.info(out)
        return out

    @staticmethod
    @abstractmethod
    def player_access(player_name: str, access_name: str) -> str:
        """Change player's access."""
        if player_name in utils.get_players():
            new_access = ACCESSES.get(access_name)
            if new_access is None:
                out = eval(utils.get_message("command.player_access", -3))
                logger.warning(out)
                return out
            out = eval(utils.get_message("command.player_access", 0))
            logger.info(out)
            utils.get_player(player_name).access = new_access
            return out
        return eval(utils.get_message("command.player_access", -3.5))

    @staticmethod
    @abstractmethod
    def new_alias(command: str, alias: str) -> str:
        """Add a alias."""
        if (
            commands.alias.get(alias) is not None
            or commands.command_access.get(alias) is not None
        ):
            out = eval(utils.get_message("command.new_alias", -2))
            logger.info(out)
            return out
        out = eval(utils.get_message("command.new_alias", 0))
        logger.info(out)
        commands.alias[alias] = command
        return out

    @staticmethod
    @abstractmethod
    def del_alias(alias: str) -> str:
        """Remove a alias."""
        if commands.alias.get(alias) is None:
            out = eval(utils.get_message("command.del_alias", -2))
            logger.info(out)
            return out
        out = eval(utils.get_message("command.del_alias", 0))
        logger.info(out)
        del commands.alias[alias]
        return out

    @staticmethod
    @abstractmethod
    def get_alias() -> str:
        """Get alias's list."""
        all_alias = list(commands.alias.keys())
        out = eval(utils.get_message("command.get_alias", 0))
        logger.info(out)
        return out

    @staticmethod
    @abstractmethod
    def ban(player_name: str) -> str:
        """Ban a player, it never join the game."""
        if not player_name:
            out = eval(utils.get_message("command.ban", -3))
            logger.warning(out)
            return out
        if player_name not in utils.get_players():
            logger.warning(eval(utils.get_message("command.kick", -3)))
        if player_name in banlist:
            out = eval(utils.get_message("network.player.duplicate_ban", 0))
            logger.error(out)
            return out
        with Path("banlist.txt").open("a", encoding="utf-8") as ban_file:
            ban_file.write(player_name + "\n")
        banlist.append(player_name)
        commands.kick(player_name)
        out = eval(utils.get_message("command.ban", 0))
        logger.info(out)
        return out

    @staticmethod
    @abstractmethod
    def unban(player_name: str) -> str:
        """Unban a player."""
        if not player_name:
            out = eval(utils.get_message("command.unban", -3))
            logger.warning(out)
            return out
        if player_name not in banlist:
            out = eval(utils.get_message("network.player.never_ban", 0))
            logger.warning(out)
            return out
        with Path("banlist.txt").open(encoding="utf-8") as file:
            lines = file.readlines()
        with Path("banlist.txt").open("w", encoding="utf-8") as write_file:
            for file_line in lines:
                if file_line.strip() != player_name:
                    write_file.write(file_line)
        banlist.remove(player_name)
        out = eval(utils.get_message("command.unban", 0))
        logger.info(out)
        return out

    @staticmethod
    @abstractmethod
    def banlist() -> str:
        """Get banned player's list."""
        out = eval(utils.get_message("command.banlist", 0))
        logger.info(out)
        return out

    @staticmethod
    @abstractmethod
    async def say(
        message: str,
    ) -> None:
        """Say a message to websocket server."""
        await asyncio.wait(
            [
                user.send(
                    json.dumps(
                        {
                            "type": "send",
                            "content": message,
                            "sender": utils.query_config("SYSTEM_NAME"),
                        },
                    ),
                )
                for user in utils.get_websockets()
            ],
        )


class PluginError(Exception):
    """Error happend during loading plugin."""


class Plugin:
    """A class for plugin system."""

    def __init__(self, filename: str | None = None, code: str | None = None) -> None:
        """Load a plugin."""
        if filename and code:
            raise PluginError(eval(utils.get_message("plugin.too_many_args", 0)))
        if filename:
            with Path(os.path.split(__file__)[0] + utils.query_config("PLUGIN_PATH") + filename).open() as plugin:
                self.file = plugin.read()
        elif code:
            self.file = code
        self.code = {}
        exec(self.file, self.code)
        if not self.code or self.code.get("__metadata__") is None:
            msg = eval(utils.get_message("plugin.missing_key", 0))
            raise PluginError(msg)
        self.metadata = self.code["__metadata__"]
        self.name = self.metadata["module_name"]
        self.code["__name__"] = self.name
        self.version = self.metadata["module_version"]
        self.id = self.metadata["module_id"]
        for plugin in plugins:
            if plugin.id == self.id:
                raise PluginError(eval(utils.get_message("plugin.loading_duplicated", 0)))
        self.call_event("on_plugin_load")
        atexit_method = self.code.get("at_exit")
        if atexit_method is not None:
            atexit.register(atexit_method)
            logger.info(eval(utils.get_message("plugin.registed_atexit", 0)))
        logger.info(eval(utils.get_message("plugin.loaded_plugin", 0)))

    def __del__(self) -> None:
        """Call 'on_plugin_unload'."""
        self.call_event("on_plugin_unload")

    def load(self) -> None:
        """Load plugin code into __main__."""
        __main__.__dict__ = {**vars(__main__), **self.code}

    def trigger_event(self, event_name: str, *args, **kwargs) -> object:
        """Trigging an event."""
        event_func = self.code.get(event_name, None)
        if event_func:
            return event_func(*args, **kwargs)
        msg = f"Event '{event_name}' not found in plugin."
        raise PluginError(msg)

    def call_event(self, event_name: str, *args, **kwargs) -> object:
        """Call an event."""
        if self.code.get(event_name) is not None:
            return self.trigger_event(event_name, *args, **kwargs)
        return None

    def bind_event(self, method: typing.Callable, event_name: str) -> typing.Callable:
        """Bind an event to a method."""

        def wrapped_method(*args, **kwargs) -> object:
            """Add an event to the method."""
            self.call_event(event_name, *args, **kwargs)
            return method(*args, **kwargs)

        return wrapped_method


config = {}


try:
    with Path("./config/config.cfg").open(encoding="utf-8") as f:
        for line in f.readlines():
            config_dict = line.split("//")[0].strip().split(" = ")
            config[config_dict[0]] = config_dict[1]
except FileNotFoundError:
    if not Path("./config/").exists():
        Path("./config/").mkdir()
    with Path("./config/commands_conf.cfg").open("w", encoding="utf-8") as f:
        f.write(
            """
                HTTP_PORT = 3872
                WS_PORT = 3827
                HTTP_TIMEOUT = 5
                LISTENS_COUNT = 8
                HTTP_SERVER_NAME = Kris's HTTP Server
                LANGUAGE = zh_cn
                PROMPT = >>>
                SYSTEM_NAME = Kris
                SPACE_COUNT = 4
                HTTP_PATH = ../../
                HTTPS_CAFILE = cert.pem
                MSPF = 175 // Milisecond per frame
                PLUGIN_PATH = ./plugins/
            """.strip(),
        )

lang = {}
_COMMENTING = False
try:
    with Path("./lang/" + utils.query_config("LANGUAGE") + ".lang").open(
        "r",
        encoding="utf-8",
    ) as f:
        readlines = f.readlines()
        if "No Replace" not in readlines[0]:
            replace_punctuations: dict[str, str] = ast.literal_eval(
                "{" + readlines[0] + "}",
            )
        else:
            replace_punctuations: dict[str, str] = {}
        for langs in readlines[1:]:
            if _COMMENTING:
                continue
            if langs.startswith("--Comments: Start"):
                _COMMENTING = True
                continue
            if langs.startswith("--Comments: End"):
                _COMMENTING = False
                continue
            if langs.startswith("--"):
                _COMMENTING = False
                continue
            _loading = langs.rsplit("#", 2)[0].split(
                ",",
                2,
            )  # [0]: 命令 [1]: 返回值 [2]: 语言内容 [3]: 注释
            if _loading == [""]:
                continue

            for punctuations in replace_punctuations:
                _loading[2] = _loading[2].replace(
                    punctuations,
                    replace_punctuations.get(punctuations),
                )
            lang[f"{_loading[0]}.{_loading[1]}"] = _loading[2]
except FileNotFoundError:
    if not Path("./lang/").exists():
        Path("./lang/").mkdir()
    logger.critical("语言文件不存在. ")
    os._exit(0)

logger.remove()
if __name__ == "__main__":
    logger.add(sys.stderr, level=20, enqueue=True)  # 命令行句柄
logger.add(
    f"{utils.query_config('LOG_PATH')}{time.strftime('%Y.%m.%d.log')}",
    encoding="utf-8",
    enqueue=True,
    rotation="00:00",
    level=0,
    colorize=False,
)  # 文件句柄

logger.debug(eval(utils.get_message("root.loaded_language", 0)))

try:
    for _plugin in os.listdir(utils.query_config("PLUGIN_PATH")):
        with Path(utils.query_config("PLUGIN_PATH") + _plugin).open(
            encoding="utf-8"
        ) as f:
            try:
                plugins.append(Plugin(code=f.read()))
            except Exception as e:
                logger.exception(e)
                logger.error(eval(utils.get_message("plugin.load_error", 0)))
                game.error_stop()
except FileNotFoundError:
    if not Path(utils.query_config("PLUGIN_PATH")).exists():
        Path(utils.query_config("PLUGIN_PATH")).mkdir()
logger.debug(eval(utils.get_message("root.loaded_plugins", 0)))

try:
    with Path("banlist.txt").open(encoding="utf-8") as f:
        banlist = [ban.strip() for ban in f.readlines()]
except FileNotFoundError:
    with Path("banlist.txt").open("w", encoding="utf-8") as f:
        banlist = []
        f.write("")

logger.debug(eval(utils.get_message("root.loaded_bans", 0)))


def run(
    enabled_shell: bool = True,
    override_sys_excepthook: bool = True,
) -> None:
    """Run all server."""
    logger.debug(eval(utils.get_message("root.run", 0)))
    try:
        threading.Thread(target=network.run_ws_server).start()
    except RuntimeError:
        logger.critical(eval(utils.get_message("root.ws_network_run_error", 0)))
        game.error_stop()
    try:
        network.HTTP11Server(
            utils.query_config("LISTEN_IP"),
            int(utils.query_config("HTTP_PORT")),
        ).start()
    except RuntimeError:
        logger.critical(eval(utils.get_message("root.ws_network_run_error", 0)))
        game.error_stop()
    if override_sys_excepthook:
        install_rich_traceback(show_locals=True, max_frames=0)
    if enabled_shell:
        try:
            game.command_interpreter(utils.query_config("PROMPT") + " ")
        except KeyboardInterrupt:
            game.stop()


if __name__ == "__main__":
    sys.stdout.write(eval(utils.get_message("game.command_interpreter.start_info", 0)))
    run()

# TODO: eval(log) to log.format(*infos)
