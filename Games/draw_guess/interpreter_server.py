#!/usr/bin/env python
# coding=utf-8
""" A draw&guess game, includes websocket server and http server."""
from contextlib import suppress
from mimetypes import types_map as mime_types
import json
import time
import os
import asyncio
import threading
import socket
import typing
import sys
import functools
import re
import ast
import inspect
from rich.traceback import install as install_rich_traceback
from fuzzywuzzy import process
from colorama import init, Fore
from loguru import logger
import websockets

init(autoreset=True)
logger.remove()
if __name__ == "__main__":
    logger.add(sys.stderr, level=0, enqueue=False)  # 命令行句柄
logger.add(
    f"./logs/{time.strftime('%Y.%m.%d.log')}",
    encoding="utf-8",
    enqueue=True,
    rotation="00:00",
    level=0,
    colorize=False,
)  # 文件句柄

MIN_PLAYERS: int = 2
accesses: dict = {"server": 4, "admin": 3, "player": 2, "spectators": 1, "banned": 0}


class player:
    """A class for player."""

    def __init__(self, name, websocket, access=2):
        self.name = name
        self.websocket = websocket
        self.access = access
        self.scores = 0
        self.last_heartbeat = time.time()

    def __str__(self):
        return self.name


players = []


class utils:
    """A class to encapsulates codes"""

    @staticmethod
    @functools.cache
    def get_message(eqalname: str, value: typing.Union[int, float]) -> str:
        """Query message in language file."""
        try:
            return str(lang[eqalname + "." + str(value)]).strip()
        except KeyError:
            return str(lang[("root.unknown_language.0")]).strip()

    @staticmethod
    def get_players() -> list:
        """Get all player's name."""
        return [iter_player.name for iter_player in players]

    @staticmethod
    def get_player(name: str) -> player:
        """Get player object by name"""
        if name == utils.query_config("SYSTEM_NAME"):
            return player(utils.query_config("SYSTEM_NAME"), None, accesses["server"])
        return [iter_player for iter_player in players if iter_player.name == name][0]

    @staticmethod
    def delete_player(name: str) -> None:
        """Remove a player from players list."""
        players.remove(utils.get_player(name))

    @staticmethod
    def login_player(name: str, websocket) -> player:
        """Added 1 player to players list."""
        logined_player = player(name, websocket)
        players.append(name)
        return logined_player

    @staticmethod
    def get_websocket(name: str):
        """Get player's websocket object."""
        return [
            iter_player.websocket for iter_player in players if iter_player.name == name
        ][0]

    @staticmethod
    def get_websockets() -> list:
        """Get all the player's websocket object."""
        return [iter_player.websocket for iter_player in players]

    @staticmethod
    @functools.cache
    def query_config(key: str) -> str:
        """Query config in config file."""
        try:
            return str(config[key]).strip()
        except KeyError:
            return eval(utils.get_message("root.config_not_found", 0))

    @staticmethod
    def reverse_replace(string: str, old: str, new: str, max_count: int = -1) -> str:
        """Reverse string and replace string"""
        # 从后往前查找旧字符串
        reversed_string = string[::-1]
        reversed_old = old[::-1]
        reversed_new = new[::-1]

        # 替换
        if max_count == -1:
            reversed_result = reversed_string.replace(reversed_old, reversed_new)
        else:
            reversed_result = reversed_string.replace(
                reversed_old, reversed_new, max_count
            )

        # 将结果反转回来
        result = reversed_result[::-1]
        return result

    placeholder_replacer = re.compile("{(.*?)}")

    @staticmethod
    def replace_escape_string(string: str) -> str:
        """Replace escape chars.."""
        string = string.replace("\\n", chr(10))
        string = string.replace("\\t", int(utils.query_config("SPACE_COUNT")) * " ")
        string = string.replace("\\a", chr(7))
        string = string.replace("\\b", chr(8))
        string = string.replace("\\t", chr(9))
        string = string.replace("\\f", chr(12))
        string = string.replace("\\t", chr(9))
        string = string.replace("\\r", chr(13))
        return string

    @staticmethod
    def parse(string: str, **variables) -> str:
        """Parsing f-string"""
        try:
            return utils.replace_escape_string(string.format(**variables))
        except KeyError:
            for placeholder in re.findall(utils.placeholder_replacer, string):
                try:
                    string = string.replace(
                        f"{{{placeholder}}}", str(variables[placeholder])
                    )
                except KeyError:
                    continue
            return utils.replace_escape_string(string)

    @staticmethod
    def get_param_type(function: typing.Callable) -> tuple:
        """Get required type of parameter."""
        types: list = []
        signature = inspect.signature(function)
        for param in signature.parameters.items():
            types.append(param[1].annotation)
        return (signature, types)

    @staticmethod
    def get_param_count(function: typing.Callable) -> int:
        """Get required count of parameter."""
        return len(inspect.signature(function).parameters.items())


class game:
    """A class to processing game's all event."""

    server_running = True

    @staticmethod
    def command_interpreter(prompt: str) -> None:
        """a basic command interpreter."""
        while True:
            try:
                commands.execute(utils.query_config("SYSTEM_NAME"), str(input(prompt)))
            except NameError as err:
                logger.error(
                    eval(
                        utils.get_message("game.command_interpreter.name_error", 0),
                    )
                )
            except TypeError as err:
                logger.error(
                    eval(
                        utils.get_message("game.command_interpreter.type_error", 0),
                    )
                )
            except SyntaxError as err:
                logger.error(
                    eval(
                        utils.get_message("game.command_interpreter.syntax_error", 0),
                    )
                )
            except KeyboardInterrupt:
                game.stop()
            except SystemExit:
                logger.info(
                    eval(
                        utils.get_message("game.command_interpreter.server_stop", 0),
                    )
                )
                os._exit(0)
            except EOFError:
                logger.error(
                    eval(
                        utils.get_message("game.command_interpreter.eof_error", 0),
                    )
                )

    @staticmethod
    def stop(exit_value: int = 0) -> typing.NoReturn:
        """Stop server normally."""
        logger.info(eval(utils.get_message("game.command_interpreter.server_stop", 0)))
        os._exit(exit_value)

    @staticmethod
    def error_stop(error_level: int = -1) -> typing.NoReturn:
        """Stop server when error."""
        logger.error(eval(utils.get_message("game.command_interpreter.error_stop", 0)))
        os._exit(error_level)


class network:
    """A large class, includes http server and websocket server."""

    accept_players = 0

    class HTTPServer(threading.Thread):
        """A basic http server allows [GET, POST, and HEAD] request."""

        class ResponseBuilder:
            """Response message builder."""

            def __init__(self):
                self.headers = []
                self.status = None
                self.content = None

            def add_header(self, header_key: str, header_value: str) -> None:
                """Add a head to the headers."""
                head = f"{header_key}: {header_value}"
                self.headers.append(head)
                logger.debug(
                    eval(utils.get_message("network.http_server.set_header", 0))
                )

            def set_status(self, status_code: str, status_message: str) -> None:
                """Setting HTTP reply status."""
                self.status = f"HTTP/1.1 {status_code} {status_message}"
                logger.debug(
                    eval(utils.get_message("network.http_server.set_status", 0))
                )

            def set_content(self, content: typing.Union[str, bytes]) -> None:
                """Set reply content."""
                if isinstance(content, (bytes, bytearray)):
                    self.content = content
                    logger.debug(
                        eval(
                            utils.get_message(
                                "network.http_server.set_string_content", 0
                            ),
                        )
                    )

                else:
                    self.content = content.encode("utf-8")
                    logger.debug(
                        eval(
                            utils.get_message("network.http_server.set_content", 0),
                        )
                    )

            def build(self) -> bytes:
                """Building response text."""
                response = f"{self.status}\r\n"
                for i in self.headers:
                    response += i + "\r\n"
                response = f"{response}\n\n".encode("utf-8") + self.content
                return response

        def __init__(self, host, port):
            threading.Thread.__init__(self)
            logger.debug(eval(utils.get_message("network.http_server.listening", 0)))
            self.host = host
            self.port = port
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        def run(self) -> typing.NoReturn:
            """Start HTTP server"""
            self.setup_socket()
            self.change_dir()
            self.accept()

        def setup_socket(self) -> None:
            """Install&init socket object."""
            self.sock.bind((self.host, self.port))
            self.sock.listen(int(utils.query_config("LISTENS_COUNT")))
            self.sock.settimeout(int(utils.query_config("HTTP_TIMEOUT")))
            self.sock.setblocking(True)

        def change_dir(self) -> None:
            """Change working directory."""
            os.chdir(utils.query_config("HTTP_PATH"))

        def accept_request(
            self, client_sock: socket.socket, client_addr: tuple
        ) -> None:
            """processing response and send it."""
            logger.debug(eval(utils.get_message("network.http_server.connect", 0)))
            buffer = [client_sock.recv(1024)]
            if buffer[0] in (0, -1):
                return None
            client_sock.setblocking(False)
            while True:
                try:
                    data = client_sock.recv(1024)
                    buffer.append(data)
                except BlockingIOError:
                    break
            client_sock.setblocking(True)
            req = b"".join(buffer).decode("utf-8")
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
            """accepting request forever."""
            while True:
                (client, address) = self.sock.accept()
                threading.Thread(
                    target=self.accept_request, args=(client, address)
                ).start()

        def process_response(self, request: str) -> bytes:
            """Processing response text."""
            logger.debug(
                eval(utils.get_message("network.http_server.process_response", 0))
            )
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

        def has_permission_other(self, requested_file: str) -> bool:
            """Check readable permissions"""
            return os.access(requested_file, os.R_OK)

        def _check_binary(self, data_bytes: typing.Union[str, bytes]) -> bool:
            return bool(
                data_bytes.translate(
                    None,
                    bytearray(
                        {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F}
                    ),
                )
            )

        def should_return_binary(self, filename: str) -> bool:
            """Check file is binary"""
            logger.debug(eval(utils.get_message("network.http_server.check_binary", 0)))
            with open(filename, "rb") as file:
                logger.debug(
                    eval(
                        utils.get_message("network.http_server.file_contents", 0),
                    )
                )
                return self._check_binary(file.read())

        def get_file_binary_contents(self, filename: str) -> bytes:
            """Get (binary) file content."""
            logger.debug(
                eval(utils.get_message("network.http_server.file_contents", 0))
            )
            with open(filename, "rb") as file:
                return file.read()

        def get_file_contents(self, filename: str) -> str:
            """Get (plaintext) file content."""
            logger.debug(
                eval(utils.get_message("network.http_server.file_contents", 0))
            )
            with open(filename, "r", encoding="utf-8") as file:
                return file.read()

        def get_request(self, requested_file: str, data) -> bytes:
            """Get request messages."""
            requested_file = "./" + requested_file
            requested_file = requested_file.split("?", 1)[0]
            logger.debug(
                eval(utils.get_message("network.http_server.requested_file", 0))
            )
            if not requested_file.replace(".", "", 1):
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
                mime_types.get(
                    "." + requested_file.split(".")[-1], "application/octet-stream"
                )
                + "; charset=utf8",
            )
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

            return builder.build()

        def method_not_allowed(self) -> bytes:
            """
            Returns 405 not allowed status and gives allowed methods.
            """
            builder = self.ResponseBuilder()
            builder.set_status("405", "METHOD NOT ALLOWED")
            allowed = ", ".join(["GET", "POST"])
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

        def post_request(self, requested_file: str, data) -> bytes:
            """Processing POST request."""
            builder = self.ResponseBuilder()
            builder.set_status("200", "OK")
            builder.add_header("Connection", "close")
            builder.add_header(
                "Content-Type",
                mime_types.get(
                    requested_file.rsplit(".")[-1], "application/octet-stream"
                ),
            )
            builder.set_content(self.get_file_contents(requested_file))
            return builder.build()

        def head_request(self, requested_file: str, data):
            """Processing HEAD request."""
            builder = self.ResponseBuilder()
            builder.set_status("200", "OK")
            builder.add_header("Connection", "close")
            builder.add_header(
                "Content-Type",
                mime_types.get(
                    requested_file.rsplit(".")[-1], "application/octet-stream"
                ),
            )
            return builder.build()

    @staticmethod
    async def ws_server(websocket, path) -> typing.NoReturn:
        """Websocket server."""
        # 采用JSON式
        # 将新连接的客户端添加到clients集合中
        async for message in websocket:
            logger.debug(eval(utils.get_message("network.ws_server.recived", 0)))
            try:
                data: dict = json.loads(str(message.replace("'", '"')), strict=False)
            except json.JSONDecodeError:
                logger.warning(
                    eval(
                        utils.get_message("network.ws_server.json_decode_error", 0),
                    )
                )
                continue
            else:
                if data.get("type") is None or data.get("content") is None:
                    logger.warning(
                        eval(
                            utils.get_message(
                                "network.ws_server.json_missing_keyword", 0
                            ),
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
                            logger.info(
                                eval(utils.get_message("network.player.send", 0))
                            )
                    else:
                        logger.info(
                            eval(
                                utils.get_message("network.player.anonymous_send", 0),
                            )
                        )
                        continue
            elif data["type"] == "login":
                if data["content"] in utils.get_players():
                    logger.warning(
                        eval(
                            utils.get_message("network.player.duplicate_login", 0),
                        )
                    )
                    await commands.kick(data["content"])
                if data["content"] in banlist:
                    logger.info(eval(utils.get_message("network.player.banned", 0)))
                    await websocket.close()
                    continue
                if len(players) != 0:  # asyncio.wait doesn't accept an empty list
                    message = json.dumps(
                        {"type": "login", "content": data["content"]}
                    )  # content是名字
                    utils.login_player(data["content"], websocket)
                    logger.info(eval(utils.get_message("network.player.login", 0)))
            elif data["type"] == "logout":
                if len(players) != 0:  # asyncio.wait doesn't accept an empty list
                    message = json.dumps({"type": "logout", "content": data["content"]})
                    utils.delete_player(data["content"])
                    logger.info(eval(utils.get_message("network.logout", 0)))
                    continue
            elif data["type"] == "paint":
                if len(players) != 0:
                    message = json.dumps({"type": "paint", "content": data["content"]})
                    logger.info(
                        eval(utils.get_message("network.player.update_paint", 0))
                    )
            elif data["type"] == "heartbeat":
                if len(players) != 0:
                    message = json.dumps(
                        {"type": "heartbeat", "content": data["content"]}
                    )
                    utils.get_player(data["content"]).last_heartbeat = time.time()
                    logger.debug(
                        eval(utils.get_message("network.player.keep_alive", 0))
                    )
                    continue
            elif data["type"] == "ready":
                network.accept_players += 1
                if network.accept_players == len(players) >= MIN_PLAYERS:
                    message = json.dumps({"type": "start", "content": "game_start"})
                    logger.info(eval(utils.get_message("game.game_start", 0)))
                else:
                    logger.info(eval(utils.get_message("network.player.ready", 0)))
                    message = json.dumps({"type": "ready", "content": data["content"]})
            with suppress(Exception):
                await asyncio.wait(
                    [user.send(message) for user in utils.get_websockets()]
                )

    @staticmethod
    def run_ws_server() -> typing.NoReturn:
        """Run websocket server."""
        asyncio.set_event_loop(asyncio.new_event_loop())
        start_server = websockets.serve(
            network.ws_server, "0.0.0.0", int(utils.query_config("WS_PORT"))
        )
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()


class commands:
    """All the commands over here."""

    class _CommandNotFoundError(Exception):
        def __init__(self, *args, **kwargs):
            pass

    class _RedirectToAlias(Exception):  # 其实是个信号 不是Error
        def __init__(self, *args, **kwargs):
            pass

    class _AsyncFunction(Exception):
        def __init__(self, *args, **kwargs):
            pass

    command_access = {
        "execute": 1,  # 执行命令
        "kick": 3,  # 踢人
        "stop": 4,  # 停服
        "modify_access": 4,  # 修改命令权限
        "get_commands": 1,  # 获取命令列表
        "clean_logs": 3,  # 删除所有日志文件
        "list": 2,  # 获取玩家列表
        "player_access": 3,  # 修改玩家权限
        "new_alias": 3,  # 创建别名
        "del_alias": 3,  # 删除别名
        "get_alias": 1,  # 获取别名列表
        "ban": 3,  # 封人
        "unban": 3,  # 解封
        "banlist": 3,  # 获取封禁列表
        "say": 4,  # 服务器说话
    }  # 指令权限等级(服务器4级，管理3级，普通玩家2级，旁观1级
    alias = {
        "clean": "clean_logs",
        "exit": "stop",
        "quit": "stop",
        "halt": "stop",
        "shutdown": "stop",
        "list": "player_list",
    }
    async_commands = [
        "kick",
        "say",
        "ban",
    ]

    @staticmethod
    def execute(executer: str, command: str) -> typing.Union[str, None]:
        """Check access and parse, run commands."""
        if not command.strip():
            return None
        if executer == utils.query_config("SYSTEM_NAME"):
            players_access: int = accesses["server"]
        else:
            players_access: int = utils.get_player(executer).access
        compiled: list = command.split(" ")  # 以第一个参数为主命令，空格为参数
        if compiled[0] not in commands.command_access:
            if compiled[0] in commands.alias:
                raise commands._RedirectToAlias(
                    f"Command {compiled[0]} is defined in alias."
                )
            raise commands._CommandNotFoundError(f"Command {compiled[0]} not found.")
        param_count = utils.get_param_count(getattr(commands, compiled[0]))
        if param_count > 0:
            param_types = utils.get_param_type(getattr(commands, compiled[0]))
            for index, parsing_type in enumerate(compiled[1:]):
                if (
                    hasattr(typing, repr(param_types[1][index]).rsplit(".", 1)[-1])
                    or param_types[1][index] is param_types[0].empty
                ):  # 不用解析typing的子类
                    continue
                compiled[index] = param_types[index](parsing_type)
        try:
            run_compiled = f"commands.{compiled[0]}({(','.join(compiled[1:]))})"
            logger.debug(eval(utils.get_message("command.run_compiled", 0)))
            if players_access >= commands.command_access[compiled[0]]:
                logger.info(eval(utils.get_message("command.execute", 0)))
                return getattr(commands, compiled[0])(*compiled[1:])
            out = eval(utils.get_message("command.execute.access_denied", 0))
            logger.warning(out)  # 权限不足
            return out
        except commands._CommandNotFoundError:
            if (
                commands.command_access.get(compiled[0]) is None
                and commands.alias.get(compiled[0]) is None
            ):
                if command != "":
                    out = eval(utils.get_message("command.execute.not_found", 0))
                    logger.error(out)
                    detect: tuple = process.extractOne(
                        command, list(commands.command_access.keys())
                    )
                    if detect[1] >= 85:
                        out += eval(
                            utils.get_message("command.execute.syntax_detect", 0),
                        )
                        logger.info(
                            eval(
                                utils.get_message("command.execute.syntax_detect", 0),
                            )
                        )
                    return out
                try:
                    return out
                except NameError:
                    return None
        except commands._RedirectToAlias as err:
            compiled[0] = commands.alias[compiled[0]]
            if players_access >= commands.command_access[compiled[0]]:
                logger.info(eval(utils.get_message("command.alias_execute", 0)))
                run_compiled = f"commands.{compiled[0]}({(','.join(compiled[1:]))})"
                logger.debug(eval(utils.get_message("command.run_compiled", 0)))
                return getattr(commands, run_compiled[0])(*run_compiled[1:])
            out = eval(utils.get_message("command.execute.access_denied", 0))
            logger.warning(out)  # 权限不足
            return out
        except commands._AsyncFunction as err:
            raise NotImplementedError("Async execute is not implemented.") from err
        return out

    @staticmethod
    async def kick(player_name: str) -> str:
        """Kick a player."""
        if player_name in utils.get_players():
            out = eval(utils.get_message("command.kick", 0))
            logger.info(out)
            await utils.get_player(player_name).websocket.close()
            utils.delete_player(player_name)
            return out
        out = eval(utils.get_message("command.kick.player_not_found", -3))
        logger.warning(out)
        return out

    @staticmethod
    def stop(delay: int = 0) -> str:
        """Stop game server."""
        if delay > 4294967:  # 它是固定的值吗..?
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
            target=lambda: exec(
                f"time.sleep({delay})\ngame.stop()\ngame.server_running=False"
            )
        ).start()
        return out

    @staticmethod
    def modify_access(command: str, new_access: int) -> str:
        """Modify command access."""
        if new_access > 5:
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
    def get_commands() -> str:
        """Get command list."""
        commands_list = [
            method
            for method in dir(commands)
            if not method.startswith("_") and callable(getattr(commands, method))
        ]
        out = eval(utils.get_message("command.get_commands", 0))
        logger.info(out)
        return out

    @staticmethod
    def clean_logs(folder_path: str = "./logs/") -> str:
        """Remove all logs."""
        out = eval(utils.get_message("command.clean_logs", 0))
        logger.info(out)
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)  # 获取文件路径
            if os.path.isfile(file_path):  # 判断是否为文件
                try:
                    os.remove(file_path)  # 删除文件
                except PermissionError:
                    logger.warning(eval(utils.get_message("command.clean_logs", -1)))
        return out

    @staticmethod
    def player_list() -> str:
        """Get player's list."""
        lists = utils.get_players()
        out = eval(utils.get_message("command.list", 0))
        logger.info(out)
        return out

    @staticmethod
    def player_access(player_name: str, access_: str) -> str:
        """Change player's access."""
        if player_name in utils.get_players():
            new_access = accesses.get(access_)
            if new_access is None:
                out = eval(utils.get_message("command.player_access", -3))
                logger.warning(out)
                return out
            out = eval(utils.get_message("command.player_access", 0))
            logger.info(out)
            utils.get_player(player_name).access = new_access
            return out
        out = eval(utils.get_message("command.player_access", -3.5))
        return out

    @staticmethod
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
    def get_alias() -> str:
        """Get alias's list."""
        all_alias = list(commands.alias.keys())
        out = eval(utils.get_message("command.get_alias", 0))
        logger.info(out)
        return out

    @staticmethod
    async def ban(player_name: str) -> str:
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
        with open("banlist.txt", "a", encoding="utf-8") as ban_file:
            ban_file.write(player_name + "\n")
        banlist.append(player_name)
        await commands.kick(player_name)
        out = eval(utils.get_message("command.ban", 0))
        logger.info(out)
        return out

    @staticmethod
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
        with open("banlist.txt", "r", encoding="utf-8") as file:
            lines = file.readlines()
        with open("banlist.txt", "w", encoding="utf-8") as write_file:
            for file_line in lines:
                if file_line.strip() != player_name:
                    write_file.write(file_line)
        banlist.remove(player_name)
        out = eval(utils.get_message("command.unban", 0))
        logger.info(out)
        return out

    @staticmethod
    def banlist() -> str:
        """Get banned player's list."""
        out = eval(utils.get_message("command.banlist", 0))
        logger.info(out)
        return out

    @staticmethod
    async def say(message) -> None:
        """Say a message to websocket server."""
        await asyncio.wait(
            [
                user.send(
                    json.dumps(
                        {
                            "type": "send",
                            "content": message,
                            "sender": utils.query_config("SYSTEM_NAME"),
                        }
                    )
                )
                for user in utils.get_websockets()
            ]
        )


config = {}

try:
    with open("./config/config.cfg", "r", encoding="utf-8") as f:
        for line in f.readlines():
            config_dict = line.split(" = ")
            config[config_dict[0]] = config_dict[1]
except FileNotFoundError:
    if not os.path.exists("./config/"):
        os.mkdir("./config/")
    with open("./config/commands_conf.cfg", "w", encoding="utf-8") as f:
        f.write("HTTP_TIMEOUT = 60\nLISTENS_COUNT = 8")

lang = {}
_COMMENTING = False
try:
    with open(
        "./lang/" + utils.query_config("LANGUAGE") + ".lang", "r", encoding="utf-8"
    ) as f:
        readlines = f.readlines()
        if "No Replace" not in readlines[0]:
            replace_punctuations: dict = ast.literal_eval("{" + readlines[0] + "}")
        else:
            replace_punctuations: dict = {}
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
                ",", 2
            )  # [0]: 命令 [1]: 返回值 [2]: 语言内容 [3]: 注释
            if _loading == [""]:
                continue

            for punctuations in replace_punctuations.keys():
                _loading[2] = _loading[2].replace(
                    punctuations, replace_punctuations.get(punctuations)
                )
            lang[f"{_loading[0]}.{_loading[1]}"] = _loading[2]
except FileNotFoundError:
    if not os.path.exists("./lang/"):
        os.mkdir("./lang/")
    logger.critical("语言文件不存在. ")
    os._exit(0)

logger.debug(eval(utils.get_message("root.loaded_language", 0)))

try:
    for _plugin in os.listdir("./plugins/"):
        with open("./plugins/" + _plugin, "r", encoding="utf-8") as f:
            try:
                exec(f.read())
            except Exception as e:
                logger.error(eval(utils.get_message("plugin.load_error", 0)))
                logger.exception(e)
                game.error_stop()
        logger.debug(eval(utils.get_message("root.loaded", 0)))
except FileNotFoundError:
    if not os.path.exists("./plugins/"):
        os.mkdir("./plugins/")
logger.debug(eval(utils.get_message("root.loaded_plugins", 0)))

try:
    with open("banlist.txt", "r", encoding="utf-8") as f:
        banlist = [ban.strip() for ban in f.readlines()]
except FileNotFoundError:
    with open("banlist.txt", "w", encoding="utf-8") as f:
        banlist = []
        f.write("")

logger.debug(eval(utils.get_message("root.loaded_bans", 0)))


def run(enabled_shell=True, override_sys_excepthook=True):
    """Run all server."""
    logger.debug(eval(utils.get_message("root.run", 0)))
    try:
        threading.Thread(target=network.run_ws_server).start()
    except RuntimeError:
        logger.critical(eval(utils.get_message("root.ws_network_run_error", 0)))
        game.error_stop()
    try:
        network.HTTPServer("0.0.0.0", int(utils.query_config("HTTP_PORT"))).start()
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
    print(eval(utils.get_message("game.command_interpreter.start_info", 0)))
    run()
