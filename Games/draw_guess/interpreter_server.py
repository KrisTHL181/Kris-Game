#!/usr/bin/env python
#coding=utf-8
import json
import time
import os
import asyncio
import threading
from contextlib import suppress
from sys import argv as arg, stderr
import socket
import typing
from fuzzywuzzy import process
from colorama import init, Fore
from loguru import logger
from mimetypes import types_map as mime_types
import websockets

init(autoreset=True)
logger.remove()
ALLOW_PRINT = False
if __name__ == "__main__":
    logger.add(stderr, level=0, enqueue=False)  # 命令行句柄
    ALLOW_PRINT = True
logger.add(
    f"./logs/{time.strftime('%Y.%m.%d.log')}",
    encoding="utf-8",
    enqueue=True,
    rotation="00:00",
    level=0,
    colorize=False,
)  # 文件句柄

MIN_PLAYERS = 2
SCORES = {}
accesses = {"server": 4, "admin": 3, "player": 2, "spectators": 1, "banned": 0}


class player:
    def __init__(self, name, websocket, access=2):
        self.name = name
        self.websocket = websocket
        self.access = access
        self.last_heartbeat = time.time()

    def __str__(self):
        return self.name


players = []


class utils:
    @staticmethod
    def get_message(eqalname, value) -> str:
        try:
            out = str(lang[eqalname + "." + str(value)])
        except KeyError:
            return str(lang[("root.unknown_language.0")])
        return out

    @staticmethod
    def get_players() -> list:
        return [vars(iter_player)["name"] for iter_player in players]

    @staticmethod
    def get_player(name) -> player:
        if name == SYSTEM_NAME:
            return player(SYSTEM_NAME, None, accesses.get("server"))
        return [iter_player for iter_player in players if iter_player.name == name][0]

    @staticmethod
    def delete_player(name) -> None:
        players.remove(utils.get_player(name))

    @staticmethod
    def login_player(name, websocket) -> player:
        logined_player = player(name, websocket)
        players.append(name)
        return logined_player

    @staticmethod
    def get_websocket(name):
        return [
            iter_player.websocket for iter_player in players if iter_player.name == name
        ][0]

    @staticmethod
    def get_websockets() -> list:
        return [iter_player.websocket for iter_player in players]

    @staticmethod
    def query_config(key):
        return config.get(key, eval(utils.get_message("root.config_not_found", 0)))


class game:
    server_running = True

    @staticmethod
    def command_interpreter(prompt: str) -> None:
        while True:
            try:
                commands.execute(SYSTEM_NAME, str(input(prompt)))
            except NameError as err:
                logger.error(
                    eval(utils.get_message("game.command_interpreter.name_error", 0))
                )
            except TypeError as err:
                logger.error(
                    eval(utils.get_message("game.command_interpreter.type_error", 0))
                )
            except SyntaxError as err:
                logger.error(
                    eval(utils.get_message("game.command_interpreter.syntax_error", 0))
                )
            except KeyboardInterrupt:
                game.stop()
            except SystemExit:
                logger.info(
                    eval(utils.get_message("game.command_interpreter.server_stop", 0))
                )
                os._exit(0)
            except EOFError:
                logger.error(
                    eval(utils.get_message("game.command_interpreter.eof_error", 0))
                )
            except Exception as err:
                logger.error(
                    eval(
                        utils.get_message(
                            "game.command_interpreter.unhandled_exception", 0
                        )
                    )
                )
                logger.exception(err)

    @staticmethod
    def stop(exit_value=0):
        logger.info(eval(utils.get_message("game.command_interpreter.server_stop", 0)))
        os._exit(exit_value)

    @staticmethod
    def error_stop(error_level=-1):
        logger.error(eval(utils.get_message("game.command_interpreter.error_stop", 0)))
        os._exit(error_level)


class network:
    accept_players = 0

    # TODO-working: 优化HTTP服务器性能
    class HTTPServer(threading.Thread):
        class ResponseBuilder:
            def __init__(self):
                self.headers = []
                self.status = None
                self.content = None

            def add_header(self, headerKey, headerValue) -> None:
                head = f"{headerKey}: {headerValue}"
                self.headers.append(head)
                logger.debug(
                    eval(utils.get_message("network.http_server.set_header", 0))
                )

            def set_status(self, statusCode, statusMessage) -> None:
                self.status = f"HTTP/1.1 {statusCode} {statusMessage}"
                logger.debug(
                    eval(utils.get_message("network.http_server.set_status", 0))
                )

            def set_content(self, content) -> None:
                if isinstance(content, (bytes, bytearray)):
                    self.content = content
                    logger.debug(
                        eval(
                            utils.get_message(
                                "network.http_server.set_string_content", 0
                            )
                        )
                    )

                else:
                    self.content = content.encode("utf-8")
                    logger.debug(
                        eval(utils.get_message("network.http_server.set_content", 0))
                    )

            def build(self) -> bytes:
                response = f"{self.status}\r\n"
                for i in self.headers:
                    response += i + "\r\n"
                response = f"{response}\n\n".encode("utf-8") + self.content
                logger.debug(
                    eval(utils.get_message("network.http_server.reply_build", 0))
                )
                return response

        def __init__(self, host, port):
            threading.Thread.__init__(self)
            logger.debug(eval(utils.get_message("network.http_server.listening", 0)))
            self.host = host
            self.port = port
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        def run(self) -> typing.NoReturn:
            self.setup_socket()
            self.accept()

        def setup_socket(self) -> None:
            self.sock.bind((self.host, self.port))
            self.sock.listen(int(utils.query_config("LISTENS_COUNT")))
            self.sock.settimeout(int(utils.query_config("HTTP_TIMEOUT")))
            self.sock.setblocking(True)

        def accept_request(self, client_sock, client_addr) -> None:
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
                    return
                if not _data:
                    break
                data += _data
            req = data.decode("utf-8")

            response = self.process_response(req)
            if not response:
                logger.warning(
                    eval(utils.get_message("network.http_server.recv_no_msg", 0))
                )
                return
            client_sock.sendall(response)
            logger.debug(eval(utils.get_message("network.http_server.send_back", 0)))
            # clean up
            logger.debug(eval(utils.get_message("network.http_server.full", 0)))
            client_sock.shutdown(socket.SHUT_WR)
            client_sock.close()

        def accept(self) -> typing.NoReturn:
            while True:
                (client, address) = self.sock.accept()
                threading.Thread(
                    target=self.accept_request, args=(client, address)
                ).start()

        def process_response(self, request) -> bytes:
            logger.debug(
                eval(utils.get_message("network.http_server.process_response", 0))
            )
            formatted_data = request.strip().split("\n")
            request_words = formatted_data[0].split()

            if len(request_words) == 0:
                return b''

            requested_file = request_words[1][1:]
            if request_words[0] == "GET":
                return self.get_request(requested_file, formatted_data)
            elif request_words[0] == "POST":
                return self.post_request(requested_file, formatted_data)
            elif request_words[0] == "HEAD":
                return self.head_request(requested_file, formatted_data)
            return self.method_not_allowed()

        def has_permission_other(self, requested_file) -> bool:
            """Check readable permissions"""
            return os.access(requested_file, os.R_OK)

        def _check_binary(self, data_bytes) -> bool:
            return bool(
                data_bytes.translate(
                    None,
                    bytearray(
                        {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F}
                    ),
                )
            )

        def should_return_binary(self, filename) -> bool:
            """Check file is binary"""
            logger.debug(eval(utils.get_message("network.http_server.check_binary", 0)))
            with open(filename, "rb") as file:
                logger.debug(
                    eval(utils.get_message("network.http_server.file_contents", 0))
                )
                return self._check_binary(file.read())

        def get_file_binary_contents(self, filename) -> bytes:
            """Get (binary) file content."""
            logger.debug(
                eval(utils.get_message("network.http_server.file_contents", 0))
            )
            with open(filename, "rb", encoding="utf-8") as file:
                return file.read()

        def get_file_contents(self, filename) -> str:
            """Get (plaintext) file content."""
            logger.debug(
                eval(utils.get_message("network.http_server.file_contents", 0))
            )
            with open(filename, "r", encoding="utf-8") as file:
                return file.read()

        def get_request(self, requested_file, data) -> bytes:
            """Get request messages."""
            if not requested_file:
                requested_file = "index.html"
            if not os.path.exists(requested_file):
                return self.resource_not_found()
            elif not self.has_permission_other(requested_file):
                return self.resource_forbidden()
            else:
                builder = self.ResponseBuilder()

                if self.should_return_binary(requested_file):
                    builder.set_content(self.get_file_binary_contents(requested_file))
                else:
                    builder.set_content(self.get_file_contents(requested_file))

                builder.set_status("200", "OK")

                builder.add_header("Connection", "close")
                builder.add_header(
                    "Content-Type", mime_types["." + requested_file.split(".")[-1]]+"; charset=utf8"
                )
                builder.add_header("Connection", "close")
                builder.add_header("Date", time.strftime('%a, %d %b %Y %H:%M:%S GMT',time.localtime(os.path.getctime(requested_file))))
                builder.add_header("Last-Modified", time.strftime('%a, %d %b %Y %H:%M:%S GMT',time.localtime(os.path.getmtime(requested_file))))

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

        def post_request(self, requested_file, data) -> bytes:
            builder = self.ResponseBuilder()
            builder.set_status("200", "OK")
            builder.add_header("Connection", "close")
            builder.add_header(
                "Content-Type", mime_types[requested_file.rsplit(".")[-1]]
            )
            builder.set_content(self.get_file_contents(requested_file))
            return builder.build()

        def head_request(self, requested_file, data):
            builder = self.ResponseBuilder()
            builder.set_status("200", "OK")
            builder.add_header("Connection", "close")
            builder.add_header(
                "Content-Type", mime_types[requested_file.rsplit(".")[-1]]
            )
            return builder.build()

    @staticmethod
    async def ws_server(websocket, path):
        # 采用JSON式
        # 将新连接的客户端添加到clients集合中
        async for message in websocket:
            logger.debug(eval(utils.get_message("network.ws_server.recived", 0)))
            try:
                data: dict = json.loads(str(message.replace("'", '"')), strict=False)
            except:
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
                                    "sender": SYSTEM_NAME,
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
                            eval(utils.get_message("network.player.anonymous_send", 0))
                        )
                        continue
            elif data["type"] == "login":
                if data["content"] in utils.get_players():
                    logger.warning(
                        eval(utils.get_message("network.player.duplicate_login", 0))
                    )
                    commands.kick(data["content"])
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
    def run_server():
        asyncio.set_event_loop(asyncio.new_event_loop())
        start_server = websockets.serve(network.ws_server, "0.0.0.0", WS_PORT)
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()


class commands:
    class _CommandNotFoundError(Exception):
        def __init__(self, message):
            self.message = message

    class _RedirectToAlias(Exception):  # 其实是个信号 不是Error
        def __init__(self, message):
            self.message = message

    class _AsyncFunction(Exception):
        def __init__(self, message):
            self.message = message

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
    }
    async_commands = [
        "kick",
        "say",
    ]

    @staticmethod
    def execute(executer, command):
        if not command.strip():
            return 0
        if executer == SYSTEM_NAME:
            players_access = accesses.get("server")
        else:
            players_access = utils.get_player(executer).access
        compiled = command.split(" ")  # 以第一个参数为主命令，空格为参数
        try:
            run_compiled = f"commands.{compiled[0]}({(','.join(compiled[1:]))})"
            logger.debug(eval(utils.get_message("commands.run_compiled", 0)))
            if compiled[0] not in commands.command_access:
                raise commands._CommandNotFoundError(
                    f"Command {compiled[0]} not found."
                )
            else:
                if players_access >= commands.command_access[compiled[0]]:
                    logger.info(eval(utils.get_message("command.execute", 0)))
                    value = eval(run_compiled)
                    return value
                else:
                    logger.warning(
                        eval(utils.get_message("command.execute.access_denied", 0))
                    )  # 权限不足
                    return -1
        except commands._CommandNotFoundError:
            if (
                commands.command_access.get(compiled[0]) is None
                and commands.alias.get(compiled[0]) is None
            ):
                if command != "":
                    logger.error(
                        eval(utils.get_message("command.execute.not_found", 0))
                    )
                    detect = process.extractOne(
                        command, list(commands.command_access.keys())
                    )
                    if detect[1] >= 85:
                        logger.info(
                            eval(utils.get_message("command.execute.syntax_detect", 0))
                        )
                return -2
        except commands._RedirectToAlias:
            compiled[0] = commands.alias.get(compiled[0])
            if players_access >= commands.command_access[compiled[0]]:
                logger.info(eval(utils.get_message("command.execute", 0)))
                compiled = f"commands.{compiled[0]}({(','.join(compiled[1:]))})"
                logger.debug(eval(utils.get_message("commands.compiled", 0)))

            else:
                logger.warning(
                    eval(utils.get_message("command.execute.access_denied", 0))
                )  # 权限不足
                return -1

    @staticmethod
    async def kick(player_name):
        if player_name in utils.get_players():
            logger.info(eval(utils.get_message("command.kick", 0)))
            await utils.get_player(player_name).websocket.close()
            utils.delete_player(player_name)
            return 0
        logger.warning(eval(utils.get_message("command.kick.player_not_found", -3)))
        return -3

    @staticmethod
    def stop(delay=0):
        if delay > 4294967:  # 它是固定的值吗..?
            logger.error(eval(utils.get_message("command.stop.delay_too_large", 0)))
            return 0
        elif delay > 0:
            logger.info(eval(utils.get_message("command.stop.delay_stop", 0)))
        elif delay < 0:
            logger.error(eval(utils.get_message("command.stop.smaller_zero", 0)))
        elif delay == 0:
            logger.info(eval(utils.get_message("command.stop", 0)))
        threading.Thread(
            target=lambda: exec(
                f"time.sleep({delay})\ngame.stop()\ngame.server_running=False"
            )
        ).start()
        return 0

    @staticmethod
    def modify_access(command, new_access):
        if new_access > 5:
            logger.error(eval(utils.get_message("command.modify_access", 1)))
            return -1
        elif new_access < 1:
            logger.error(eval(utils.get_message("command.modify_access", 1.5)))
            return -1.5
        commands.command_access[command] = new_access
        logger.warning(eval(utils.get_message("command.modify_access", 0)))
        return 0

    @staticmethod
    def get_commands():
        commands_list = [
            method
            for method in dir(commands)
            if not method.startswith("_") and callable(getattr(commands, method))
        ]
        out = eval(utils.get_message("command.get_commands", 0))
        logger.info(eval(utils.get_message("command.get_commands", 0)))
        return out

    @staticmethod
    def clean_logs(folder_path="./logs/"):
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
    def list():
        lists = utils.get_players()
        out = eval(utils.get_message("command.list", 0))
        logger.info(out)
        return out

    @staticmethod
    def player_access(player_name, access_):
        if player_name in utils.get_players():
            new_access = accesses.get(access_)
            if new_access is None:
                out = eval(utils.get_message("command.player_access", -3))
                logger.warning(out)
                return out
            else:
                out = eval(utils.get_message("command.player_access", 0))
                logger.info(out)
                utils.get_player(player_name).access = new_access
                return out
        out = eval(utils.get_message("command.player_access", -3.5))
        return out

    @staticmethod
    def new_alias(command, alias):
        if (
            commands.alias.get(alias) is not None
            or commands.command_access.get(alias) is not None
        ):
            out = eval(utils.get_message("command.new_alias", -2))
            logger.info(out)
            return out
        else:
            out = eval(utils.get_message("command.new_alias", 0))
            logger.info(out)
            commands.alias[alias] = command
            return out

    @staticmethod
    def del_alias(alias):
        if commands.alias.get(alias) is None:
            out = eval(utils.get_message("command.del_alias", -2))
            logger.info(out)
            return out
        else:
            out = eval(utils.get_message("command.del_alias", 0))
            logger.info(out)
            del commands.alias[alias]
            return out

    @staticmethod
    def get_alias():
        all_alias = list(commands.alias.keys())
        out = eval(utils.get_message("command.get_alias", 0))
        logger.info(out)
        return out

    @staticmethod
    def ban(player_name):
        if not player_name:
            out = eval(utils.get_message("command.ban", -3))
            logger.warning(out)
            return out
        if player_name not in utils.get_players():
            logger.warning(eval(utils.get_message("command.kick", -3)))
        if player_name in banlist:
            logger.error(eval(utils.get_message("network.player.duplicate_ban", 0)))
            return
        with open("banlist.txt", "a", encoding="utf-8") as ban_file:
            ban_file.write(player_name + "\n")
        banlist.append(player_name)
        commands.kick(player)
        logger.info(eval(utils.get_message("command.ban", 0)))

    @staticmethod
    def unban(player_name):
        if not player_name:
            logger.warning(eval(utils.get_message("command.unban", -3)))
            return
        if player_name not in banlist:
            logger.warning(eval(utils.get_message("network.player.never_ban", 0)))
            return
        with open("banlist.txt", "r", encoding="utf-8") as file:
            lines = file.readlines()
        with open("banlist.txt", "w", encoding="utf-8") as write_file:
            for line in lines:
                if line.strip() != player_name:
                    write_file.write(line)
        banlist.remove(player_name)
        logger.info(eval(utils.get_message("command.unban", 0)))

    @staticmethod
    def banlist():
        logger.info(eval(utils.get_message("command.banlist", 0)))

    @staticmethod
    async def say(message):
        await asyncio.wait(
            [
                user.send(
                    json.dumps(
                        {"type": "send", "content": message, "sender": SYSTEM_NAME}
                    )
                )
                for user in utils.get_websockets()
            ]
        )


lang = {}
COMMENTING = False
try:
    LANGUAGE_LOAD_ERROR_FLAG = False
    LANGUAGE = arg[2]
except:
    LANGUAGE_LOAD_ERROR_FLAG = True
    LANGUAGE = "zh_cn"
try:
    with open("./lang/" + LANGUAGE + ".lang", "r", encoding="utf-8") as f:
        readlines = f.readlines()
        if "No Replace" not in readlines[0]:
            replace_punctuations = eval("{" + readlines[0] + "}")
        else:
            replace_punctuations = {}
        for langs in readlines[1:]:
            if COMMENTING:
                continue
            if langs.startswith("--Comments: Start"):
                COMMENTING = True
                continue
            if langs.startswith("--Comments: End"):
                COMMENTING = False
                continue
            if langs.startswith("--"):
                COMMENTING = False
                continue
            tmp = langs.rsplit("#", 2)[0].split(
                ",", 2
            )  # [0]: 命令 [1]: 返回值 [2]: 语言内容 [3]: 注释
            if tmp == [""] or []:
                continue

            for punctuations in replace_punctuations.keys():
                tmp[2] = tmp[2].replace(
                    punctuations, replace_punctuations.get(punctuations)
                )
            lang[f"{tmp[0]}.{tmp[1]}"] = tmp[2]
except FileNotFoundError:
    if not os.path.exists("./lang/"):
        os.mkdir("./lang/")
    logger.critical("语言文件不存在. ")
    os._exit(0)
if LANGUAGE_LOAD_ERROR_FLAG:
    logger.warning(eval(utils.get_message("root.unchoosed_lang", 0)))
try:
    WS_PORT = arg[1]
except:
    logger.warning(eval(utils.get_message("root.unchoosed_port", 0)))
    WS_PORT = 3827
try:
    HTTP_PORT = arg[4]
except:
    HTTP_PORT = 3872
    logger.warning(eval(utils.get_message("root.unchoosed_http_port", 0)))
try:
    SYSTEM_NAME = arg[3]
except:
    logger.warning(eval(utils.get_message("root.unchoosed_system_name", 0)))
    SYSTEM_NAME = "Server"

logger.debug(eval(utils.get_message("root.loaded_language", 0)))

try:
    for plugin in os.listdir("./plugins/"):
        with open("./plugins/" + plugin, "r", encoding="utf-8") as f:
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
    with open("./config/default_prompt.txt", "r", encoding="utf-8") as f:
        PROMPT = f.read().strip() + " "
except FileNotFoundError:
    if not os.path.exists("./config/"):
        os.mkdir("./config/")
    with open("./config/default_prompt.txt", "w", encoding="utf-8") as f:
        PROMPT = ">>> "
        f.write(PROMPT)
logger.debug(eval(utils.get_message("root.loaded_prompt", 0)))
try:
    with open("banlist.txt", "r", encoding="utf-8") as f:
        banlist = [ban.strip() for ban in f.readlines()]
except FileNotFoundError:
    with open("banlist.txt", "w", encoding="utf-8") as f:
        banlist = []
        f.write("")

logger.debug(eval(utils.get_message("root.loaded_bans", 0)))
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
        HTTP_TIMEOUT = 60
        LISTENS_COUNT = 8
# TODO: 配置文档化所有的参数

def run(enabled_shell=True):
    try:
        threading.Thread(target=network.run_server).start()
    except RuntimeError:
        logger.critical(eval(utils.get_message("root.ws_network_run_error", 0)))
        game.error_stop()
    try:
        network.HTTPServer("0.0.0.0", int(utils.query_config("HTTP_PORT"))).start()
    except RuntimeError:
        logger.critical(eval(utils.get_message("root.ws_network_run_error", 0)))
        game.error_stop()
    if enabled_shell:
        try:
            game.command_interpreter(PROMPT)
        except KeyboardInterrupt:
            game.stop()


if __name__ == "__main__":
    if ALLOW_PRINT:
        print(eval(utils.get_message("game.command_interpreter.start_info", 0)))
    run()
