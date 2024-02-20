#!/usr/bin/env python
# coding=utf-8
"""
A built-in Websocket server and HTTP server for the game "Draw and Guess".
"""
import time
import os
import threading
import sys
from colorama import init, Fore
from loguru import logger
import game
import network
import utils

init(autoreset=True)
logger.remove()
ALLOW_PRINT = False
if __name__ == "__main__":
    logger.add(sys.stderr, level=0, enqueue=False)  # 命令行句柄
    ALLOW_PRINT = True
logger.add(
    f"./logs/{time.strftime('%Y.%m.%d.log')}",
    encoding="utf-8",
    enqueue=True,
    rotation="00:00",
    level=0,
    colorize=False,
)  # 文件句柄


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


def run(enabled_shell=True, override_except_handle=True):
    """Run WebSocket server and HTTP server"""
    try:
        threading.Thread(target=network.run_ws_server).start()
    except RuntimeError:
        logger.critical(eval(utils.get_message("root.ws_network_run_error", 0)))
        game.error_stop()
    try:
        network.HTTPServer("0.0.0.0", int(utils.query_config("HTTP_PORT"))).start()
    except RuntimeError:
        logger.critical(eval(utils.get_message("root.http_network_run_error", 0)))
        game.error_stop()
    if enabled_shell:
        try:
            game.command_interpreter(utils.query_config("PROMPT") + " ")
        except KeyboardInterrupt:
            game.stop()
    if override_except_handle:
        sys.excepthook = utils.override_excepthook


if __name__ == "__main__":
    if ALLOW_PRINT:
        print(eval(utils.get_message("game.command_interpreter.start_info", 0)))
    run()
