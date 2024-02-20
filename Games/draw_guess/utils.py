"""A util class."""

import os
import functools
from loguru import logger
from player import Player

accesses = {"server": 4, "admin": 3, "player": 2, "spectators": 1, "banned": 0}
players = []
MIN_PLAYERS = 2
SCORES = {}
ACCEPT_PLAYERS = 0
lang = {}
COMMENTING = False
config = {}
LANGUAGE_LOADED_SUCCESS = False

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


@functools.cache
def query_config(key) -> str:
    """Query config in config file."""
    try:
        out = config[key].strip()
    except KeyError:
        return eval(get_message("root.config_not_found", 0))
    return out


try:
    with open(
        "./lang/" + query_config("LANGUAGE") + ".lang", "r", encoding="utf-8"
    ) as f:
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
            if tmp == [""]:
                continue

            for punctuations in replace_punctuations.keys():
                tmp[2] = tmp[2].replace(
                    punctuations, replace_punctuations[punctuations]
                )
            lang[f"{tmp[0]}.{tmp[1]}"] = tmp[2]
except FileNotFoundError:
    if not os.path.exists("./lang/"):
        os.mkdir("./lang/")
    logger.critical("语言文件不存在. ")
    os._exit(0)
else:
    LANGUAGE_LOADED_SUCCESS = True


@functools.cache
def get_message(eqalname, value) -> str:
    """Get information in language file."""
    try:
        out = str(lang[eqalname + "." + str(value)])
    except KeyError:
        return str(lang[("root.unknown_language.0")])
    return out


def get_players() -> list:
    """Get player name list."""
    return [vars(iter_player)["name"] for iter_player in players]


def get_player(name) -> Player:
    """Get player's type."""
    if name == query_config("SYSTEM_NAME"):
        return Player(query_config("SYSTEM_NAME"), None, accesses.get("server"))
    return [iter_player for iter_player in players if iter_player.name == name][0]


def delete_player(name) -> None:
    """Remove player's type in players(list)"""
    players.remove(get_player(name))


def login_player(name, websocket) -> Player:
    """Add a player in players(list)"""
    logined_player = Player(name, websocket)
    players.append(name)
    return logined_player


def get_websocket(name):
    """Get player's websocket object."""
    return [
        iter_player.websocket for iter_player in players if iter_player.name == name
    ][0]


def get_websockets() -> list:
    """Get all player's websocket object."""
    return [iter_player.websocket for iter_player in players]


def override_excepthook(err_type, err_value, err_traceback):
    """Overriding sys.excepthook."""
    logger.critical(
        eval(get_message("Game.command_interpreter.unhandled_critical_exception", 0))
    )
    logger.exception(err_traceback)


if LANGUAGE_LOADED_SUCCESS:
    logger.debug(eval(get_message("root.loaded_language", 0)))
    logger.debug(eval(get_message("root.loaded_config", 0)))

try:
    with open("banlist.txt", "r", encoding="utf-8") as f:
        banlist = [ban.strip() for ban in f.readlines()]
except FileNotFoundError:
    with open("banlist.txt", "w", encoding="utf-8") as f:
        banlist = []
        f.write("")
logger.debug(eval(get_message("root.loaded_bans", 0)))
