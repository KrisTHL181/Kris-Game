"""A module to run """

import json
import os
import asyncio
import threading
from fuzzywuzzy import process
from loguru import logger
import utils


class _commandNotFoundError(Exception):
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
alias_list = {
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
]


def execute(executer, command) -> str:
    """Check access and execute command."""
    if not command.strip():
        return ""
    if executer == utils.query_config("SYSTEM_NAME"):
        players_access: int = int(utils.accesses["server"])
    else:
        players_access: int = utils.get_player(executer).access
    compiled = command.split(" ")  # 以第一个参数为主命令，空格为参数
    try:
        run_compiled = f"commands.{compiled[0]}({(','.join(compiled[1:]))})"
        logger.debug(eval(utils.get_message("commands.run_compiled", 0)))
        if compiled[0] not in command_access:
            raise _commandNotFoundError(f"command {compiled[0]} not found.")
        if players_access >= command_access[compiled[0]]:
            logger.info(eval(utils.get_message("command.execute", 0)))
            value = eval(run_compiled)
            return value
        out = eval(utils.get_message("command.execute.access_denied", 0))
        logger.warning(out)  # 权限不足
        return out
    except _commandNotFoundError:
        if (
            command_access.get(compiled[0]) is None
            and alias_list.get(compiled[0]) is None
        ):
            if command != "":
                show_out = eval(utils.get_message("command.execute.not_found", 0))
                logger.error(show_out)
                detect = process.extractOne(command, command_access.keys())
                if detect[1] >= 85:
                    out = eval(utils.get_message("command.execute.syntax_detect", 0))
                    show_out += out
                    logger.info(out)
                return show_out
    except _RedirectToAlias:
        compiled[0] = alias_list.get(compiled[0])
        if players_access >= command_access[compiled[0]]:
            logger.info(eval(utils.get_message("command.execute", 0)))
            logger.debug(eval(utils.get_message("commands.compiled", 0)))
            return execute(utils.query_config("SYSTEM_NAME"), " ".join(compiled))
        out = eval(utils.get_message("command.execute.access_denied", 0))
        logger.warning(out)  # 权限不足
        return out
    return out


async def kick(player_name):
    """Kick player."""
    if player_name in utils.get_players():
        logger.info(eval(utils.get_message("command.kick", 0)))
        await utils.get_player(player_name).websocket.close()
        utils.delete_player(player_name)
        return 0
    logger.warning(eval(utils.get_message("command.kick.player_not_found", -3)))
    return -3


def stop(delay=0):
    """Stop server."""
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
            f"time.sleep({delay})\nGame.stop()\nGame.server_running=False"
        )
    ).start()
    return out


def modify_access(command, new_access):
    """Modify command's access."""
    if new_access > 5:
        out = eval(utils.get_message("command.modify_access", 1))
        logger.error(out)
        return out
    if new_access < 1:
        out = eval(utils.get_message("command.modify_access", 1.5))
        logger.error(out)
        return out
    command_access[command] = new_access
    logger.warning(eval(utils.get_message("command.modify_access", 0)))
    return 0


def get_commands():
    """Get command list."""
    commands_list = [
        method
        for method in dir()
        if not method.startswith("_") and callable(locals()[method])
    ]
    out = eval(utils.get_message("command.get_commands", 0))
    logger.info(eval(utils.get_message("command.get_commands", 0)))
    return out


def clean_logs(folder_path="./logs/"):
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


def player_list():
    """Get player list."""
    lists = utils.get_players()
    out = eval(utils.get_message("command.list", 0))
    logger.info(out)
    return out


def player_access(player_name, access_):
    """Change player's access."""
    if player_name in utils.get_players():
        new_access = utils.accesses.get(access_)
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


def new_alias(command, alias):
    """Add a alias_list."""
    if alias_list.get(alias) is not None or command_access.get(alias) is not None:
        out = eval(utils.get_message("command.new_alias", -2))
        logger.info(out)
        return out
    out = eval(utils.get_message("command.new_alias", 0))
    logger.info(out)
    alias[alias] = command
    return out


def del_alias(alias):
    """Remove a alias"""
    if alias_list.get(alias) is None:
        out = eval(utils.get_message("command.del_alias", -2))
        logger.info(out)
        return out
    out = eval(utils.get_message("command.del_alias", 0))
    logger.info(out)
    del alias[alias]
    return out


def get_alias():
    """Get alias list."""
    all_alias = list(alias_list.keys())
    out = eval(utils.get_message("command.get_alias", 0))
    logger.info(out)
    return out


def ban(player_name):
    """Ban a player, it never login to Game."""
    if not player_name:
        out = eval(utils.get_message("command.ban", -3))
        logger.warning(out)
        return out
    if player_name not in utils.get_players():
        logger.warning(eval(utils.get_message("command.kick", -3)))
    if player_name in utils.banlist:
        out = eval(utils.get_message("Network.player.duplicate_ban", 0))
        logger.error(out)
        return out
    with open("banlist.txt", "a", encoding="utf-8") as ban_file:
        ban_file.write(player_name + "\n")
    utils.banlist.append(player_name)
    kick(player_name)
    out = eval(utils.get_message("command.ban", 0))
    logger.info(out)
    return out


def unban(player_name):
    """Unban a player."""
    if not player_name:
        out = eval(utils.get_message("command.unban", -3))
        logger.warning(out)
        return out
    if player_name not in utils.banlist:
        out = eval(utils.get_message("Network.player.never_ban", 0))
        logger.warning(out)
        return out
    with open("banlist.txt", "r", encoding="utf-8") as file:
        lines = file.readlines()
    with open("banlist.txt", "w", encoding="utf-8") as write_file:
        for file_line in lines:
            if file_line.strip() != player_name:
                write_file.write(file_line)
    utils.banlist.remove(player_name)
    out = eval(utils.get_message("command.unban", 0))
    logger.info(out)
    return out


def banlist():
    """Get banned player's list."""
    out = eval(utils.get_message("command.banlist", 0))
    logger.info(out)
    return out


async def say(message):
    """Say a message by WebSocket server."""
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
    return None
