import os
from loguru import logger
import commands
import utils

"""A class to processing game's all events."""


def command_interpreter(prompt: str) -> None:
    """Run game's command interpreter."""
    while True:
        try:
            commands.execute(utils.query_config("SYSTEM_NAME"), str(input(prompt)))
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
            stop()
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
                    utils.get_message("game.command_interpreter.unhandled_exception", 0)
                )
            )
            logger.exception(err)


def stop(exit_value=0):
    """shutdown game server."""
    logger.info(eval(utils.get_message("game.command_interpreter.server_stop", 0)))
    os._exit(exit_value)


def error_stop(error_level=-1):
    """shutdown game server(when error)."""
    logger.error(eval(utils.get_message("game.command_interpreter.error_stop", 0)))
    os._exit(error_level)
