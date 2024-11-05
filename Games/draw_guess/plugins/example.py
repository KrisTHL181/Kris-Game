import __main__

__metadata__ = {"module_name": "自动kill自己", "module_version": "1.1.4.5.1.4"}


def on_plugin_load():
    __main__.logger.info("自动自杀模块加载完成!!Ohyee!!")

def at_exit(*args, **kwargs):
    __main__.os._exit(1)

def on_plugin_unload():
    __main__.logger.info("已卸载")