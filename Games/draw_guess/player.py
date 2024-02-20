"""A module for players."""

import time


class Player:
    """A class for players."""

    def __init__(self, name, websocket, access=2):
        self.name = name
        self.websocket = websocket
        self.access = access
        self.last_heartbeat = time.time()

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    def __eq__(self, other):
        if vars(self) == vars(other):
            return True
        return False
