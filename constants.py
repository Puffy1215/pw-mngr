from enum import Enum


class MasterPasswordStatus(Enum):
    EMPTY = "0"
    SET = "1"


class Action(Enum):
    EXIT = "0"
    RETRIEVE = "1"
    SET = "2"
