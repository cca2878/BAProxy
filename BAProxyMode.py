from enum import Enum


class BAProxyMode(Enum):
    OBSERVER = 1
    MODIFIER = 2

    def isSafe(self) -> bool:
        return self in [BAProxyMode.OBSERVER]
