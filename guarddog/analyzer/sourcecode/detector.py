from abc import abstractmethod
from typing import Optional


class Detector:
    RULE_NAME = ""

    def __init__(self, name: str, description: str) -> None:
        self.name = name
        self.description = description

    # returns (ruleMatches, message)
    @abstractmethod
    def detect(self, path: Optional[str] = None) -> tuple[bool, Optional[str]]:
        pass  # pragma: no cover

    def get_name(self) -> str:
        return self.name

    def get_description(self) -> str:
        return self.description
