"""检测器基类"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..types import DetectionResult


class BaseDetector(ABC):
    """检测器抽象基类"""

    name: str = "base"

    @abstractmethod
    def detect(self, text: str) -> list[DetectionResult]:
        """检测文本中的敏感信息

        Args:
            text: 待检测文本

        Returns:
            检测结果列表
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"
