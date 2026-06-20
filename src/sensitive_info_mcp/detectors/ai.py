"""AI 检测引擎 - 基于 LLM 语义理解的敏感信息检测

用于补充规则检测器无法覆盖的场景，例如：
- 上下文中的姓名、地址、公司内部信息
- 变形的敏感信息（如 "我的电话是 一三八 0000 一二三四"）
- 业务相关的敏感字段
"""
from __future__ import annotations

import json
import re
from typing import Optional

from ..types import DetectionResult, RiskLevel, SensitiveType
from .base import BaseDetector


class AIConfig:
    """AI 检测器配置"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        timeout: float = 30.0,
        enabled: bool = False,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.timeout = timeout
        self.enabled = enabled


_SYSTEM_PROMPT = """你是一个敏感信息检测专家。你的任务是识别文本中可能包含的敏感信息。

识别范围包括但不限于：
1. 个人姓名（中文姓名、英文姓名）
2. 详细地址（家庭住址、工作地址）
3. 日期信息（可能用于推断个人信息的生日等）
4. 公司内部信息（项目代号、内部系统名、商业机密）
5. 变形/拆分的敏感信息（如"一三八"表示138）
6. 其他上下文中明显属于隐私的内容

请返回 JSON 数组，每个元素包含：
- "type": 类型，从以下选择：name, address, birthday, internal_info, disguised_pii, other
- "value": 检测到的敏感信息原文
- "reason": 判断理由（简短）
- "confidence": 置信度 0-1

如果未发现敏感信息，返回空数组 []。
只返回 JSON，不要其他解释。"""

_USER_TEMPLATE = "请检测以下文本中的敏感信息：\n\n{text}"


class AIDetector(BaseDetector):
    """AI 语义检测器（可选，需要配置 API）"""

    name = "ai"

    def __init__(self, config: Optional[AIConfig] = None) -> None:
        self.config = config or AIConfig()
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        if not self.config.api_key:
            return None
        try:
            import httpx
        except ImportError:
            return None
        self._client = httpx.Client(
            base_url=self.config.base_url,
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            timeout=self.config.timeout,
        )
        return self._client

    def detect(self, text: str) -> list[DetectionResult]:
        if not self.config.enabled:
            return []
        client = self._get_client()
        if client is None:
            return []

        try:
            resp = client.post(
                "/chat/completions",
                json={
                    "model": self.config.model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": _USER_TEMPLATE.format(text=text)},
                    ],
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
        except Exception:
            return []

        # 兼容模型返回 {"findings": [...]} 或直接 [...] 的情况
        try:
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                items = parsed.get("findings") or parsed.get("results") or []
            else:
                items = parsed
        except json.JSONDecodeError:
            return []

        type_map = {
            "name": (SensitiveType.AI_DETECTED, RiskLevel.MEDIUM),
            "address": (SensitiveType.AI_DETECTED, RiskLevel.HIGH),
            "birthday": (SensitiveType.AI_DETECTED, RiskLevel.MEDIUM),
            "internal_info": (SensitiveType.AI_DETECTED, RiskLevel.HIGH),
            "disguised_pii": (SensitiveType.AI_DETECTED, RiskLevel.HIGH),
            "other": (SensitiveType.AI_DETECTED, RiskLevel.MEDIUM),
        }

        results: list[DetectionResult] = []
        for item in items:
            value = str(item.get("value", "")).strip()
            if not value:
                continue
            # 在原文中定位
            idx = text.find(value)
            if idx < 0:
                # 模糊匹配：去除空白后查找
                compact = re.sub(r"\s+", "", value)
                m = re.search(re.escape(compact), text)
                if not m:
                    continue
                idx = m.start()
            kind = str(item.get("type", "other"))
            stype, risk = type_map.get(kind, (SensitiveType.AI_DETECTED, RiskLevel.MEDIUM))
            conf = float(item.get("confidence", 0.7))
            results.append(
                DetectionResult(
                    type=stype,
                    value=value,
                    masked_value="",
                    start=idx,
                    end=idx + len(value),
                    confidence=conf,
                    source="ai",
                    risk_level=risk,
                    suggestion=str(item.get("reason", "AI 检测到的潜在敏感信息")),
                )
            )
        return results
