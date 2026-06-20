"""脱敏处理器 - 对检测结果执行脱敏操作"""
from __future__ import annotations

import hashlib
import re
from typing import Optional

from ..types import DetectionResult, MaskConfig, MaskStrategy, SensitiveType


# 每种敏感类型的默认脱敏配置（覆盖全局策略）
_TYPE_DEFAULTS: dict[SensitiveType, dict] = {
    SensitiveType.PHONE: {
        "strategy": MaskStrategy.MASK,
        "keep_prefix": 3,
        "keep_suffix": 4,
    },
    SensitiveType.ID_CARD: {
        "strategy": MaskStrategy.MASK,
        "keep_prefix": 3,
        "keep_suffix": 4,
    },
    SensitiveType.EMAIL: {
        "strategy": MaskStrategy.KEEP_FORMAT,
    },
    SensitiveType.BANK_CARD: {
        "strategy": MaskStrategy.MASK,
        "keep_prefix": 4,
        "keep_suffix": 4,
    },
    SensitiveType.IP_ADDRESS: {
        "strategy": MaskStrategy.MASK,
        "keep_prefix": 0,
        "keep_suffix": 0,
    },
    # 高危类型默认完全掩码
    SensitiveType.API_KEY: {"strategy": MaskStrategy.REPLACE, "replacement": "[API_KEY_REDACTED]"},
    SensitiveType.AWS_KEY: {"strategy": MaskStrategy.REPLACE, "replacement": "[AWS_KEY_REDACTED]"},
    SensitiveType.GITHUB_TOKEN: {"strategy": MaskStrategy.REPLACE, "replacement": "[GITHUB_TOKEN_REDACTED]"},
    SensitiveType.JWT: {"strategy": MaskStrategy.REPLACE, "replacement": "[JWT_REDACTED]"},
    SensitiveType.PRIVATE_KEY: {"strategy": MaskStrategy.REPLACE, "replacement": "[PRIVATE_KEY_REDACTED]"},
    SensitiveType.PASSWORD: {"strategy": MaskStrategy.REPLACE, "replacement": "[PASSWORD_REDACTED]"},
    SensitiveType.URL_WITH_CRED: {"strategy": MaskStrategy.REPLACE, "replacement": "[CREDENTIAL_REDACTED]"},
    SensitiveType.SSN: {"strategy": MaskStrategy.MASK, "keep_prefix": 0, "keep_suffix": 4},
    SensitiveType.LLM_DETECTED: {"strategy": MaskStrategy.REPLACE, "replacement": "[LLM_REDACTED]"},
    SensitiveType.CUSTOM: {"strategy": MaskStrategy.MASK, "keep_prefix": 1, "keep_suffix": 1},
}


class Masker:
    """脱敏处理器"""

    def __init__(self, config: Optional[MaskConfig] = None) -> None:
        self.config = config or MaskConfig()

    def _effective_config(self, stype: SensitiveType) -> dict:
        """获取某个类型的生效配置

        优先级：type_overrides > 全局显式策略(非AUTO) > 类型默认 > 全局默认
        """
        type_default = _TYPE_DEFAULTS.get(stype, {})

        if self.config.strategy == MaskStrategy.AUTO:
            # AUTO 模式：使用类型默认策略
            strategy = type_default.get("strategy", MaskStrategy.MASK)
        else:
            # 用户显式设置全局策略：覆盖所有类型
            strategy = self.config.strategy

        cfg = {
            "strategy": strategy,
            "replacement": type_default.get("replacement", self.config.replacement),
            "keep_prefix": type_default.get("keep_prefix", self.config.keep_prefix),
            "keep_suffix": type_default.get("keep_suffix", self.config.keep_suffix),
        }
        # 用户对特定类型的覆盖最高优先
        override = self.config.type_overrides.get(stype.value)
        if override:
            cfg.update(override)
        return cfg

    def mask_value(self, stype: SensitiveType, value: str) -> str:
        """对单个值脱敏"""
        cfg = self._effective_config(stype)
        strategy = MaskStrategy(cfg["strategy"])

        if strategy == MaskStrategy.REDACT:
            return "[REDACTED]"

        if strategy == MaskStrategy.REPLACE:
            return cfg["replacement"]

        if strategy == MaskStrategy.HASH:
            salt = self.config.hash_salt
            return "hash:" + hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()[:16]

        if strategy == MaskStrategy.MASK:
            kp, ks = cfg["keep_prefix"], cfg["keep_suffix"]
            if len(value) <= kp + ks:
                return "*" * len(value)
            return value[:kp] + "*" * (len(value) - kp - ks) + value[-ks:] if ks else value[:kp] + "*" * (len(value) - kp)

        if strategy == MaskStrategy.KEEP_FORMAT:
            return self._keep_format_mask(stype, value)

        return value

    def _keep_format_mask(self, stype: SensitiveType, value: str) -> str:
        """保留格式掩码"""
        if stype == SensitiveType.EMAIL:
            # z******@example.com
            if "@" in value:
                local, domain = value.split("@", 1)
                if len(local) <= 1:
                    return f"***@{domain}"
                return f"{local[0]}{'*' * (len(local) - 1)}@{domain}"
            return "***"
        # 默认保留首字符
        if len(value) <= 1:
            return "*"
        return value[0] + "*" * (len(value) - 1)

    def apply(self, text: str, findings: list[DetectionResult]) -> tuple[str, list[DetectionResult]]:
        """对文本应用脱敏，返回 (脱敏后文本, 填充了 masked_value 的结果)"""
        # 从后往前替换，避免位置偏移
        sorted_findings = sorted(findings, key=lambda f: f.start, reverse=True)
        masked_text = text
        enriched = list(findings)

        for f in sorted_findings:
            masked_val = self.mask_value(f.type, f.value)
            masked_text = masked_text[: f.start] + masked_val + masked_text[f.end :]
            f.masked_value = masked_val

        enriched.sort(key=lambda r: r.start)
        return masked_text, enriched
