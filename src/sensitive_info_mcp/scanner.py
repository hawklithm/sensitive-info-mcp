"""扫描器 - 整合规则检测与脱敏处理

职责：仅基础检测（正则规则 + 校验算法）+ 脱敏。
LLM 语义检测由外部 Skill 完成（见 skills/sensitive-info-scan）。
"""
from __future__ import annotations

from typing import Optional

from .detectors import RuleDetector
from .maskers import Masker
from .types import (
    DetectionResult,
    MaskConfig,
    RiskLevel,
    ScanReport,
)


class Scanner:
    """敏感信息扫描器（基础规则检测 + 脱敏）"""

    def __init__(
        self,
        mask_config: Optional[MaskConfig] = None,
        extra_rules: Optional[list] = None,
    ) -> None:
        self.rule_detector = RuleDetector(extra_rules=extra_rules)
        self.masker = Masker(mask_config or MaskConfig())

    def detect(self, text: str) -> list[DetectionResult]:
        """仅检测，不脱敏（基础规则检测）"""
        return self.rule_detector.detect(text)

    def mask(self, text: str) -> tuple[str, list[DetectionResult]]:
        """检测并脱敏，返回 (脱敏后文本, 检测结果)"""
        findings = self.detect(text)
        masked_text, enriched = self.masker.apply(text, findings)
        return masked_text, enriched

    def report(self, text: str) -> ScanReport:
        """生成完整扫描报告"""
        findings = self.detect(text)
        masked_text, enriched = self.masker.apply(text, findings)

        summary: dict[str, int] = {}
        risk = RiskLevel.LOW
        risk_order = {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.CRITICAL: 3,
        }
        for f in enriched:
            summary[f.type.value] = summary.get(f.type.value, 0) + 1
            if risk_order[f.risk_level] > risk_order[risk]:
                risk = f.risk_level

        return ScanReport(
            total_findings=len(enriched),
            risk_level=risk,
            findings=enriched,
            masked_text=masked_text,
            original_length=len(text),
            masked_length=len(masked_text),
            summary=summary,
            source_summary={"rule": len(enriched)},
        )


# 默认全局实例（规则检测）
_default_scanner: Optional[Scanner] = None


def get_scanner() -> Scanner:
    global _default_scanner
    if _default_scanner is None:
        _default_scanner = Scanner()
    return _default_scanner
