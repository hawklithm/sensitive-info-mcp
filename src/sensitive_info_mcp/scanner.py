"""扫描器 - 整合规则检测、AI 检测和脱敏处理"""
from __future__ import annotations

from typing import Optional

from .detectors import AIDetector, AIConfig, RuleDetector
from .maskers import Masker
from .types import (
    DetectionResult,
    MaskConfig,
    RiskLevel,
    ScanReport,
    SensitiveType,
)


class Scanner:
    """敏感信息扫描器（整合规则 + AI + 脱敏）"""

    def __init__(
        self,
        mask_config: Optional[MaskConfig] = None,
        ai_config: Optional[AIConfig] = None,
        extra_rules: Optional[list] = None,
        enable_ai: bool = False,
    ) -> None:
        self.rule_detector = RuleDetector(extra_rules=extra_rules)
        self.ai_detector = AIDetector(ai_config) if ai_config or enable_ai else AIDetector()
        if enable_ai and ai_config:
            ai_config.enabled = True
            self.ai_detector.config = ai_config
        self.masker = Masker(mask_config or MaskConfig())

    def detect(self, text: str, use_ai: bool = False) -> list[DetectionResult]:
        """仅检测，不脱敏"""
        findings = self.rule_detector.detect(text)
        if use_ai and self.ai_detector.config.enabled:
            # AI 补充检测：排除已被规则覆盖的区间
            existing = {(f.start, f.end) for f in findings}
            ai_findings = self.ai_detector.detect(text)
            for f in ai_findings:
                if not any(not (f.end <= s or f.start >= e) for s, e in existing):
                    findings.append(f)
            findings.sort(key=lambda r: r.start)
        return findings

    def mask(
        self, text: str, use_ai: bool = False
    ) -> tuple[str, list[DetectionResult]]:
        """检测并脱敏，返回 (脱敏后文本, 检测结果)"""
        findings = self.detect(text, use_ai=use_ai)
        masked_text, enriched = self.masker.apply(text, findings)
        return masked_text, enriched

    def report(self, text: str, use_ai: bool = False) -> ScanReport:
        """生成完整扫描报告"""
        findings = self.detect(text, use_ai=use_ai)
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
        )


# 默认全局实例（规则检测，无 AI）
_default_scanner: Optional[Scanner] = None


def get_scanner() -> Scanner:
    global _default_scanner
    if _default_scanner is None:
        _default_scanner = Scanner()
    return _default_scanner
