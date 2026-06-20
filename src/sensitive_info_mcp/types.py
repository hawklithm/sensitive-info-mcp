"""核心类型定义"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class SensitiveType(str, Enum):
    """敏感信息类型"""

    PHONE = "phone"  # 手机号
    ID_CARD = "id_card"  # 身份证号
    EMAIL = "email"  # 邮箱
    BANK_CARD = "bank_card"  # 银行卡号
    API_KEY = "api_key"  # 通用 API Key
    AWS_KEY = "aws_key"  # AWS 访问密钥
    GITHUB_TOKEN = "github_token"  # GitHub Token
    JWT = "jwt"  # JWT Token
    IP_ADDRESS = "ip_address"  # IP 地址
    PRIVATE_KEY = "private_key"  # 私钥
    PASSWORD = "password"  # 密码
    URL_WITH_CRED = "url_with_cred"  # 含凭据的 URL
    SSN = "ssn"  # 社会保障号
    CUSTOM = "custom"  # 自定义规则匹配
    LLM_DETECTED = "llm_detected"  # LLM 语义检测到的（由 Skill 二次筛选产生）


class RiskLevel(str, Enum):
    """风险等级"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MaskStrategy(str, Enum):
    """脱敏策略"""

    AUTO = "auto"  # 自动：使用各类型的默认策略
    MASK = "mask"  # 部分掩码: 138****1234
    REPLACE = "replace"  # 完全替换: ***
    HASH = "hash"  # 哈希: a1b2c3...
    KEEP_FORMAT = "keep_format"  # 保留格式掩码
    REDACT = "redact"  # 完全删除: [REDACTED]


class DetectionResult(BaseModel):
    """单条检测结果

    支持两种来源：rule（基础规则检测）与 llm（Skill 二次筛选产生）。
    外部/LLM finding 可能没有精确位置，故 start/end/masked_value 均有默认值。
    """

    type: SensitiveType
    value: str  # 原始值
    masked_value: str = ""  # 脱敏后的值（由 Masker 填充）
    start: int = 0  # 起始位置（外部 finding 可能为 0）
    end: int = 0  # 结束位置
    confidence: float = Field(0.7, ge=0.0, le=1.0, description="置信度 0-1")
    source: str = "rule"  # "rule" | "llm"
    risk_level: RiskLevel = RiskLevel.MEDIUM
    suggestion: str = ""
    location: str = ""  # 文件路径:行号 或片段 id（多文件报告溯源用）


class MaskConfig(BaseModel):
    """脱敏配置"""

    strategy: MaskStrategy = MaskStrategy.AUTO  # AUTO=使用类型默认策略
    replacement: str = "***"
    keep_prefix: int = 0  # 保留前缀字符数
    keep_suffix: int = 0  # 保留后缀字符数
    hash_salt: str = "sensitive-info-mcp"  # hash 策略的盐

    # 类型特定的默认配置（可选，覆盖全局策略）
    type_overrides: dict[str, dict] = Field(default_factory=dict)


class ScanReport(BaseModel):
    """扫描报告"""

    total_findings: int
    risk_level: RiskLevel
    findings: list[DetectionResult]
    masked_text: str = ""
    original_length: int = 0
    masked_length: int = 0
    summary: dict[str, int] = Field(default_factory=dict, description="按类型统计")
    source_summary: dict[str, int] = Field(
        default_factory=dict, description="按来源 rule|llm 统计"
    )

    def to_markdown(self) -> str:
        """生成 Markdown 报告"""
        lines = [
            "# 敏感信息扫描报告\n",
            f"- **发现总数**: {self.total_findings}",
            f"- **风险等级**: {self.risk_level.value}",
        ]
        if self.original_length:
            lines.append(f"- **原始长度**: {self.original_length} 字符")
            lines.append(f"- **脱敏后长度**: {self.masked_length} 字符")
        if self.source_summary:
            parts = " | ".join(f"{k} {v} 处" for k, v in self.source_summary.items())
            lines.append(f"- **来源统计**: {parts}")
        lines.append("")

        if self.summary:
            lines.append("## 类型统计\n")
            lines.append("| 类型 | 数量 |")
            lines.append("|------|------|")
            for t, c in self.summary.items():
                lines.append(f"| {t} | {c} |")
            lines.append("")

        if self.source_summary:
            lines.append("## 来源统计\n")
            lines.append("| 来源 | 数量 |")
            lines.append("|------|------|")
            for k, v in self.source_summary.items():
                lines.append(f"| {k} | {v} |")
            lines.append("")

        if self.findings:
            lines.append("## 详细发现\n")
            lines.append("| # | 类型 | 来源 | 位置 | 原始值 | 脱敏建议 | 风险 | 置信度 | 说明 |")
            lines.append("|---|------|------|------|--------|----------|------|--------|------|")
            for i, f in enumerate(self.findings, 1):
                val = f.value if len(f.value) <= 40 else f.value[:37] + "..."
                mv = f.masked_value if len(f.masked_value) <= 30 else f.masked_value[:27] + "..."
                loc = f.location or "-"
                sug = f.suggestion if len(f.suggestion) <= 30 else f.suggestion[:27] + "..."
                lines.append(
                    f"| {i} | {f.type.value} | {f.source} | {loc} "
                    f"| `{val}` | `{mv}` | {f.risk_level.value} | {f.confidence:.0%} | {sug} |"
                )
        else:
            lines.append("## 未发现敏感信息 ✅")

        return "\n".join(lines)
