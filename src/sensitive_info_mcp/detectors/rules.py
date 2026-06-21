"""规则检测引擎 - 基于正则表达式和校验算法的敏感信息检测

注意：所有模式使用 lookaround 断言而非 \\b，以兼容中文环境
（Python re 的 \\w 默认匹配 Unicode 字母，包含中文，导致 \\b 在中文字符旁失效）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from ..types import DetectionResult, RiskLevel, SensitiveType
from .base import BaseDetector


# 身份证校验位系数
ID_CARD_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
ID_CARD_CHECK_CODES = ["1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"]


def _validate_id_card(value: str) -> bool:
    """中国大陆身份证号校验位验证"""
    if len(value) != 18:
        return False
    body, check = value[:-1], value[-1].upper()
    if not body.isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(body, ID_CARD_WEIGHTS))
    return ID_CARD_CHECK_CODES[total % 11] == check


def _validate_bank_card(value: str) -> bool:
    """银行卡号 Luhn 校验"""
    digits = re.sub(r"\D", "", value)
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@dataclass
class Rule:
    """单条检测规则"""

    type: SensitiveType
    pattern: re.Pattern
    risk_level: RiskLevel = RiskLevel.MEDIUM
    confidence: float = 0.85
    validator: Optional[Callable[[str], bool]] = None
    description: str = ""
    extract_group: int = 0
    strip: bool = True

    def match_value(self, m: re.Match) -> str:
        v = m.group(self.extract_group) if self.extract_group else m.group(0)
        return v.strip() if self.strip else v


class RuleDetector(BaseDetector):
    """规则检测器：使用正则 + 校验函数检测敏感信息"""

    name = "rule"

    def __init__(self, extra_rules: Optional[list[Rule]] = None) -> None:
        self.rules: list[Rule] = list(self._builtin_rules())
        if extra_rules:
            self.rules.extend(extra_rules)

    @staticmethod
    def _builtin_rules() -> list[Rule]:
        return [
            # 私钥（优先级最高，避免被其他规则截断）
            Rule(
                type=SensitiveType.PRIVATE_KEY,
                pattern=re.compile(
                    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
                    r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
                    re.DOTALL,
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.99,
                description="PEM 格式私钥",
                strip=False,
            ),
            # AWS Access Key ID
            Rule(
                type=SensitiveType.AWS_KEY,
                pattern=re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.98,
                description="AWS Access Key ID",
            ),
            # 腾讯云 SecretId (AKID 前缀)
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(r"(?<![A-Za-z0-9])AKID[A-Za-z0-9]{32,}(?![A-Za-z0-9])"),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.95,
                description="腾讯云 SecretId",
            ),
            # 腾讯云 SecretKey (赋值格式)
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(
                    r"(?<![A-Za-z0-9_])secret_key\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{32,})['\"]?",
                    re.IGNORECASE,
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.9,
                extract_group=1,
                description="腾讯云 SecretKey",
            ),
            # 阿里云 AccessKeyId (LTAI 前缀)
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(r"(?<![A-Za-z0-9])LTAI[A-Za-z0-9]{20,}(?![A-Za-z0-9])"),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.98,
                description="阿里云 AccessKeyId",
            ),
            # 阿里云 AccessKeySecret (赋值格式)
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(
                    r"(?<![A-Za-z0-9_])access_key_secret\s*[:=]\s*['\"]?([A-Za-z0-9+/]{30,})['\"]?",
                    re.IGNORECASE,
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.9,
                extract_group=1,
                description="阿里云 AccessKeySecret",
            ),
            # 华为云 AK (Access Key ID)
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(r"(?<![A-Za-z0-9])AK[A-Za-z0-9]{20,}(?![A-Za-z0-9])"),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.95,
                description="华为云 Access Key ID",
            ),
            # 华为云 SK (Secret Key 赋值格式)
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(
                    r"(?<![A-Za-z0-9_])secret_key\s*[:=]\s*['\"]?([A-Za-z0-9+/]{32,})['\"]?",
                    re.IGNORECASE,
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.9,
                extract_group=1,
                description="华为云 Secret Key",
            ),
            # 火山引擎/火山方舟 AccessKeyId (AKLT 前缀)
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(r"(?<![A-Za-z0-9])AKLT[A-Za-z0-9]{20,}(?![A-Za-z0-9])"),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.95,
                description="火山引擎 AccessKeyId",
            ),
            # Anthropic Claude API Key (sk-ant- 前缀)
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{40,}(?![A-Za-z0-9])"),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.98,
                description="Anthropic Claude API Key",
            ),
            # OpenRouter API Key (sk-or- 前缀)
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(r"(?<![A-Za-z0-9])sk-or-[A-Za-z0-9_-]{40,}(?![A-Za-z0-9])"),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.98,
                description="OpenRouter API Key",
            ),
            # Cohere API Key (ek_ 前缀)
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(r"(?<![A-Za-z0-9])ek_[A-Za-z0-9]{40,}(?![A-Za-z0-9])"),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.95,
                description="Cohere API Key",
            ),
            # Groq API Key (gsk_ 前缀)
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(r"(?<![A-Za-z0-9])gsk_[A-Za-z0-9]{40,}(?![A-Za-z0-9])"),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.95,
                description="Groq API Key",
            ),
            # OpenAI API Key (sk- 前缀，已有通用规则覆盖，此处增强置信度)
            # GitHub Token (ghp_/gho_/ghu_/ghs_/ghr_)
            Rule(
                type=SensitiveType.GITHUB_TOKEN,
                pattern=re.compile(r"(?<![A-Za-z0-9])gh[posur]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])"),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.98,
                description="GitHub Personal Access Token",
            ),
            # JWT (header.payload.signature)
            Rule(
                type=SensitiveType.JWT,
                pattern=re.compile(
                    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])"
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.95,
                description="JWT Token",
            ),
            # 通用 API Key (key=value 格式)
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(
                    r"(?<![A-Za-z0-9_])(?:api[_-]?key|secret|token|access[_-]?key)\s*[:=]\s*"
                    r"['\"]?([A-Za-z0-9_/+=\-]{32,})['\"]?",
                    re.IGNORECASE,
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.8,
                extract_group=1,
                description="通用 API Key",
            ),
            # Google API Key
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}(?![A-Za-z0-9])"),
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                description="Google API Key",
            ),
            # Slack Token
            Rule(
                type=SensitiveType.API_KEY,
                pattern=re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9])"),
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                description="Slack Token",
            ),
            # 含凭据的 URL (https://user:pass@host)
            Rule(
                type=SensitiveType.URL_WITH_CRED,
                pattern=re.compile(
                    r"(?<![A-Za-z0-9])[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:([^/\s:@]+)@",
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.85,
                extract_group=1,
                description="URL 中嵌入的密码",
            ),
            # password = xxx
            Rule(
                type=SensitiveType.PASSWORD,
                pattern=re.compile(
                    r"(?<![A-Za-z0-9_])(?:password|passwd|pwd)\s*[:=]\s*['\"]?(\S+?)['\"]?(?:\s|$)",
                    re.IGNORECASE,
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.7,
                extract_group=1,
                description="明文密码",
            ),
            # 中国身份证号（18位，含校验位验证）
            Rule(
                type=SensitiveType.ID_CARD,
                pattern=re.compile(
                    r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.95,
                validator=_validate_id_card,
                description="中国大陆身份证号",
            ),
            # 中国手机号
            Rule(
                type=SensitiveType.PHONE,
                pattern=re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                description="中国手机号",
            ),
            # 银行卡号（含 Luhn 校验）
            Rule(
                type=SensitiveType.BANK_CARD,
                pattern=re.compile(
                    r"(?<!\d)6(?:2\d{2}|[013-9]\d{2})\d{10,15}(?!\d)"
                    r"|(?<!\d)4\d{15}(?!\d)"
                    r"|(?<!\d)5[1-5]\d{14}(?!\d)"
                    r"|(?<!\d)3[47]\d{13}(?!\d)"
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.85,
                validator=_validate_bank_card,
                description="银行卡号",
            ),
            # 邮箱
            Rule(
                type=SensitiveType.EMAIL,
                pattern=re.compile(
                    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9._%+-])"
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.95,
                description="电子邮箱",
            ),
            # IPv4
            Rule(
                type=SensitiveType.IP_ADDRESS,
                pattern=re.compile(
                    r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)"
                ),
                risk_level=RiskLevel.LOW,
                confidence=0.8,
                description="IPv4 地址",
            ),
            # 美国社会保障号 SSN
            Rule(
                type=SensitiveType.SSN,
                pattern=re.compile(
                    r"(?<!\d)(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)"
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.85,
                description="美国社会保障号",
            ),
        ]

    def add_rule(self, rule: Rule) -> None:
        """添加自定义规则"""
        self.rules.append(rule)

    def detect(self, text: str) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        occupied: list[tuple[int, int]] = []

        def _overlaps(s: int, e: int) -> bool:
            return any(not (e <= os or s >= oe) for os, oe in occupied)

        for rule in self.rules:
            for m in rule.pattern.finditer(text):
                start, end = m.span()
                if rule.extract_group:
                    try:
                        gs, ge = m.span(rule.extract_group)
                    except IndexError:
                        gs, ge = start, end
                else:
                    gs, ge = start, end

                value = rule.match_value(m)
                if not value:
                    continue

                confidence = rule.confidence
                if rule.validator and not rule.validator(value):
                    continue
                elif rule.validator:
                    confidence = min(0.99, confidence + 0.04)

                if _overlaps(gs, ge):
                    continue
                occupied.append((gs, ge))

                results.append(
                    DetectionResult(
                        type=rule.type,
                        value=value,
                        masked_value="",
                        start=gs,
                        end=ge,
                        confidence=confidence,
                        source="rule",
                        risk_level=rule.risk_level,
                        suggestion=f"检测到{rule.description}，建议脱敏处理",
                    )
                )

        results.sort(key=lambda r: r.start)
        return results
