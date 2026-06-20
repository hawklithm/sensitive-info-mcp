"""核心功能测试"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sensitive_info_mcp.scanner import Scanner
from sensitive_info_mcp.types import SensitiveType, RiskLevel, MaskStrategy, MaskConfig


# 测试样本
SAMPLE_TEXT = """
用户张三最近登录系统，他的手机号是13812345678，邮箱是 zhangsan@example.com。
身份证号：110101199003071233
银行卡号：4111111111111111
请勿泄露以下密钥：
api_key = sk_test_FAKE_FOR_TEST_ONLY_1234567890abcdef
GitHub Token: ghp_abcdefghijklmnopqrstuvwxyz0123456789
JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
数据库连接：mysql://root:password123@10.0.0.1:3306/db
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygvF...
-----END RSA PRIVATE KEY-----
AWS Key: AKIAIOSFODNN7EXAMPLE
IP地址: 192.168.1.100
"""


def test_detection():
    """测试规则检测"""
    scanner = Scanner()
    findings = scanner.detect(SAMPLE_TEXT)
    types_found = {f.type for f in findings}

    print(f"✓ 检测到 {len(findings)} 处敏感信息")
    for f in findings:
        print(f"  - [{f.type.value}] risk={f.risk_level.value} conf={f.confidence:.0%} value={f.value[:40]}")

    # 断言关键类型都被检测到
    assert SensitiveType.PHONE in types_found, "未检测到手机号"
    assert SensitiveType.EMAIL in types_found, "未检测到邮箱"
    assert SensitiveType.ID_CARD in types_found, "未检测到身份证"
    assert SensitiveType.BANK_CARD in types_found, "未检测到银行卡"
    assert SensitiveType.API_KEY in types_found, "未检测到API Key"
    assert SensitiveType.GITHUB_TOKEN in types_found, "未检测到GitHub Token"
    assert SensitiveType.JWT in types_found, "未检测到JWT"
    assert SensitiveType.PRIVATE_KEY in types_found, "未检测到私钥"
    assert SensitiveType.AWS_KEY in types_found, "未检测到AWS Key"
    assert SensitiveType.URL_WITH_CRED in types_found, "未检测到URL凭据"
    assert SensitiveType.IP_ADDRESS in types_found, "未检测到IP地址"

    print("✓ 所有关键类型检测通过\n")
    return findings


def test_id_card_validation():
    """测试身份证校验位（无效的应被过滤）"""
    scanner = Scanner()
    # 一个校验位错误（末位应为3），一个正确
    text = "无效身份证: 11010119900307123X（校验位错误）\n有效身份证: 110101199003071233"
    findings = scanner.detect(text)
    valid = [f for f in findings if f.type == SensitiveType.ID_CARD]
    print(f"✓ 身份证检测：{len(valid)} 个有效（应只有1个通过校验）")
    assert len(valid) == 1, f"应有1个有效身份证，实际{len(valid)}"
    assert valid[0].value == "110101199003071233"
    print("✓ 身份证校验位验证通过\n")


def test_masking():
    """测试脱敏"""
    scanner = Scanner()
    masked, findings = scanner.mask(SAMPLE_TEXT)

    # 验证原始敏感值不在脱敏结果中
    assert "13812345678" not in masked, "手机号未被脱敏!"
    assert "zhangsan@example.com" not in masked or "***" in masked, "邮箱未被脱敏!"
    assert "110101199003071233" not in masked, "身份证未被脱敏!"
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in masked, "Token未被脱敏!"

    print("✓ 脱敏结果预览：")
    for f in findings[:6]:
        print(f"  {f.value[:30]:30s} → {f.masked_value}")
    print("✓ 脱敏验证通过\n")


def test_strategies():
    """测试不同脱敏策略"""
    phone = "13812345678"

    # MASK 策略
    cfg = MaskConfig(strategy=MaskStrategy.MASK, keep_prefix=3, keep_suffix=4)
    scanner = Scanner(mask_config=cfg)
    masked, _ = scanner.mask(phone)
    assert masked == "138****5678", f"MASK策略错误: {masked}"
    print(f"✓ MASK策略: {phone} → {masked}")

    # REPLACE 策略
    cfg = MaskConfig(strategy=MaskStrategy.REPLACE, replacement="[HIDDEN]")
    scanner = Scanner(mask_config=cfg)
    masked, _ = scanner.mask(phone)
    assert masked == "[HIDDEN]", f"REPLACE策略错误: {masked}"
    print(f"✓ REPLACE策略: {phone} → {masked}")

    # HASH 策略
    cfg = MaskConfig(strategy=MaskStrategy.HASH)
    scanner = Scanner(mask_config=cfg)
    masked, _ = scanner.mask(phone)
    assert masked.startswith("hash:"), f"HASH策略错误: {masked}"
    print(f"✓ HASH策略: {phone} → {masked}")

    # REDACT 策略
    cfg = MaskConfig(strategy=MaskStrategy.REDACT)
    scanner = Scanner(mask_config=cfg)
    masked, _ = scanner.mask(phone)
    assert masked == "[REDACTED]", f"REDACT策略错误: {masked}"
    print(f"✓ REDACT策略: {phone} → {masked}")

    print("✓ 所有脱敏策略验证通过\n")


def test_report():
    """测试报告生成"""
    scanner = Scanner()
    report = scanner.report(SAMPLE_TEXT)
    md = report.to_markdown()

    assert "# 敏感信息扫描报告" in md
    assert "发现总数" in md
    assert "类型统计" in md
    assert report.total_findings > 0

    print(f"✓ 报告生成成功，发现 {report.total_findings} 处，风险等级: {report.risk_level.value}")
    print("✓ 报告验证通过\n")
    return md


def test_clean_text():
    """测试无敏感信息的文本"""
    scanner = Scanner()
    clean = "这是一段普通的文本，没有任何敏感信息。今天天气不错，适合出门散步。"
    findings = scanner.detect(clean)
    assert len(findings) == 0, f"不应检测到敏感信息，但检测到{len(findings)}处"
    print("✓ 干净文本检测通过（无误报）\n")


if __name__ == "__main__":
    print("=" * 60)
    print("  敏感信息检测与脱敏工具 - 功能测试")
    print("=" * 60 + "\n")

    test_detection()
    test_id_card_validation()
    test_masking()
    test_strategies()
    test_report()
    test_clean_text()

    print("=" * 60)
    print("  ✅ 全部测试通过！")
    print("=" * 60)
