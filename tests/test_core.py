"""核心功能测试"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sensitive_info_mcp.scanner import Scanner
from sensitive_info_mcp.types import SensitiveType, RiskLevel, MaskStrategy, MaskConfig


# 测试样本
# 测试用凭据以拼接方式存储，避免被 GitHub secret scanning 误判为真实密钥
_GH_TOKEN = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
_STRIPE_KEY = "sk_test_" + "FAKE_FOR_TEST_ONLY_1234567890abcdef"
_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
SAMPLE_TEXT = f"""
用户张三最近登录系统，他的手机号是13812345678，邮箱是 zhangsan@example.com。
身份证号：110101199003071233
银行卡号：4111111111111111
请勿泄露以下密钥：
api_key = {_STRIPE_KEY}
GitHub Token: {_GH_TOKEN}
JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
数据库连接：mysql://root:password123@10.0.0.1:3306/db
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygvF...
-----END RSA PRIVATE KEY-----
AWS Key: {_AWS_KEY}
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
    assert _GH_TOKEN not in masked, "Token未被脱敏!"

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


def test_scan_snippets():
    """测试批量片段初筛"""
    import json
    from sensitive_info_mcp.server import scan_snippets, Snippet

    snippets = [
        Snippet(id="s1", content="phone=13812345678", location="a.py:1"),
        Snippet(id="s2", content=f"token={_GH_TOKEN}", location="b.py:2"),
        Snippet(id="s3", content="print('hello world')", location="c.py:3"),
    ]
    result = json.loads(scan_snippets(snippets))
    assert result["total_findings"] >= 1, "应检测到敏感信息"
    assert "s3" in result["clean_ids"], "干净片段应在 clean_ids 中"
    assert all(r["findings_count"] > 0 for r in result["results"]), "命中片段应有 findings"
    for r in result["results"]:
        for f in r["findings"]:
            assert f["location"], "findings 的 location 应已回填"
    print(f"✓ scan_snippets: 命中 {result['total_findings']} 处，未命中 {result['clean_ids']}")
    print("✓ 批量片段初筛测试通过\n")


def test_build_report_mixed_sources():
    """测试混合 rule+llm 来源的报告生成"""
    from sensitive_info_mcp.server import build_report, FindingInput

    findings = [
        FindingInput(type="phone", value="13812345678", source="rule",
                     risk_level="high", location="a.py:1"),
        FindingInput(type="llm_detected", value="DB_PASSWORD=secret123", source="llm",
                     risk_level="critical", location="d.py:5",
                     suggestion="[hardcoded_credential] 硬编码数据库密码"),
    ]
    md = build_report(findings, title="测试报告", include_masking=True)
    assert "# 测试报告" in md, "报告应含自定义标题"
    assert "rule" in md and "llm" in md, "报告应含来源统计"
    assert "来源统计" in md, "报告应含来源统计段"
    assert "138****" in md or "REDACTED" in md, "报告应含脱敏建议值"
    print("✓ build_report 混合来源报告测试通过\n")


def test_llm_detected_type_masking():
    """测试 LLM_DETECTED 类型脱敏"""
    from sensitive_info_mcp.maskers import Masker

    masked = Masker().mask_value(SensitiveType.LLM_DETECTED, "some_secret_value")
    assert masked == "[LLM_REDACTED]", f"LLM_DETECTED 应脱敏为 [LLM_REDACTED]，实际: {masked}"
    print(f"✓ LLM_DETECTED 脱敏: some_secret_value → {masked}")
    print("✓ LLM_DETECTED 类型脱敏测试通过\n")


def test_source_field_llm():
    """测试 DetectionResult 的 source 字段支持 llm"""
    from sensitive_info_mcp.types import DetectionResult

    r = DetectionResult(type=SensitiveType.LLM_DETECTED, value="xxx", source="llm")
    dumped = r.model_dump(mode="json")
    assert dumped["source"] == "llm", "source 应为 llm"
    assert dumped["type"] == "llm_detected", "type 应为 llm_detected"
    print("✓ source 字段 llm 测试通过\n")


def test_ai_detector_removed():
    """测试 AIDetector 已彻底移除"""
    import importlib.util
    import sensitive_info_mcp.detectors as d

    assert not hasattr(d, "AIDetector"), "AIDetector 不应存在"
    assert not hasattr(d, "AIConfig"), "AIConfig 不应存在"
    spec = importlib.util.find_spec("sensitive_info_mcp.detectors.ai")
    assert spec is None, "detectors/ai.py 应已删除"
    print("✓ AIDetector 已彻底移除测试通过\n")


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
    test_scan_snippets()
    test_build_report_mixed_sources()
    test_llm_detected_type_masking()
    test_source_field_llm()
    test_ai_detector_removed()

    print("=" * 60)
    print("  ✅ 全部测试通过！")
    print("=" * 60)
