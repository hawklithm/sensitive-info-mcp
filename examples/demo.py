"""使用示例 - 演示敏感信息检测与脱敏的各种用法"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sensitive_info_mcp.scanner import Scanner
from sensitive_info_mcp.types import MaskConfig, MaskStrategy


def demo_basic_detection():
    """基础检测"""
    print("=" * 50)
    print("示例 1：基础检测")
    print("=" * 50)
    scanner = Scanner()
    text = "用户李四手机13912345678，邮箱lisi@test.com，身份证110101199003071233"
    findings = scanner.detect(text)
    for f in findings:
        print(f"  [{f.type.value:15s}] {f.value}  (风险: {f.risk_level.value}, 置信度: {f.confidence:.0%})")
    print()


def demo_masking():
    """脱敏处理"""
    print("=" * 50)
    print("示例 2：脱敏处理")
    print("=" * 50)
    scanner = Scanner()
    text = "手机13812345678，邮箱admin@company.com，卡号4111111111111111"
    masked, findings = scanner.mask(text)
    print(f"  原文: {text}")
    print(f"  脱敏: {masked}")
    print()


def demo_strategies():
    """不同脱敏策略"""
    print("=" * 50)
    print("示例 3：脱敏策略对比")
    print("=" * 50)
    phone = "13812345678"
    strategies = [
        ("AUTO (默认)", MaskStrategy.AUTO),
        ("MASK", MaskStrategy.MASK),
        ("REPLACE", MaskStrategy.REPLACE),
        ("HASH", MaskStrategy.HASH),
        ("REDACT", MaskStrategy.REDACT),
    ]
    for name, strategy in strategies:
        scanner = Scanner(mask_config=MaskConfig(strategy=strategy))
        masked, _ = scanner.mask(phone)
        print(f"  {name:15s}: {phone} → {masked}")
    print()


def demo_report():
    """生成报告"""
    print("=" * 50)
    print("示例 4：Markdown 扫描报告")
    print("=" * 50)
    scanner = Scanner()
    _aws = "AKIA" + "IOSFODNN7EXAMPLE"
    text = f"""
    系统配置泄露：
    AWS_KEY = {_aws}
    DB_URL = mysql://root:secret123@10.0.0.1/db
    管理员手机：13812345678
    """
    report = scanner.report(text)
    print(report.to_markdown())
    print()


def demo_custom_rules():
    """自定义规则"""
    print("=" * 50)
    print("示例 5：自定义检测规则")
    print("=" * 50)
    import re
    from sensitive_info_mcp.detectors.rules import Rule
    from sensitive_info_mcp.types import SensitiveType, RiskLevel

    # 添加内部员工号检测
    emp_rule = Rule(
        type=SensitiveType.CUSTOM,
        pattern=re.compile(r"(?<![A-Za-z0-9])EMP\d{6}(?![A-Za-z0-9])"),
        risk_level=RiskLevel.MEDIUM,
        confidence=0.9,
        description="内部员工编号",
    )
    scanner = Scanner(extra_rules=[emp_rule])
    text = "工单由 EMP123456 提交，联系电话13812345678"
    findings = scanner.detect(text)
    for f in findings:
        print(f"  [{f.type.value:15s}] {f.value}  ({f.suggestion})")
    print()


def demo_clean_text():
    """无敏感信息文本"""
    print("=" * 50)
    print("示例 6：干净文本（无误报）")
    print("=" * 50)
    scanner = Scanner()
    text = "今天的会议在3号会议室，讨论Q3季度计划。"
    findings = scanner.detect(text)
    print(f"  文本: {text}")
    print(f"  检测结果: {len(findings)} 处敏感信息 ✅" if not findings else f"  发现 {len(findings)} 处")
    print()


def demo_chinese_compatibility():
    """中文环境兼容性"""
    print("=" * 50)
    print("示例 7：中文环境兼容性")
    print("=" * 50)
    scanner = Scanner()
    # 敏感信息紧贴中文字符，仍能正确检测
    cases = [
        "我的手机是13812345678没问题",       # 手机号紧贴中文
        "身份证号：110101199003071233已验证", # 身份证紧贴中文
        "邮箱test@qq.com可以联系",            # 邮箱紧贴中文
    ]
    for case in cases:
        findings = scanner.detect(case)
        print(f"  「{case}」")
        print(f"    → 检测到 {len(findings)} 处: {[f.value for f in findings]}")
    print()


def demo_scan_snippets_and_report():
    """批量片段初筛 + 汇总报告（配合 Skill 工作流）"""
    print("=" * 50)
    print("示例 8：批量片段初筛 + 汇总报告")
    print("=" * 50)
    import json
    from sensitive_info_mcp.server import scan_snippets, build_report, Snippet, FindingInput

    # 模拟 codegraph / Glob 收集到的代码片段
    # 测试用凭据以拼接方式存储，避免被 GitHub secret scanning 误判为真实密钥
    _stripe = "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
    _slack = "xoxb-" + "1234567890-abcdefghijklmnop"
    snippets = [
        Snippet(id="src/config.py:5", content=f'API_KEY = "{_stripe}"'),
        Snippet(id="src/db.py:12", content='DB_PASSWORD = "my_secret_db_pass_123"'),
        Snippet(id=".env:1", content=f"SLACK_TOKEN={_slack}"),
        Snippet(id="src/utils.py:3", content="def helper(): return 'normal code'"),
    ]
    result = json.loads(scan_snippets(snippets))
    print(f"  初筛命中 {result['total_findings']} 处，未命中片段: {result['clean_ids']}")

    # 收集初筛命中的 rule findings
    findings = []
    for r in result["results"]:
        for f in r["findings"]:
            findings.append(FindingInput(**f))
    # 模拟 LLM 二次筛选：对未命中片段中的硬编码密码做语义判断
    findings.append(FindingInput(
        type="llm_detected",
        value="my_secret_db_pass_123",
        source="llm",
        risk_level="critical",
        confidence=0.85,
        location="src/db.py:12",
        suggestion="[hardcoded_credential] 变量名 DB_PASSWORD 暗示敏感，硬编码明文密码",
    ))

    report = build_report(findings, title="代码敏感信息扫描报告", include_masking=True)
    print(report)
    print()


if __name__ == "__main__":
    demo_basic_detection()
    demo_masking()
    demo_strategies()
    demo_report()
    demo_custom_rules()
    demo_clean_text()
    demo_chinese_compatibility()
    demo_scan_snippets_and_report()
    print("✅ 所有示例运行完成！")
