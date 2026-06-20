"""MCP Server 主入口 - 敏感信息检测与脱敏工具

可作为 MCP Server 被 Claude Desktop / Cursor / CodeBuddy 调用，
也可作为 CLI 工具直接使用。
"""
from __future__ import annotations

import json
import os
import sys
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .detectors import AIConfig
from .scanner import Scanner, get_scanner
from .types import MaskConfig, MaskStrategy


# --------------------------------------------------------------------------- #
#  MCP Server 定义
# --------------------------------------------------------------------------- #
mcp = FastMCP(
    "sensitive-info-mcp",
    instructions=(
        "敏感信息检测与数据脱敏工具。支持检测手机号、身份证、银行卡、邮箱、"
        "API Key、JWT、私钥等 14+ 类敏感信息，并提供掩码/替换/哈希等多种脱敏策略。"
        "可用工具：scan_text 检测、mask_text 脱敏、scan_report 生成报告、"
        "scan_file 扫描文件、list_rules 查看规则。"
    ),
)


def _get_scanner(
    mask_strategy: Optional[str] = None, enable_ai: bool = False
) -> Scanner:
    """根据参数构建扫描器"""
    if mask_strategy is None and not enable_ai:
        return get_scanner()

    cfg = MaskConfig()
    if mask_strategy:
        try:
            cfg.strategy = MaskStrategy(mask_strategy)
        except ValueError:
            pass

    ai_cfg = None
    if enable_ai:
        ai_cfg = AIConfig(
            api_key=os.environ.get("OPENAI_API_KEY"),
            base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            model=os.environ.get("SI_MCP_MODEL", "gpt-4o-mini"),
            enabled=True,
        )
    return Scanner(mask_config=cfg, ai_config=ai_cfg, enable_ai=enable_ai)


@mcp.tool()
def scan_text(
    text: str,
    enable_ai: bool = False,
    mask_strategy: Optional[str] = None,
) -> str:
    """检测文本中的敏感信息

    Args:
        text: 待检测文本
        enable_ai: 是否启用 AI 语义检测（需配置 OPENAI_API_KEY 环境变量）
        mask_strategy: 脱敏策略，可选 mask|replace|hash|keep_format|redact

    Returns:
        JSON 格式的检测结果列表
    """
    scanner = _get_scanner(mask_strategy=mask_strategy, enable_ai=enable_ai)
    findings = scanner.detect(text, use_ai=enable_ai)
    return json.dumps(
        [f.model_dump(mode="json") for f in findings],
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
def mask_text(
    text: str,
    mask_strategy: Optional[str] = None,
    enable_ai: bool = False,
) -> str:
    """检测并脱敏文本，返回脱敏后的文本

    Args:
        text: 待脱敏文本
        mask_strategy: 脱敏策略 mask|replace|hash|keep_format|redact
        enable_ai: 是否启用 AI 语义检测

    Returns:
        脱敏后的文本
    """
    scanner = _get_scanner(mask_strategy=mask_strategy, enable_ai=enable_ai)
    masked, _ = scanner.mask(text, use_ai=enable_ai)
    return masked


@mcp.tool()
def scan_report(
    text: str,
    enable_ai: bool = False,
    mask_strategy: Optional[str] = None,
) -> str:
    """生成完整的 Markdown 扫描报告

    Args:
        text: 待扫描文本
        enable_ai: 是否启用 AI 检测
        mask_strategy: 脱敏策略

    Returns:
        Markdown 格式的扫描报告
    """
    scanner = _get_scanner(mask_strategy=mask_strategy, enable_ai=enable_ai)
    report = scanner.report(text, use_ai=enable_ai)
    return report.to_markdown()


@mcp.tool()
def scan_file(
    file_path: str,
    enable_ai: bool = False,
    mask_strategy: Optional[str] = None,
) -> str:
    """扫描文件中的敏感信息

    Args:
        file_path: 文件路径
        enable_ai: 是否启用 AI 检测
        mask_strategy: 脱敏策略

    Returns:
        JSON 格式的检测结果
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return json.dumps({"error": f"读取文件失败: {e}"}, ensure_ascii=False)
    scanner = _get_scanner(mask_strategy=mask_strategy, enable_ai=enable_ai)
    findings = scanner.detect(content, use_ai=enable_ai)
    return json.dumps(
        {
            "file": file_path,
            "findings_count": len(findings),
            "findings": [f.model_dump(mode="json") for f in findings],
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
def mask_file(
    file_path: str,
    output_path: Optional[str] = None,
    mask_strategy: Optional[str] = None,
    enable_ai: bool = False,
    inplace: bool = False,
) -> str:
    """脱敏文件内容并保存

    Args:
        file_path: 输入文件路径
        output_path: 输出文件路径（与 inplace 互斥）
        mask_strategy: 脱敏策略
        enable_ai: 是否启用 AI 检测
        inplace: 是否原地覆盖（慎用）

    Returns:
        操作结果 JSON
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return json.dumps({"error": f"读取文件失败: {e}"}, ensure_ascii=False)

    scanner = _get_scanner(mask_strategy=mask_strategy, enable_ai=enable_ai)
    masked, findings = scanner.mask(content, use_ai=enable_ai)

    target = file_path if inplace else (output_path or file_path + ".masked")
    try:
        with open(target, "w", encoding="utf-8") as f:
            f.write(masked)
    except OSError as e:
        return json.dumps({"error": f"写入文件失败: {e}"}, ensure_ascii=False)

    return json.dumps(
        {
            "input": file_path,
            "output": target,
            "findings_count": len(findings),
            "original_length": len(content),
            "masked_length": len(masked),
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
def list_rules() -> str:
    """列出当前所有内置检测规则

    Returns:
        JSON 格式的规则列表
    """
    scanner = get_scanner()
    rules_info = []
    for r in scanner.rule_detector.rules:
        rules_info.append(
            {
                "type": r.type.value,
                "risk_level": r.risk_level.value,
                "confidence": r.confidence,
                "description": r.description,
                "has_validator": r.validator is not None,
                "pattern": r.pattern.pattern[:80] + ("..." if len(r.pattern.pattern) > 80 else ""),
            }
        )
    return json.dumps(rules_info, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------- #
#  CLI 入口
# --------------------------------------------------------------------------- #
def _cli() -> None:
    """命令行模式：python -m sensitive_info_mcp.server "文本" [--mask] [--report]"""
    import argparse

    parser = argparse.ArgumentParser(
        prog="sensitive-info-mcp",
        description="敏感信息检测与脱敏工具",
    )
    parser.add_argument("text", nargs="?", help="待检测文本（不提供则进入 MCP 模式）")
    parser.add_argument("--mask", action="store_true", help="输出脱敏后的文本")
    parser.add_argument("--report", action="store_true", help="输出 Markdown 报告")
    parser.add_argument("--file", help="扫描文件而非文本")
    parser.add_argument(
        "--strategy",
        choices=[s.value for s in MaskStrategy],
        help="脱敏策略",
    )
    parser.add_argument("--ai", action="store_true", help="启用 AI 检测")
    args = parser.parse_args()

    scanner = _get_scanner(mask_strategy=args.strategy, enable_ai=args.ai)

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        source = content
        label = args.file
    else:
        source = args.text or ""
        label = "<stdin>"

    if not source:
        parser.print_help()
        sys.exit(0)

    if args.report:
        print(scanner.report(source, use_ai=args.ai).to_markdown())
    elif args.mask:
        masked, findings = scanner.mask(source, use_ai=args.ai)
        print(f"# 脱敏结果（{label}，发现 {len(findings)} 处）\n")
        print(masked)
    else:
        findings = scanner.detect(source, use_ai=args.ai)
        print(f"# 检测结果（{label}，发现 {len(findings)} 处）\n")
        for i, f in enumerate(findings, 1):
            print(
                f"{i}. [{f.type.value}] {f.value} → (风险:{f.risk_level.value}, "
                f"置信度:{f.confidence:.0%}, 来源:{f.source})"
            )
            if f.suggestion:
                print(f"   {f.suggestion}")


def main() -> None:
    """主入口：有参数走 CLI，无参数走 MCP Server"""
    if len(sys.argv) > 1 and sys.argv[1] not in ("--help", "-h"):
        _cli()
    else:
        mcp.run()


if __name__ == "__main__":
    main()
