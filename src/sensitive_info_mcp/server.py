"""MCP Server 主入口 - 敏感信息检测与脱敏工具

可作为 MCP Server 被 Claude Desktop / Cursor / CodeBuddy 调用，
也可作为 CLI 工具直接使用。

职责定位：仅基础检测（正则规则 + 校验算法）+ 脱敏 + 报告。
LLM 语义检测由外部 Skill（skills/sensitive-info-scan）编排 AI 助手完成。
"""
from __future__ import annotations

import json
import sys
from typing import Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from .scanner import Scanner, get_scanner
from .types import (
    DetectionResult,
    MaskConfig,
    MaskStrategy,
    RiskLevel,
    ScanReport,
    SensitiveType,
)


# --------------------------------------------------------------------------- #
#  MCP Server 定义
# --------------------------------------------------------------------------- #
mcp = FastMCP(
    "sensitive-info-mcp",
    instructions=(
        "敏感信息检测与数据脱敏工具（基础规则检测）。支持手机号、身份证、银行卡、邮箱、"
        "API Key、JWT、私钥等 14+ 类敏感信息的正则 + 校验算法检测，并提供掩码/替换/哈希等脱敏策略。"
        "本 MCP 仅做基础检测；LLM 语义检测由外部 Skill 完成。"
        "可用工具：scan_text 检测、mask_text 脱敏、scan_report 单文本报告、"
        "scan_file 扫描文件、mask_file 脱敏文件、list_rules 规则列表、"
        "scan_snippets 批量片段初筛、build_report 汇总 rule+llm 生成报告。"
    ),
)


def _get_scanner(mask_strategy: Optional[str] = None) -> Scanner:
    """根据脱敏策略构建扫描器"""
    if mask_strategy is None:
        return get_scanner()

    cfg = MaskConfig()
    try:
        cfg.strategy = MaskStrategy(mask_strategy)
    except ValueError:
        pass
    return Scanner(mask_config=cfg)


# --------------------------------------------------------------------------- #
#  工具入参模型（pydantic）
# --------------------------------------------------------------------------- #
class Snippet(BaseModel):
    """待初筛的代码/配置片段"""

    id: str = Field(description="片段唯一标识，用于结果回溯，如 'src/config.py:12-30' 或 'const-7'")
    content: str = Field(description="代码/配置片段原文")
    location: str = Field(default="", description="可选位置描述，如 文件路径:行号")


class FindingInput(BaseModel):
    """外部传入的单条检测结果（含 rule 与 llm 来源）"""

    type: str = Field(
        description="敏感类型值，如 phone/api_key/llm_detected/custom 等（对应 SensitiveType 枚举值）"
    )
    value: str = Field(description="检测到的敏感信息原文")
    source: str = Field(default="rule", description="来源: rule | llm")
    risk_level: str = Field(default="medium", description="low|medium|high|critical")
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    location: str = Field(default="", description="文件路径:行号 或片段 id")
    suggestion: str = Field(default="", description="处置建议 / LLM 判断理由")
    start: int = Field(default=0)
    end: int = Field(default=0)


# --------------------------------------------------------------------------- #
#  MCP 工具
# --------------------------------------------------------------------------- #
@mcp.tool()
def scan_text(text: str, mask_strategy: Optional[str] = None) -> str:
    """检测文本中的敏感信息（基础规则检测，不含 LLM 语义检测）

    Args:
        text: 待检测文本
        mask_strategy: 脱敏策略，可选 mask|replace|hash|keep_format|redact（仅影响返回的 masked_value）

    Returns:
        JSON 格式的检测结果列表
    """
    scanner = _get_scanner(mask_strategy=mask_strategy)
    findings = scanner.detect(text)
    return json.dumps(
        [f.model_dump(mode="json") for f in findings],
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
def mask_text(text: str, mask_strategy: Optional[str] = None) -> str:
    """检测并脱敏文本，返回脱敏后的文本

    Args:
        text: 待脱敏文本
        mask_strategy: 脱敏策略 mask|replace|hash|keep_format|redact

    Returns:
        脱敏后的文本
    """
    scanner = _get_scanner(mask_strategy=mask_strategy)
    masked, _ = scanner.mask(text)
    return masked


@mcp.tool()
def scan_report(text: str, mask_strategy: Optional[str] = None) -> str:
    """生成完整的 Markdown 扫描报告

    Args:
        text: 待扫描文本
        mask_strategy: 脱敏策略

    Returns:
        Markdown 格式的扫描报告
    """
    scanner = _get_scanner(mask_strategy=mask_strategy)
    report = scanner.report(text)
    return report.to_markdown()


@mcp.tool()
def scan_file(file_path: str, mask_strategy: Optional[str] = None) -> str:
    """扫描文件中的敏感信息

    Args:
        file_path: 文件路径
        mask_strategy: 脱敏策略

    Returns:
        JSON 格式的检测结果
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return json.dumps({"error": f"读取文件失败: {e}"}, ensure_ascii=False)
    scanner = _get_scanner(mask_strategy=mask_strategy)
    findings = scanner.detect(content)
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
    inplace: bool = False,
) -> str:
    """脱敏文件内容并保存

    Args:
        file_path: 输入文件路径
        output_path: 输出文件路径（与 inplace 互斥）
        mask_strategy: 脱敏策略
        inplace: 是否原地覆盖（慎用）

    Returns:
        操作结果 JSON
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return json.dumps({"error": f"读取文件失败: {e}"}, ensure_ascii=False)

    scanner = _get_scanner(mask_strategy=mask_strategy)
    masked, findings = scanner.mask(content)

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


@mcp.tool()
def scan_snippets(snippets: list[Snippet]) -> str:
    """批量对多个代码/配置片段做基础规则初筛

    专为配合 codegraph 取出的多个常量/变量/配置片段设计，一次性完成正则 + 校验算法初筛。
    仅做基础检测（rule），不做 LLM 语义判断。LLM 二次筛选由调用方（Skill / AI 助手）完成。

    Args:
        snippets: 片段列表，每个含 id / content / 可选 location

    Returns:
        JSON: {"total_findings": N,
               "results": [{"id","location","findings_count","findings":[DetectionResult...]}],
               "clean_ids": ["初筛未命中的片段 id..."]}
    """
    scanner = get_scanner()
    results = []
    clean_ids = []
    total = 0
    for snip in snippets:
        findings = scanner.detect(snip.content)
        for f in findings:
            if not f.location:
                f.location = snip.location or snip.id
        if findings:
            total += len(findings)
            results.append(
                {
                    "id": snip.id,
                    "location": snip.location,
                    "findings_count": len(findings),
                    "findings": [f.model_dump(mode="json") for f in findings],
                }
            )
        else:
            clean_ids.append(snip.id)
    return json.dumps(
        {"total_findings": total, "results": results, "clean_ids": clean_ids},
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
def build_report(
    findings: list[FindingInput],
    title: str = "敏感信息扫描报告",
    include_masking: bool = True,
    mask_strategy: Optional[str] = None,
) -> str:
    """汇总 rule + llm 来源的检测结果，生成统一 Markdown 报告

    接受外部 findings（含 source='llm' 的 LLM 二次筛选结果与 source='rule' 的初筛结果），
    按类型与来源统计生成报告。可选为每条 finding 计算脱敏建议值。
    典型用法：Skill 把 scan_snippets 初筛结果与 LLM 二筛结果合并后传入本工具生成最终报告。

    Args:
        findings: 外部检测结果列表（rule 与 llm 来源混合）
        title: 报告标题
        include_masking: 是否为每条 finding 计算并展示脱敏建议值
        mask_strategy: 脱敏策略（计算建议值时使用）

    Returns:
        Markdown 报告字符串
    """
    scanner = _get_scanner(mask_strategy=mask_strategy)
    risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    max_risk = 0
    enriched: list[DetectionResult] = []
    summary: dict[str, int] = {}
    src_summary: dict[str, int] = {}

    for fi in findings:
        # 类型映射：未知值按 source 兜底
        try:
            stype = SensitiveType(fi.type)
        except ValueError:
            stype = SensitiveType.LLM_DETECTED if fi.source == "llm" else SensitiveType.CUSTOM
        try:
            rl = RiskLevel(fi.risk_level)
        except ValueError:
            rl = RiskLevel.MEDIUM

        masked_value = scanner.masker.mask_value(stype, fi.value) if include_masking else ""
        enriched.append(
            DetectionResult(
                type=stype,
                value=fi.value,
                masked_value=masked_value,
                start=fi.start,
                end=fi.end,
                confidence=fi.confidence,
                source=fi.source,
                risk_level=rl,
                suggestion=fi.suggestion,
                location=fi.location,
            )
        )
        summary[stype.value] = summary.get(stype.value, 0) + 1
        src_summary[fi.source] = src_summary.get(fi.source, 0) + 1
        if risk_order.get(rl.value, 1) > max_risk:
            max_risk = risk_order[rl.value]

    report = ScanReport(
        total_findings=len(enriched),
        risk_level=RiskLevel(
            next((k for k, v in risk_order.items() if v == max_risk), "low")
        ),
        findings=enriched,
        summary=summary,
        source_summary=src_summary,
    )
    md = report.to_markdown()
    if title and title != "敏感信息扫描报告":
        md = md.replace("# 敏感信息扫描报告", f"# {title}", 1)
    return md


# --------------------------------------------------------------------------- #
#  CLI 入口
# --------------------------------------------------------------------------- #
def _cli() -> None:
    """命令行模式：python -m sensitive_info_mcp.server "文本" [--mask] [--report]"""
    import argparse

    parser = argparse.ArgumentParser(
        prog="sensitive-info-mcp",
        description="敏感信息检测与脱敏工具（基础规则检测）",
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
    args = parser.parse_args()

    scanner = _get_scanner(mask_strategy=args.strategy)

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
        print(scanner.report(source).to_markdown())
    elif args.mask:
        masked, findings = scanner.mask(source)
        print(f"# 脱敏结果（{label}，发现 {len(findings)} 处）\n")
        print(masked)
    else:
        findings = scanner.detect(source)
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
