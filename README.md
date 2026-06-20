# 🔒 Sensitive Info MCP

> 规则驱动的敏感信息检测与数据脱敏 MCP 服务器 + LLM Skill 协同

一个 Model Context Protocol (MCP) 服务器，用于检测和脱敏文本/文件/代码中的敏感信息。支持 **14+ 类**敏感信息识别，结合**正则规则 + 校验算法**做基础检测，并提供掩码、替换、哈希等多种脱敏策略。LLM 语义检测通过 **Skill** 编排 AI 助手完成（MCP 不内置 LLM 调用）。

## ✨ 特性

- **全面检测**：手机号、身份证、银行卡、邮箱、API Key、JWT、私钥、AWS Key、GitHub Token 等 14+ 类
- **智能校验**：身份证校验位算法、银行卡 Luhn 校验，降低误报
- **MCP/Skill 分工**：基础检测在 MCP（快、确定性），LLM 语义检测在 Skill（识别变形/拆分/上下文隐私），职责清晰
- **灵活脱敏**：5 种策略（掩码/替换/哈希/保留格式/删除），支持按类型自定义
- **中文友好**：所有正则使用 lookaround 断言，完美兼容中文环境
- **多形态使用**：MCP Server（Claude/Cursor/CodeBuddy）、CLI 命令行、Python SDK、GitHub Action

## 📦 安装

```bash
pip install -e .
```

## 🚀 快速开始

### 1. CLI 命令行

```bash
# 检测敏感信息
sensitive-info-mcp "我的手机号是13812345678"

# 脱敏输出
sensitive-info-mcp "我的手机号是13812345678" --mask

# 生成 Markdown 报告
sensitive-info-mcp "身份证：110101199003071233" --report

# 扫描文件
sensitive-info-mcp --file ./config.yaml --mask
```

### 2. MCP Server（Claude Desktop / Cursor / CodeBuddy）

在客户端配置文件中添加：

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "sensitive-info": {
      "command": "sensitive-info-mcp",
      "args": []
    }
  }
}
```

**Cursor / CodeBuddy** (`.codebuddy/mcp.json` 或对应配置):
```json
{
  "mcpServers": {
    "sensitive-info": {
      "command": "python3",
      "args": ["-m", "sensitive_info_mcp.server"]
    }
  }
}
```

配置后，AI 助手即可调用以下工具：

| 工具 | 功能 |
|------|------|
| `scan_text` | 检测文本中的敏感信息（基础规则） |
| `mask_text` | 检测并脱敏文本 |
| `scan_report` | 生成单文本 Markdown 扫描报告 |
| `scan_file` | 扫描文件 |
| `mask_file` | 脱敏文件并保存 |
| `list_rules` | 列出所有检测规则 |
| `scan_snippets` | 批量对多个代码/配置片段做基础初筛（配合 Skill） |
| `build_report` | 汇总 rule + llm 来源检测结果生成统一报告（配合 Skill） |

### 3. Python SDK

```python
from sensitive_info_mcp.scanner import Scanner

scanner = Scanner()

# 检测
findings = scanner.detect("联系我：13812345678 或 test@qq.com")
for f in findings:
    print(f"[{f.type.value}] {f.value} → 风险:{f.risk_level.value}")

# 脱敏
masked, findings = scanner.mask("手机号13812345678")
print(masked)  # 手机号138****5678

# 完整报告
report = scanner.report("身份证：110101199003071233")
print(report.to_markdown())
```

## 🔧 配置

### 脱敏策略

| 策略 | 说明 | 示例 |
|------|------|------|
| `auto`（默认）| 使用各类型默认策略 | 手机号→掩码，API Key→替换 |
| `mask` | 部分掩码 | `138****5678` |
| `replace` | 完全替换 | `[REDACTED]` |
| `hash` | SHA256 哈希 | `hash:a1b2c3...` |
| `keep_format` | 保留格式 | `z******@example.com` |
| `redact` | 完全删除 | `[REDACTED]` |

```python
from sensitive_info_mcp.types import MaskConfig, MaskStrategy
from sensitive_info_mcp.scanner import Scanner

# 全局强制使用替换策略
scanner = Scanner(mask_config=MaskConfig(strategy=MaskStrategy.REPLACE))

# 按类型自定义
scanner = Scanner(mask_config=MaskConfig(
    type_overrides={
        "phone": {"strategy": "hash"},
        "email": {"strategy": "keep_format"},
    }
))
```

## 🤝 结合 Skill 做 LLM 语义检测

本 MCP 仅做基础检测（正则 + 校验算法），不内置 LLM 调用。LLM 语义检测（识别变形/拆分敏感信息、非标准命名的硬编码凭据、内网信息、上下文隐私等）通过 **Skill** 编排 AI 助手完成 —— 因为 AI 助手本身就在执行 LLM，无需 MCP 再调外部 API。

### 工作流

```
代码 / 配置片段
     │
     ├─ codegraph 取常量/变量定义 + Glob/Read 取配置文件
     ▼
┌───────────────────────┐
│ MCP scan_snippets       │ ── rule 初筛 ──┐
│ (正则 + 校验算法)       │                │
└───────────────────────┘                │
     │ 初筛未命中片段                      │
     ▼                                    │
┌───────────────────────┐                │
│ AI 助手 LLM 二次筛选    │ ── llm findings│
│ (Skill 识别规则)        │ ──────────────►│
└───────────────────────┘                │
     ▼                                    ▼
┌───────────────────────┐
│ MCP build_report        │ → 统一 Markdown 报告（区分 rule/llm 来源）
└───────────────────────┘
```

### 安装 Skill

将 `skills/sensitive-info-scan/SKILL.md` 复制到 CodeBuddy / Cursor 的 skills 目录：

```bash
# CodeBuddy
mkdir -p ~/.codebuddy/skills/sensitive-info-scan
cp skills/sensitive-info-scan/SKILL.md ~/.codebuddy/skills/sensitive-info-scan/SKILL.md

# 或 Cursor / Claude Code 对应 skills 目录
```

重启会话后，对用户说"扫描代码中的敏感信息"，AI 助手会自动按 Skill 工作流执行：codegraph 取片段 → MCP 初筛 → LLM 二筛 → build_report 生成报告。

> Skill 也可在无 codegraph 环境下工作（回退为 Grep 赋值行收集片段），详见 SKILL.md。

## 📋 支持的敏感信息类型

| 类型 | 标识 | 风险等级 | 校验 |
|------|------|---------|------|
| 手机号 | `phone` | 高 | - |
| 身份证号 | `id_card` | 严重 | ✅ 校验位 |
| 银行卡号 | `bank_card` | 严重 | ✅ Luhn |
| 邮箱 | `email` | 中 | - |
| API Key | `api_key` | 高 | - |
| AWS Key | `aws_key` | 严重 | - |
| GitHub Token | `github_token` | 严重 | - |
| JWT | `jwt` | 严重 | - |
| 私钥 | `private_key` | 严重 | - |
| 密码 | `password` | 高 | - |
| URL 凭据 | `url_with_cred` | 高 | - |
| IP 地址 | `ip_address` | 低 | - |
| 社会保障号 | `ssn` | 高 | - |
| LLM 检测 | `llm_detected` | 中-严重 | - (Skill 二次筛选产生) |

### 添加自定义规则

```python
from sensitive_info_mcp.detectors.rules import Rule, RuleDetector
from sensitive_info_mcp.types import SensitiveType, RiskLevel
import re

custom = Rule(
    type=SensitiveType.CUSTOM,
    pattern=re.compile(r"(?<!\d)EMP\d{6}(?!\d)"),  # 员工号 EMP123456
    risk_level=RiskLevel.MEDIUM,
    confidence=0.9,
    description="内部员工编号",
)

scanner = Scanner(extra_rules=[custom])
```

## 🏗️ 架构

```
输入文本 / 文件 / 代码片段
   │
   ▼
┌───────────────────┐
│  规则检测器         │  正则 + 校验算法（身份证校验位 / 银行卡 Luhn）
│  (RuleDetector)    │  → 14+ 类已知格式敏感信息
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  脱敏处理器         │  掩码 / 替换 / 哈希 / 保留格式 / 删除
│  (Masker)          │
└────────┬──────────┘
         ▼
   脱敏文本 + 检测报告

┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
LLM 语义检测（在 Skill 层，不在 MCP 内）：
  codegraph 取片段 → scan_snippets 初筛 → AI 助手 LLM 二筛 → build_report
```

## 📁 项目结构

```
sensitive-info-mcp/
├── src/sensitive_info_mcp/
│   ├── server.py          # MCP Server + CLI 入口（8 个工具）
│   ├── scanner.py         # 扫描器（基础规则检测 + 脱敏）
│   ├── types.py           # 类型定义
│   ├── detectors/
│   │   ├── base.py        # 检测器基类
│   │   └── rules.py       # 规则检测引擎（14+ 类）
│   └── maskers/
│       └── processor.py   # 脱敏处理器
├── skills/
│   └── sensitive-info-scan/
│       └── SKILL.md       # LLM 语义检测 Skill（codegraph + MCP + AI 助手协同）
├── action.yml             # GitHub Action
├── examples/              # 使用示例
├── tests/                 # 测试用例
└── pyproject.toml
```

## 🧪 测试

```bash
python tests/test_core.py
```

## 📄 License

MIT
