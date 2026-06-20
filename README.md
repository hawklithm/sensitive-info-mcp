# 🔒 Sensitive Info MCP

> AI 驱动的敏感信息检测与数据脱敏 MCP 工具

一个 Model Context Protocol (MCP) 服务器，用于检测和脱敏文本/文件中的敏感信息。支持 **14+ 类**敏感信息识别，结合**正则规则 + 校验算法 + AI 语义理解**三重检测，提供掩码、替换、哈希等多种脱敏策略。

## ✨ 特性

- **全面检测**：手机号、身份证、银行卡、邮箱、API Key、JWT、私钥、AWS Key、GitHub Token 等 14+ 类
- **智能校验**：身份证校验位算法、银行卡 Luhn 校验，降低误报
- **AI 增强**：可选的 LLM 语义检测，识别变形/拆分的敏感信息和上下文隐私
- **灵活脱敏**：5 种策略（掩码/替换/哈希/保留格式/删除），支持按类型自定义
- **中文友好**：所有正则使用 lookaround 断言，完美兼容中文环境
- **多形态使用**：MCP Server（Claude/Cursor/CodeBuddy）、CLI 命令行、Python SDK

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

# 查看所有规则
python -m sensitive_info_mcp.server --help
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
| `scan_text` | 检测文本中的敏感信息 |
| `mask_text` | 检测并脱敏文本 |
| `scan_report` | 生成 Markdown 扫描报告 |
| `scan_file` | 扫描文件 |
| `mask_file` | 脱敏文件并保存 |
| `list_rules` | 列出所有检测规则 |

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

### AI 检测（可选）

设置环境变量启用 AI 语义检测，可识别姓名、地址、变形信息等：

```bash
export OPENAI_API_KEY="sk-xxx"
export OPENAI_BASE_URL="https://api.openai.com/v1"  # 可选，兼容第三方 API
export SI_MCP_MODEL="gpt-4o-mini"                   # 可选
```

```python
from sensitive_info_mcp.detectors import AIConfig
from sensitive_info_mcp.scanner import Scanner

scanner = Scanner(enable_ai=True, ai_config=AIConfig(
    api_key="sk-xxx",
    model="gpt-4o-mini",
))
findings = scanner.detect("我叫张三，住在北京海淀区xx路", use_ai=True)
```

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
| AI 检测 | `ai_detected` | 中-高 | - |

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
输入文本
   │
   ▼
┌──────────────┐     ┌──────────────┐
│  规则检测器   │     │  AI 检测器    │ (可选)
│  正则 + 校验  │     │  LLM 语义理解 │
└──────┬───────┘     └──────┬───────┘
       │                     │
       └─────────┬───────────┘
                 ▼
         ┌──────────────┐
         │  脱敏处理器   │
         │  掩码/替换/哈希│
         └──────┬───────┘
                ▼
      脱敏文本 + 检测报告
```

## 📁 项目结构

```
sensitive-info-mcp/
├── src/sensitive_info_mcp/
│   ├── server.py          # MCP Server + CLI 入口
│   ├── scanner.py         # 扫描器（整合检测+脱敏）
│   ├── types.py           # 类型定义
│   ├── detectors/
│   │   ├── base.py        # 检测器基类
│   │   ├── rules.py       # 规则检测引擎
│   │   └── ai.py          # AI 语义检测
│   └── maskers/
│       └── processor.py   # 脱敏处理器
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
