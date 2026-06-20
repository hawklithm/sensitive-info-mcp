# Sensitive Info Scan

## 何时使用

当用户请求以下任何一类任务时，主动使用本 Skill：

- "检查 / 扫描代码中（或仓库中）的敏感信息 / 敏感数据"
- "扫描硬编码密钥 / 凭据 / 密码 / Token / 私钥"
- "安全审计：是否有代码泄露 / 凭据泄露"
- "检查配置文件是否包含敏感信息"
- "检查提交前是否会把密钥推上去"

本 Skill 通过 **codegraph 代码图谱 + sensitive-info-mcp 基础检测 + 你（AI 助手）自身的 LLM 语义判断** 三者协同，产出一份区分「规则命中」与「LLM 命中」来源的详细扫描报告。

## 前置条件

- **sensitive-info-mcp**（MCP 工具）：提供 `scan_snippets`（基础初筛）、`build_report`（汇总报告）。若未配置，回退见文末。
- **codegraph**（MCP 工具，可选但推荐）：用于结构化获取代码中的常量 / 变量定义。项目未索引时按文末回退方案执行。
- 你（AI 助手）本身就是 LLM —— LLM 二次筛选由你直接完成，无需调用外部 LLM API。

## 核心思路

MCP 只做**基础检测**（正则 + 校验算法，覆盖手机号 / 身份证 / 银行卡 / 邮箱 / API Key / JWT / 私钥 / AWS Key / GitHub Token 等已知格式），速度快但无法识别语义层面的敏感信息（如非标准命名的硬编码密码、变形密钥、内网信息）。因此：

1. 先用 codegraph + Glob/Read **收集候选片段**（代码中的常量/变量定义、配置文件内容）。
2. 调 MCP `scan_snippets` 对所有片段做**基础初筛**（rule）。
3. 对初筛**未命中**的片段，你按本 Skill 的【LLM 敏感识别规则】做**语义二次筛选**（llm）。
4. 合并 rule + llm 结果，调 MCP `build_report` 生成统一报告。

---

## 工作流（按顺序执行）

### 第 1 步：用 codegraph 收集代码中的常量 / 变量定义

目标：把代码里"可能藏敏感信息"的常量、变量、字段定义都捞出来。

- **按敏感命名词检索变量定义**：对下列关键词，逐个调用 `codegraph_search(kind="variable", query="<关键词>")`。
  关键词清单（每个独立调用，合并去重结果）：
  `key, secret, token, password, passwd, pwd, cred, credential, config, setting, const, api, access, private, auth, cert, salt, signing, encryption, db, database, conn, connection, merchant, license`

  > 注意：codegraph 的 `codegraph_search` 的 `kind` 参数枚举为 `['function','method','class','interface','type','variable','route','component']`，**含 `variable` 但不含 `constant`/`field`/`property`** —— 大多数语言的常量/字段会被归入 `variable`，因此 `kind="variable"` 已能覆盖。`query` 是必填的符号名（支持部分匹配）。

- **探索配置/常量模块**：调用 `codegraph_explore(query="config constants settings env keys secrets credentials" )`，一次性返回相关模块的源码（Read 等价，无需再 Read）。
- **读取命中的定义文件**：对上一步定位到的关键文件，用 `codegraph_node(file="<路径>")` 读取完整源码（替代 Read 工具）。
- **收集片段**：把每个返回的符号 / 文件片段标记为待扫描片段，记录：
  - `id`：唯一标识，如 `"src/config.py:12-30"` 或 `"const-7"`
  - `content`：源码原文
  - `location`：文件路径:行号

### 第 2 步：用 Glob + Read 收集配置文件（codegraph 不索引配置文件）

codegraph 只索引源代码，**不索引** `.env` / `.yml` / `.json` / `.toml` 等配置文件。这类文件必须用 Glob + Read 收集。

- 用 Glob 找出配置文件（排除依赖与构建产物目录）：
  - `**/.env`、`**/.env.*`
  - `**/*.yml`、`**/*.yaml`、`**/*.json`（排除 `package-lock.json` / `pnpm-lock.yaml` 等 lock 文件）
  - `**/*.properties`、`**/*.toml`、`**/*.ini`、`**/*.conf`、`**/*.cfg`
  - 排除：`**/node_modules/**`、`**/.git/**`、`**/dist/**`、`**/build/**`、`**/venv/**`、`**/.venv/**`
- 用 Read 读取每个配置文件。整文件作为一个片段，`id` = 文件路径。
- 对较大的配置文件，可按 `KEY=VALUE` 行切分为多个片段，`id` = `文件路径:行号`。

### 第 3 步：调 MCP `scan_snippets` 做基础初筛

- 把第 1、2 步收集到的所有片段组装为参数，**一次性**调用 sensitive-info-mcp 的 `scan_snippets` 工具：
  ```
  scan_snippets(snippets=[
    {"id": "src/config.py:12-30", "content": "...", "location": "src/config.py:12-30"},
    {"id": ".env", "content": "...", "location": ".env"},
    ...
  ])
  ```
- 返回结果含三部分：
  - `total_findings`：初筛命中总数
  - `results`：命中片段列表，每个含 `id` / `location` / `findings_count` / `findings`（DetectionResult 数组，`source="rule"`）
  - `clean_ids`：**初筛未命中**的片段 id 列表 —— 这些进入第 4 步 LLM 二次筛选
- 记录所有 `results` 中的 rule findings（含 `location`，已自动回填）。

### 第 4 步：对初筛未命中片段做 LLM 二次筛选（你直接执行）

- 取 `clean_ids` 对应的片段内容（第 1、2 步已收集）。
- 对每个片段，按下方【LLM 敏感识别规则】进行语义判断，找出基础规则漏掉的敏感信息。
- 把命中的 LLM finding 结构化为：
  ```
  {
    "type": "llm_detected",
    "value": "敏感信息原文（长密钥取前后各 16 字符，中间用 ... 省略）",
    "source": "llm",
    "risk_level": "low|medium|high|critical",
    "confidence": 0.0-1.0,
    "location": "<片段 id>",
    "suggestion": "[<类别>] <一句话理由>"
  }
  ```
- **去重**：若同一 `location` + 相同 `value` 已被 rule 命中，跳过（rule 置信度更高）。

### 第 5 步：合并结果并调 MCP `build_report` 生成报告

- 合并 rule findings（第 3 步，`source="rule"`）+ llm findings（第 4 步，`source="llm"`）。
- 统一转为 `build_report` 的入参 `findings` 列表（每条含 `type`/`value`/`source`/`risk_level`/`confidence`/`location`/`suggestion`）。
- 调用：
  ```
  build_report(
    findings=[...],
    title="代码敏感信息扫描报告",
    include_masking=True
  )
  ```
- 报告会自动按类型与来源（rule/llm）统计，并为每条 finding 计算脱敏建议值。
- 把返回的 Markdown 报告呈现给用户。
- **额外处置建议**：对 `critical` / `high` 级别项，追加修复建议：
  - 改用环境变量 / 配置中心 / 密钥管理服务（KMS / Vault）读取
  - 已泄露的密钥立即轮换（吊销并重新签发）
  - 从 git 历史中清除（`git filter-repo` / BFG），并强制推送

---

## LLM 敏感识别规则（第 4 步遵循）

你是敏感信息安全审计专家。下面是一段已通过基础正则 + 校验初筛且**未命中**的代码 / 配置片段。请用语义判断其中是否仍存在敏感信息，覆盖以下 6 类：

### 1. 硬编码凭据 (hardcoded_credential)
- 赋值给变量的密钥 / 密码 / Token，且变量名暗示敏感但不在正则命名覆盖内（如 `db_password` / `SECRET_KEY` / `client_secret` / `admin_pwd` / `merchant_key` / `app_secret`）。
- base64 / hex / 高熵随机串赋值给敏感命名变量。
- 非标准格式的连接串凭据（如 `"host:port:user:pass"` 拼接、字典里的 `password` 字段、URL 中的非标准凭据）。

### 2. 内网信息 (internal_info)
- 内网 IP 段作为配置（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）且非注释示例。
- 内网域名 / 主机名（`*.local`、`*.internal`、`*.corp`、`internal-api`、`dev-db` 等）。
- 内部系统代号、服务器名、内网网段注释（非占位符）。

### 3. 业务密钥 (business_secret)
- 许可证密钥（`license` / `license_key`）。
- 加密密钥（AES / DES / RSA 密钥片段、HMAC secret、`signing_key`、`encrypt_key`）。
- 非标准格式的第三方服务密钥（`sk_live_` / `pk_live_` 变体、商户号 + 密钥对、非标准前缀的 API secret）。

### 4. 变形 / 拆分的敏感信息 (disguised_pii)
- 中文数字替代（"一三八0000一二三四" 表示手机号）。
- 字符串拼接构造的密钥（`"sk_" + "live_" + "abc123"`）。
- 字符数组 / 字节序列表示的密钥（`[0x41, 0x42, ...]`）。
- 注释中泄露的真实凭据（非通用说明）。

### 5. 上下文隐私 (contextual_pii)
- 真实人名（中文姓名、英文姓名）出现在非测试代码或配置中。
- 详细地址、出生日期、身份证片段、银行卡片段。
- 员工工号、内部账号、内部邮箱（非 `@example.com` 占位）。

### 6. 加密材料碎片 (encryption_key)
- PEM 私钥片段（非完整 `BEGIN/END` 块，正则可能漏掉）。
- 裸 base64 编码的证书 / 私钥内容。

### 判断准则

- 只报告有合理把握的敏感信息（`confidence >= 0.6`）。
- **排除明显测试 / 示例 / 占位值**：值含 `test` / `example` / `fake` / `dummy` / `sample` / `placeholder` / `your_xxx` / `xxx_yyy` / `CHANGE_ME` / `TODO` / `foobar` 等。
- **排除从环境变量 / 配置中心读取的值**：`os.environ` / `os.getenv` / `process.env` / `config.get` / `Config.from_env` —— 这是正确做法，非泄露。只报告**硬编码的字面量赋值**。
- 排除纯文档 / 注释中的通用说明（非真实凭据）。
- `risk_level` 建议：硬编码凭据 / 加密材料碎片 = `critical`；业务密钥 / 变形敏感信息 = `high`；内网信息 = `medium`；上下文隐私 = `medium`。

### 输出格式

对每个片段，输出严格 JSON 数组（无额外解释），每个元素：
```json
{
  "type": "llm_detected",
  "value": "敏感信息原文",
  "category": "hardcoded_credential|internal_info|business_secret|disguised_pii|contextual_pii|encryption_key",
  "reason": "一句话判断理由",
  "confidence": 0.0-1.0,
  "risk_level": "low|medium|high|critical"
}
```
未发现则该片段返回 `[]`。

拿到 JSON 后，补 `source: "llm"` 与 `location: <片段 id>`，`suggestion` 写 `"[<category>] <reason>"`，转为 `build_report` 的 FindingInput。

---

## 无 codegraph 回退方案

若项目未安装 / 未索引 codegraph（`codegraph_*` 工具不可用或返回"未索引"）：

- **代码片段收集**：用 Glob 找出源码文件（`**/*.py`、`**/*.js`、`**/*.ts`、`**/*.java`、`**/*.go` 等），用 Grep 搜索含敏感命名的赋值行：
  - 模式：`(api[_-]?key|secret|token|password|passwd|pwd|credential|access[_-]?key|private[_-]?key|signing|salt)\s*[:=]`
  - 命中行及其上下文（前后各 2 行）作为一个片段，`id` = `文件路径:行号`。
- **配置文件收集**：同第 2 步（Glob + Read）。
- 后续第 3-5 步不变（scan_snippets 初筛 → LLM 二筛 → build_report）。

> 这样保证本 Skill 在无 codegraph 环境下仍可完整执行，只是代码片段收集从"图谱查询"退化为"Grep 赋值行"。

---

## 输出要求

- 最终向用户呈现 `build_report` 返回的 Markdown 报告。
- 报告须能区分 `rule`（基础规则命中）与 `llm`（LLM 语义命中）两类来源。
- 对 `critical` / `high` 项附修复建议（见第 5 步）。
- 若未发现任何敏感信息，明确告知用户"扫描完成，未发现敏感信息"，并说明扫描范围（文件数 / 片段数）。
