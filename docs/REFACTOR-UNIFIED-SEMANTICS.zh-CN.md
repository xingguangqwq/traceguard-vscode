# TraceGuard 统一语义层重构方案

> 目标：根治"发现一个缺陷就打一条正则/加一个特判"的屎山式修法，把 source / sink / sanitizer / propagator 收敛到**单一事实源**，让新增能力 = 加一条声明，而不是改五处代码。
>
> 本文档基于对现有代码的实测与通读，不依赖 README/CHANGELOG 的自我描述。

---

## 0. 为什么会有屎山（根因诊断）

我通读了 `src/security/semantic-models.js`、`src/frontends/pattern-parser.js`、`src/rules/definitions.js`、`src/frontends/tree-sitter-frontend.js`、`src/dataflow/*`。**同一个安全概念被定义了至少三遍，且互不同步**：

| 概念 | 定义点 1 | 定义点 2 | 定义点 3 | 后果 |
|---|---|---|---|---|
| "什么是 SQL sink" | `semantic-models.js` 的 `sinkModel`（结构化、带 receiver/参数位） | `pattern-parser.js` 各语言正则 `["sink","SQL...",/\.query.../,"database"]` | `definitions.js` 的 `SinkKind.SQL_QUERY` | 加一个 `db.executeV2` 要改 models + 7 语言正则 + 确认 kind 映射，漏一处就半失效 |
| "什么是 sanitizer" | `semantic-models.js` 的 GUARD 角色 | `pattern-parser.js` 里 7 套语言专属 sanitizer 正则（互相不一致） | `definitions.js` 的 `GuardCapability.*` 大杂烩 | **实测 `Number()`/`parseInt`/`intval` 全部不识别为净化 → 误报**。因为没有任何一处把它们建成模型 |
| "什么是 source" | `framework-entries.js` + models | `pattern-parser.js` 各语言 source 正则 | `EXTERNAL_SOURCES` 集合 | 我扫 open-webui 时 `os.getenv()` 被当 HTTP 级 source，优先级失真 |
| "污点怎么传播" | `path-engine.js` + `propagation.js`（结构化） | `tree-sitter-frontend.js` 里硬编码 `safeCollectionJoinGuard`、Java 集合特判 | `pattern-parser.js` 的 `traceIdentifier` 正则追变量 | **Python f-string 漏报**：f-string 不在任何一套传播模型里 |
| "强更新/常量覆盖" | `access-path.js` 的 `removeAssignedTaint` | path-engine / audit-query-engine 各自调用 | pattern-parser 不管 | **实测常量覆盖后仍报**（三套调用路径行为不一致） |

**一句话**：现在不是"一个污点引擎 + 一份声明式规则库"，而是"**三套并行引擎（结构化 AST / 正则 pattern / TS Compiler）各自硬编码了一份安全知识**"。修 bug = 在多处对齐，这就是屎山的成因。

---

## 1. 统一架构：单一事实源（Single Source of Truth）

### 1.1 核心原则

```
                ┌─────────────────────────────────────────┐
                │   security/catalog.js  (唯一事实源)      │
                │   声明式地描述所有 source/sink/           │
                │   sanitizer/propagator/风险规则           │
                └─────────────────────────────────────────┘
                              │ 编译
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐   ┌──────────────────┐   ┌────────────────┐
│ AST 前端       │   │ Pattern 前端      │   │ TS Compiler 前端│
│ (tree-sitter) │   │ (降级/无 AST 时)  │   │ (JS/TS 精确)    │
│ 消费编译产物   │   │ 消费编译产物       │   │ 消费编译产物     │
└───────────────┘   └──────────────────┘   └────────────────┘
        └─────────────────────┼─────────────────────┘
                              ▼
                    ┌──────────────────┐
                    │ 统一 IR 操作      │
                    │ (source/sink/     │
                    │  guard/assign)    │
                    └──────────────────┘
                              ▼
                    ┌──────────────────┐
                    │ path-engine       │
                    │ (唯一污点传播)     │
                    └──────────────────┘
```

**关键转变**：前端不再各自硬编码"什么是 sink"。它们只做一件事——把 AST/正则命中的语法节点，**翻译成统一 IR 里的操作**（`source`/`sink`/`guard`/`assignment`/`call`），具体"这个 API 算不算 sink、净化能力多强"全部由 `catalog` 决定。

### 1.2 新模块：`src/security/catalog.js`

一份声明式目录，覆盖所有语言。每个条目：

```js
{
  // —— 匹配：这个条目命中哪些调用 ——
  match: {
    // 结构化匹配（AST 前端用）：模块 + 限定名 + 方法名 + 接收者类型
    qualifiedNames: ["child_process.exec", "os.system"],
    callNames: ["exec", "system"],
    moduleNames: ["child_process", "os"],
    receiverTypes: ["os"],
    // 文本兜底（pattern 前端用，可派生，见 §3.3）
    // 不需要手写正则！由 qualifiedNames/callNames 自动生成
  },
  // —— 语义：命中后它是什么 ——
  role: "sink",                 // source | sink | sanitizer | propagator | auth
  sinkKind: SinkKind.COMMAND_EXEC,
  taintArguments: [0],          // 哪些参数位带污点
  returnsTaint: false,
  // —— 适用语言 ——
  languages: ["javascript", "typescript", "python"],
  // —— 证据强度 ——
  confidence: "high",           // high=限定名命中 / medium=仅方法名
}
```

** sanitizer 也进同一张表**（这是修复误报的关键）：

```js
{
  match: { callNames: ["Number", "parseInt", "parseFloat"], qualifiedNames: [] },
  role: "sanitizer",
  capability: GuardCapability.NUMERIC_ONLY,   // 数值化
  languages: ["javascript", "typescript"],
},
{
  match: { qualifiedNames: ["intval", "filter_var"], callNames: ["intval"] },
  role: "sanitizer",
  capability: GuardCapability.NUMERIC_ONLY,
  languages: ["php"],
},
```

> 现在 `Number()`/`intval` 之所以误报，就是因为**它们根本不存在于任何一套模型里**。统一进 catalog 后，一次声明、所有前端生效。

### 1.3 `GuardCapability` 重新归位

把 `definitions.js` 里那堆 `GuardCapability` 从"规则文件的附属品"提升为**catalog 的一等属性**。规则不再持有 `sanitizerCapabilities` 白名单，而是：

```js
// rules 只声明"我这个 sink 类型，接受哪些净化能力"
{ id: "potential-sql-injection",
  sinkKind: SinkKind.SQL_QUERY,
  acceptsSanitizers: [GuardCapability.SQL_PARAMETERIZATION, GuardCapability.NUMERIC_ONLY] }
```

规则引擎（`rule-engine.js`）的消费逻辑**保持不变**（`observedGuards.includes(capability)`），只是 `observedGuards` 现在来自统一 IR，而不是某一前端的特判。

---

## 2. 数据流引擎统一：一个传播器，多个解析器

### 2.1 现状

- `path-engine.js` 一套传播（用 `removeAssignedTaint`、`advanceValueVersion`）
- `audit-query-engine.js` **又写了一遍**传播（第 299/304/312 行各调一次 `removeAssignedTaint`，三处语义还略有差别）
- `pattern-parser.js` 的 `traceIdentifier` 用正则"追变量"——第三套

### 2.2 改法

**抽出唯一的污点传播内核** `src/dataflow/taint-kernel.js`：

```js
// 输入：统一 IR 操作序列；输出：每个 sink 点的 (taintedPaths, evidence, observedGuards)
function propagate(events, options) {
  let tainted = new Set(), versions = new Map(), guards = [];
  for (const event of events) {
    switch (event.kind) {
      case "assignment":  tainted = applyAssignment(tainted, versions, event); break;
      case "guard":       guards.push(resolveGuard(event)); break;   // catalog 判定净化能力
      case "source":      tainted.add(...event.outputs); break;
      case "sink":        emitIfTainted(event, tainted, guards); break;
    }
  }
}
```

- `path-engine` 和 `audit-query-engine` **都调用这一个内核**，删掉各自重复的传播分支。
- `pattern-parser.js` 的 `traceIdentifier` **整体删除**——降级模式下也走 IR（见 §3.3），不再用正则追变量。

**这一步直接修复"常量覆盖仍误报"**：因为强更新逻辑（`removeAssignedTaint` + version）只在一个地方实现，三个入口行为必然一致。

### 2.3 修复 f-string / 字符串内插（漏报）

在**统一 IR 生成阶段**（不是某个前端），把"字符串拼接/插值"统一映射为 `assignment(mode:"aggregate", inputs:[所有插值片段])`：

```
Python f"ping {c}"  ──┐
JS  `ping ${c}`     ──┼──►  IR: assign(out, inputs=[c], mode=aggregate)
Java "ping "+c      ──┘
```

Python 前端补 `JoinedStr`/`Interpolation` 节点 → 统一走上面这条。**一处补，全语言字符串插值都通**。

---

## 3. 前端收敛：三个前端，一份目录

### 3.1 AST 前端（tree-sitter）

保留它产出 IR 的职责，但**删除所有硬编码安全知识**：

- `tree-sitter-frontend.js` 里的 `safeCollectionJoinGuard`、Java 集合特判（`registerJavaCollection`、`genericJavaCollectionAccess`）—— 把"集合是固定/全数值/安全 join"抽象成 catalog 里的 `propagator` + `sanitizer` 条目，前端只做 AST → IR 翻译。
- 判定逻辑收敛为：`catalog.lookup(callIdentity, language)` 返回 role/sinkKind/capability，前端据此打 IR 操作。

### 3.2 TS Compiler 前端

同上。它已经有类型解析优势，让它把 `receiverType` 填进 IR，`catalog.lookup` 用 receiverType 做更精确匹配（减少"同名方法误命中"）。

### 3.3 Pattern 前端（降级模式）—— 正则从"手写"变"派生"

这是去屎山的关键一跃。**现在 7 套手写正则全部删除**，改为：

- catalog 里每个条目的 `qualifiedNames`/`callNames` **自动编译出**该语言的兜底正则：`new RegExp("\\b(?:" + callNames.join("|") + ")\\s*\\(")`。
- pattern 前端命中后产出**同构 IR 操作**（标记 `confidence: "medium"`，因为没有 receiver/模块证明），交给同一个 taint-kernel。
- 好处：pattern 模式不再是"另一套语义"，而是"低置信度的同一套语义"。降级模式和 AST 模式**结果可对齐**，`astDifferentialMode` 才有意义。

> 像 `isStaticPhpExpression` 这种"PHP echo 字面量不算 sink"的特例，保留为 catalog 条目的一个 `staticOperandSafe: true` 属性 + 一个共享求值器，而不是散在 pattern-parser 里的语言特判函数。

---

## 4. source 分级（修 open-webui 那类噪音）

catalog 里给 source 加 `exposure` 维度，规则引擎按它排序：

```js
{ role:"source", sourceKind: HTTP_INPUT,  exposure:"remote"   }  // req.query / $_GET → P0
{ role:"source", sourceKind: PROCESS_INPUT, exposure:"local" }  // process.env / os.getenv → P2
{ role:"source", sourceKind: FILE_UPLOAD, exposure:"remote"  }
```

`risk/scorer.js` 里把 `exposure:"local"` 的 finding 降权。这样 `os.getenv('DATA_DIR')→Path()` 仍被记录（可审计），但不再霸榜 P0。

---

## 5. 重构顺序（每步独立可验证、可回滚）

按"风险从低到高、收益从大到小"排：

1. **建 `catalog.js` 骨架 + 单测**：把现有 `semantic-models.js` 内容搬进去，定义 schema。此时不改任何调用方，纯新增。
2. **sanitizer 入 catalog + 统一消费**：补 `Number/parseInt/parseFloat/intval/floatval`（JS/PHP/Python `int()/float()`），让 rule-engine 能查到。**立即消除我实测的那批误报**。回归：跑全部现有测试 + 我给的对抗样本。
3. **抽 `taint-kernel.js`**：合并 path-engine 与 audit-query-engine 的传播分支。回归：现有 dataflow 测试全过即说明语义不变。**顺带修复强更新不一致**。
4. **IR 统一字符串插值**：Python 补 f-string，验证 `os.system(f"ping {c}")` 检出。回归：漏报样本转测试。
5. **前端去硬编码**：逐个把 `safeCollectionJoinGuard`、Java 集合特判搬进 catalog propagator。每次搬一个，跑测试。
6. **pattern 正则派生化**：先让派生正则与原手写正则**并行跑**，用 `astDifferentialMode` 比对覆盖率一致后再删手写正则。
7. **source 分级**：改 scorer，回归真实项目扫描的 P0 构成。

每一步都是"小步重构 + 全量测试"，绝不一次性大改。

---

## 6. 防回归：把"对抗样本"变成一等公民

现在的测试和实现是同一套假设（所以 320 全过、对外却夸大）。新增一个**独立的、不许改实现来迁就的**对抗语料 `test/adversarial/`：

- 每条样本 `vulnerable/safe` 成对，断言 `precision=1 且 recall=1`（像 `core-rules.test.js` 末尾那样算指标，但**样本来源独立于实现**）。
- 我这次测出的样本全部入库：常量强更新、Number/parseInt/intval 净化、Python f-string、三元/分支污点、数组 join、跨 3 文件。
- CI 里这条测试**失败即阻塞**，且**不允许通过修改实现来让特定样本过**（code review 时盯这一点）。

---

## 7. 明确"不做什么"

- **不删 pattern 前端**：它是无 AST/大文件降级时的兜底，只是把它的语义从"手写正则"改为"catalog 派生"。
- **不强求三大前端结果 100% 一致**：AST 高置信、pattern 低置信是合理分层，用 `confidence` 字段区分即可，不要强行拉平。
- **不动 Worker/增量缓存/CI 那套**：那部分工程质量是真的高，本次重构只在语义层动刀。

---

## 8. 验收标准（怎么知道重构成功了）

1. 我这次的 16 个对抗样本，误报（强更新/Number/parseInt/intval）全消除、f-string 漏报修复，**且不为此新增任何一条针对特定样本的硬编码**。
2. 新增一个 sink（比如某个新的 ORM 危险方法）= 只在 `catalog.js` 加一条声明，三个前端自动生效——**改 1 个文件，不是 5 个**。
3. `pattern-parser.js` 行数大幅下降（7 套手写正则消失），`tree-sitter-frontend.js` 不再含安全业务规则。
4. 全量测试 + 新对抗语料在 CI 全绿。
