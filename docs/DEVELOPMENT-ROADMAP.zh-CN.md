# TraceGuard 0.1 → 0.7：开发实录与后续路线

这份文档记录 TraceGuard 从 0.1 到 0.7 的制作过程、几次关键转向、已经形成的架构，以及后续版本应该继续解决什么问题。

TraceGuard 当前的产品定位是：

> 一个本地、增量、可解释的 VS Code 轻量 SAST。它不追求一次输出几千条告警，而是给出可信的 Source → Sink 路径、说明不确定性，并帮助人工完成代码审计。

## 版本演进

| 版本 | 当时要解决的问题 | 主要完成内容 | 对下一阶段的影响 |
| --- | --- | --- | --- |
| 0.1 | 先验证“在 VS Code 内做安全扫描”是否可用 | Java/PHP 扫描、Problems 诊断、基础规则、工作台页面 | 证明插件形态可行，但扫描结果与人工审计流程脱节 |
| 0.2 | 让结果真正服务于人工审计 | Attack Surface、P0–P2 审计队列、CodeLens、安全线索、审计笔记和报告 | 产品从“扫描器界面”转向 Audit Copilot |
| 0.3 | 降低安装和运行负担 | 移除 Python 子进程、服务端和重型扫描工作台，回到原生 VS Code 视图 | 确立本地、轻量、无外部服务的约束 |
| 0.4 | 扩展到真实的多语言项目 | 支持 Java、PHP、JavaScript/TypeScript、Python、C#、Go；增加导航、当前函数审计和更快的 review 操作 | 暴露出正则函数边界、同名函数和语言差异问题 |
| 0.5 | 补齐审计工作流 | 变量追踪、跨文件线索、审计会话导入导出、证据记录、中文文档和 CI | 插件开始能够承载完整的人工复核过程 |
| 0.6 | 把功能堆叠改造成可演进的分析架构 | 统一 IR、Frontend Registry、数据流与规则分层、Worker、稳定 ID、状态迁移、SARIF 和发布流程 | 形成 SAST 地基，但部分分析仍从 Pattern/正则结果转换而来 |
| 0.7 | 让 AST、增量分析和可解释数据流真正进入主链 | 七语言 Tree-sitter WASM、JS/TS Compiler API、精确 source span、CFG/def-use、函数摘要、持久 Worker、项目级入口绑定、参数 provenance、规则专用 guard/sanitizer | TraceGuard 从“正则辅助审计工具”升级为可运行的轻量 SAST RC |
| 0.8 | 聚焦后端审计并先打穿 Java | 公共 CFG/传播/查询内核、Spring/JAX-RS/Servlet、DTO Access Path、接口与实现、重载、MyBatis/JDBC/JPA、Spring HTTP 客户端 | 从平均覆盖七种语言改为 Java/PHP/Python Tier A，并完成第一条真实 Java 分层路径 |

## 各版本是怎么一步步做出来的

下面不是简单的功能清单，而是按“当时的代码状态 → 实际开发步骤 → 遇到的问题 → 最终留下什么”记录 0.1 到 0.7 的制作过程。

### 0.1：先跑通 VS Code 内扫描闭环

0.1 的目标很简单：先证明安全扫描放在编辑器里确实能用，而不是先设计一套庞大的分析平台。

实际开发时先完成扩展激活、命令注册和工作区文件枚举，然后只读取 Java、PHP 文件，用一组模式识别危险 API、输入点和可疑代码。匹配结果被转换为 VS Code Diagnostic，显示在 Problems 面板中，用户点击后能够直接跳到代码位置。随后补上最小配置、图标、`package.json` 命令声明和 VSIX 打包，让插件可以脱离开发环境安装。

当时的处理链基本是：

```text
扫描文件 → 正则命中 → Diagnostic → Problems 面板
```

这个做法开发快，也验证了插件形态，但很快暴露出两个问题：一是规则、解析和 UI 混在一起；二是扫描器只会告诉用户“这里可疑”，不会帮助用户判断入口、调用关系和审计进度。0.1 因此只承担产品验证，没有继续在这套结构上堆功能。

### 0.2：把扫描结果组织成人工审计任务

0.2 开始解决“告警出来以后怎么审”的问题。开发重点从 Problems 面板转向侧边栏审计工作台，并逐步形成后来一直保留的三层信息：

- Attack Surface：HTTP 路由、控制器方法等外部入口；
- Review Targets：按 P0、P1、P2 排序的待审函数和文件；
- Audit Evidence：安全线索、审计笔记和人工结论。

具体实现过程是先把原始命中结果转换为可供 TreeDataProvider 消费的审计项，再增加 CodeLens，让入口、输入和敏感操作直接显示在代码上方。之后加入 reviewed 状态、审计笔记和报告生成，使用户关闭 VS Code 后仍能恢复审计进度。

这一版最重要的变化并不是多了几个视图，而是内部开始区分“机器发现的线索”和“用户确认的结论”。TraceGuard 的定位也由普通扫描器转向 Audit Copilot。

### 0.3：删除 Python 子进程和重型工作台

0.2 之后曾经存在 Python 扫描逻辑、子进程通信和自定义 Webview 工作台。它们能够承载更多界面和分析逻辑，但带来了运行环境、进程生命周期、路径兼容、错误回传、打包体积和离线安装等一系列成本。

0.3 的开发不是“增加”，而是一次主动减法：

1. 移除 Python 运行时和服务端依赖；
2. 删除子进程启动、通信与退出管理；
3. 将主要交互迁回 VS Code 原生 Tree View、Diagnostic、CodeLens 和命令；
4. 重新整理 VSIX 清单，确认离线环境只依赖扩展自身携带的 Node.js 代码。

这次重构短期内牺牲了一些展示能力，却确立了后续版本的硬约束：本地运行、默认不上传源码、无外部服务、安装后直接可用，并且不能用长时间同步计算阻塞 Extension Host。

### 0.4：扩展七种语言，并碰到正则解析的天花板

0.4 把语言覆盖从 Java/PHP 扩展到 Java、PHP、JavaScript、TypeScript、Python、C# 和 Go。开发时为每种语言补充文件扩展名、函数识别模式、入口模式、输入源和敏感调用，同时增加当前文件、当前函数审计和更快的跳转操作。

随着真实代码样本增加，正则前端开始反复出现结构性错误：

- 字符串、注释或正则字面量里的 `{`、`}` 会破坏函数边界；
- 多行函数签名、箭头函数和嵌套回调无法稳定识别；
- Java 重载、同名函数和匿名路由回调会发生 ID 碰撞；
- 不同语言的 member access、receiver 和装饰器很难共用一套模式；
- 同一段代码只改变换行方式，扫描结论可能不同。

开发过程中尝试过继续修补 `SIGNAL_PATTERNS` 和函数正则，但每修一种语法都会影响另一种语言。这个阶段最终得到的不是“更复杂的正则”，而是一个明确结论：多语言能力必须拆成语言 Frontend，并输出统一中间表示。

### 0.5：补齐审计会话、变量线索和证据链

0.5 先没有立即重写解析器，而是把人工审计流程补完整。具体加入了选中变量后的定义、赋值、使用点和敏感操作追踪，增加跨文件线索，并让审计会话可以导入、导出和迁移。报告生成也从简单结果列表扩展为包含入口、判断、证据和备注的可复核记录。

这个阶段还处理了一批不显眼但很影响使用的问题，例如相对路径与绝对路径转换、不同系统的路径分隔符、Markdown 代码块转义、工作区切换后的状态恢复，以及分析取消后不应覆盖新结果等。

0.5 完成后，用户已经可以走完：

```text
发现入口 → 打开函数 → 追踪变量 → 记录证据 → 标记结论 → 导出会话/报告
```

但变量追踪仍是启发式的，缺少真正的 def-use、控制流和跨函数摘要。因此它解决了审计工作流，没有解决 SAST 分析深度。

### 0.6：拆掉 God Object，建立 SAST 地基

0.6 的第一步是审计现有代码，而不是直接加 AST。当时 `audit-analyzer.js` 和 `flow-analyzer.js` 同时承担代码解析、调用识别、污点传播、路径搜索和结果组装，`audit-controller.js` 还负责扫描生命周期、UI、状态和配置，任何新功能都会继续放大耦合。

重构按下面的顺序推进：

1. 建立 `src/frontends/registry.js`，让语言选择和解析能力通过 Frontend 注册，不再由控制器判断；
2. 建立 `src/ir/schema.js`，定义文件、函数、参数、operation、signal、source location 和 symbol identity；
3. 将旧 Pattern 解析保留为兼容前端，把已有结果先投影为统一 IR，避免一次性推倒所有语言；
4. 将路径传播移到 `src/dataflow/`，将漏洞语义移到 `src/rules/`；
5. 将 review target、finding 状态和 SARIF 输出从分析代码中分离；
6. 接入 Worker，把扫描计算移出 Extension Host 主线程；
7. 加入稳定 ID、状态迁移和不完整扫描保护，避免代码插入后丢失 reviewed 状态，也避免部分扫描误删历史状态。

0.6 建立了正确的分层：

```text
Frontend → IR → Dataflow → Rule → Finding → Review/SARIF
```

但实际运行路径仍有过渡痕迹：部分代码先由正则构造 `flowFunctions`，再转换为 IR；Worker 主要承担计算搬运，增量缓存和函数摘要还没有真正成为项目级运行状态。因此 0.6 是干净的 SAST 基础版，还不是 AST 分析完成版。

### 0.7：让 AST、项目语义和增量数据流真正进入主链

0.7 没有一次完成，而是经历了几轮“接入—实测—发现假阴性—补齐语义”的迭代。

#### 第一轮：接入七语言 AST 前端

先为七种语言打包 Tree-sitter WASM grammar，由 `tree-sitter-frontend.js` 负责解析函数、调用、参数、赋值、返回、分支和精确 source span。选择 WASM 是为了让同一个 VSIX 在 Windows、Linux 和 macOS 上运行，不需要分别编译 native addon。

JavaScript/TypeScript 另外建立 `typescript-compiler.js` 和 `typescript-frontend.js`。Compiler Program 提供 import/export、symbol、类型、上下文参数类型和跨文件声明解析，Tree-sitter 则继续承担容错语法层。旧 `pattern-parser.js` 没有删除，而是作为解析失败时的 fallback 和新旧结果对照工具。

接入后首先修复了 `.ts` 被错误当成 TSX 的问题。普通 TypeScript 泛型 `<T>` 曾被解析为 JSX，Compiler diagnostics 增加后整份文件静默退化。处理方式是根据 `.ts/.tsx/.js/.jsx` 文件扩展名选择正确 ScriptKind，并把 Compiler diagnostics 和降级原因暴露给能力统计。

#### 第二轮：补函数内 CFG、def-use 和精确位置

在 AST operation 基础上构造函数内 CFG，加入 assignment、argument、return、property、concat/template、简单 alias 和 branch guard 传播。没有立即实现完整 SSA，而是先让五类核心规则获得稳定的 Source → Sink 路径。

早期 branch operation 只有行号，没有 `thenRange/elseRange`，导致“guard 只要出现在 sink 前面就算生效”，Java、Python、PHP、C#、Go 会出现 SQL 注入假阴性。第一次修复分支范围后，又发现 CFG 只比较 `location.line`：如果 `if` 和危险 sink 写在同一行，sink 会被错误归入分支。最终 IR location 增加行、列和 byte offset，CFG 按真实 AST span 划分 block，并增加同一代码单行/多行结果一致的测试。

#### 第三轮：稳定 symbol identity 和 review 状态

普通函数 ID 从“文件 + 名称 + 行号”升级为：

```text
language + normalized path + enclosing scope/type + function name + typed signature
```

随后又处理匿名路由回调：两个 `app.get()` 或 `Route::get()` 不能都叫 `get$callback1`，需要将所属调用、路由方法、路由路径和结构 discriminator 纳入 identity。路径规范化也从无条件 `toLowerCase()` 改为遵守平台大小写语义，避免 Linux 下 `Foo.js` 和 `foo.js` 被合并成同一文件。

Review 层不再自行拼接 ID，而是直接消费 IR 的 `symbolKey`。完整工作区扫描成功时才允许回收 orphan 状态，单文件或中断扫描只能更新已确认的部分。

#### 第四轮：把 Worker 改成真正的增量工作区引擎

最初的 Worker 只是把全量分析放到另一个线程，每次保存仍可能复制整个 workspace。0.7 将它改为持久 Worker，并由 `workspace-engine.js` 保存文件 IR、语法树、函数摘要、调用关系和反向依赖。

运行接口逐步收敛为：

```text
initializeWorkspace
updateFile
removeFile
reanalyzeAffectedFunctions
```

文件变化后先更新单文件 AST/IR，再失效受影响函数摘要，重算有限调用图和污点路径，最后只返回变化结果。连续保存会合并旧请求；Worker 超时或崩溃后由客户端重建状态。

TypeScript 增量最初只覆盖静态 import。实测被依赖文件删除、动态 `import()` 和 CommonJS `require()` 后，Compiler Checker 已更新，但消费方缓存 IR 仍保留旧类型。后来增加模块反向依赖，在删除前保存 dependents，并让静态 import、动态 import、require 和入口绑定变化都触发消费方重解析。

#### 第五轮：从“看懂 AST”走到“看懂框架约定”

最开始框架入口仍由 `pattern-parser.js` 逐行识别，所以多行 `app.get()`、`MapGet()` 和 `HandleFunc()` 会丢失路由或直接漏报。修复时改为遍历 AST call node 和 argument，而不是扫描单行文本，同时保留动态路径为 `GET <dynamic>`。

之后又补了更深一层的框架语义：

- 一个路由绑定多个 middleware/handler，而不是只记录第一个函数；
- TypeScript Checker 将 imported handler 解析到目标文件真实声明；
- C# Minimal API lambda、Go function literal、PHP/JS 内联回调生成独立函数记录；
- Go Gorilla `.Methods()` 进入 HTTP method 语义；
- 参数不再只根据 `req/res/service` 变量名猜测可信度，而是记录 request、body、query、path、header、response、context、continuation、service、logger、database、cancellation 和 unknown 角色；
- unknown 角色保留传播但降低置信度，DI 服务默认不作为 HTTP taint seed。

这一步说明 AST 只能提供语法事实，Express、ASP.NET Core、Go HTTP、Laravel 等调用约定必须由独立的 framework entry classifier 建模。

#### 第六轮：修复一次会让 AST 全面静默降级的集成错误

0.7 重构后曾出现一个典型的模块契约断裂：`tree-sitter-frontend.js` 已开始调用 `dedupeFrameworkEntries` 和 `inferParameterRoles`，但 `framework-entries.js` 仍保留旧导出。结果不是扩展直接崩溃，而是所有 Tree-sitter 前端初始化失败后被 fallback 吞掉，七种语言静默回到 Pattern 模式。

这个问题暴露了两个缺陷：单测只验证了 fallback 后“仍有结果”，却没有断言实际 frontend mode；同时 Tree-sitter 与 TypeScript 两个调用方对 `handlerIndex/handlerIndexes` 的契约不一致。

最终修复不是简单补两个 export，而是统一整个 framework entry API：同时支持多 handler、动态路由、链式 HTTP method、参数角色和去重，再同步修改 Tree-sitter/TypeScript 前端。测试也增加直接实例化 AST 前端、断言 `mode: ast`、断言未降级和逐语言运行时校验，避免以后出现“测试绿了但 AST 根本没跑”的情况。

#### 第七轮：补产品闭环和发布验证

分析结果以 sink 为中心合并，记录污染源、中间变量/参数、跨函数步骤、观察到的 guard、缺失能力、置信度和启发式步骤。人工状态扩展为 reviewed、false positive、accepted risk 和 suppressed，并支持 SARIF 导出、覆盖率、跳过文件和降级原因展示。

打包阶段发现 `.vscodeignore` 曾把依赖许可证一起排除，因此增加第三方许可证清单和 packaged-runtime 校验。Extension Host smoke test 也从“能激活、命令已注册”扩展到真实加载 Worker、AST runtime 和核心命令链。

截至 2026-08-22，本地 0.7 候选代码的验证结果为：

- 116/116 自动化测试通过；
- 40 个 JavaScript 源文件语法检查通过；
- 七语言 Tree-sitter 前端直接验证均为 AST 模式，没有静默降级；
- 1,000 文件基准约为初始化 1.45 秒、增量 385 毫秒、RSS 370 MiB；
- 100 个 TypeScript 依赖扇出场景增量约 339 毫秒、RSS 303 MiB；
- Extension Host smoke test 正常退出；
- VSIX 共 186 个文件、约 3.32 MB，七语言 WASM、TypeScript runtime 和许可证均通过包内校验。

这些数字是当前候选版本的开发快照，不等于正式版本承诺。0.7 仍应先以 RC 在真实项目中验证，确认没有新的 P1/P2 后再发布。

## 0.7 框架语义绑定专项开发记录

这项工作解决的不是某一条漏洞规则，而是 AST 与项目级数据流之间缺失的一层关系：

```text
AST 看见：app.get("/x", auth, handler)

框架语义需要进一步回答：
  - 这是一个 GET /x 外部入口；
  - auth 和 handler 都属于同一条处理链；
  - handler 可能声明在另一个文件；
  - handler 的 request 参数是不可信输入；
  - response、next 和注入 service 不是同一种来源；
  - 路由文件变化时，handler 的入口身份和数据流也要失效。
```

如果这层关系不完整，AST 即使正确解析了每一个节点，数据流仍不知道从哪个函数、哪个参数开始传播。下面六项是作为一个整体完成的。

### 1. 一个路由绑定多个 handler 和 middleware

旧模型只返回单个 `handlerIndex`。对于：

```javascript
app.get("/x", authenticate, authorize, handler);
```

它通常只会绑定 `authenticate`，真正读取请求并调用 sink 的 `handler` 不再被视为入口。这会造成稳定假阴性，也会把 CodeLens 和 review target 跳到错误函数。

实现时把分类结果改为 `handlerIndexes`，由 framework classifier 返回路由参数之后的全部候选位置。Frontend 再逐个展开 handler；如果参数本身是数组，也递归展开数组元素。每个 handler 生成独立 entry，但共享 HTTP method、route 和 framework 信息。

为了兼容已有 IR 和界面，单条 entry 仍保留自己的 `handlerIndex`。去重键同时包含 method、route、function identity 和 handler index，避免多个 middleware 被错误合并，也避免 Pattern fallback 再生成一份相同入口。

验收不只检查入口数量，还检查：

- 多个 handler 得到不同 `functionId`；
- 最终 handler 内的 Source → Sink 路径仍能建立；
- 数组式 middleware 不会退化成一个无法解析的表达式；
- 链式路由不会同时保留 `REQUEST` 和更具体的 `GET/POST` 重复入口。

### 2. 用 TypeScript Checker 绑定 imported handler

跨文件路由的典型结构是：

```typescript
// routes.ts
import { handler } from "./handlers";
app.get("/x", handler);

// handlers.ts
export function handler(req: Request, res: Response) {
  exec(req.url);
}
```

只在 `routes.ts` 的 function records 中搜索 `handler` 必然失败。为此，TypeScript Frontend 在处理 handler argument 时执行以下步骤：

1. 使用 Checker 对 handler identifier 或 property access 调用 `getSymbolAtLocation()`；
2. 如果得到 alias symbol，继续调用 `getAliasedSymbol()`；
3. 在 symbol declarations 中寻找函数声明、方法、变量初始化函数或属性初始化函数；
4. 通过目标 declaration 的 `SourceFile` 找到项目中的真实文件信息；
5. 使用与目标文件 Frontend 相同的 `describeFunction()` 和 identity 规则生成记录；
6. 将路由 entry 的 `functionId/symbolKey` 指向目标声明，而不是路由文件里的名字文本。

这样入口、review target、调用图和 finding 都消费同一个 `symbolKey`。导入别名或代码行移动不会重新制造另一套身份。

跨文件测试必须同时初始化 `routes.ts` 和 `handlers.ts`，断言 `/x` entry 指向后者的函数，并确认 handler 内危险调用能够形成 finding。仅测试 inline callback 无法覆盖 Checker、alias 和 project file lookup 这条链路。

### 3. 动态路径保留未知入口

旧实现只有在第一个参数是字符串字面量时才创建路由：

```javascript
const route = config.apiPath;
app.get(route, handler);
```

静态求值失败后直接丢弃 entry，会连带丢掉 handler 的 HTTP taint seed。0.7 改为分两级处理：能通过 AST/Compiler 确认常量时保留真实路径；无法确认时记录为 `GET <dynamic>`。

`<dynamic>` 表示“路径文本未知”，不是“这个入口不存在”。它仍保留 method、handler identity、source span 和 framework，数据流继续运行，但路径解释和置信度会明确标记不确定性。

对应测试至少覆盖变量路径、模板表达式和无法解析的配置值，并断言：

- entry 没有消失；
- HTTP method 没有退化；
- handler 仍然绑定；
- 不确定路径不会伪装成已知字符串。

### 4. 给入口参数增加 provenance

早期数据流将入口函数的全部参数视为不可信，再根据 `res`、`response`、`next` 等变量名排除。这种方法会同时产生漏报和误报：请求参数叫 `response` 时会漏报，依赖注入的 `CommandService service` 又可能被当成攻击者输入。

0.7 在 IR 参数上增加 role/provenance，并分为两类推断：

- 框架位置规则：Express 的 request/response/continuation、错误 middleware 的 error/request/response/continuation、Go 的 response/request；
- 声明语义规则：`@Body`、`@Query`、`@Param`、`@Headers` 等 decorator，以及 `HttpRequest`、`HttpResponse`、`HttpContext`、`ILogger`、`DbContext`、`*Service`、`*Repository`、`CancellationToken` 等类型。

最终角色包括：

```text
会播种 taint：request、body、query、path、header
默认不播种：response、context、continuation、service、logger、database、cancellation
不确定：unknown（保留传播，但降低置信度）
```

角色结果写入 entry point 和 function parameter IR，Path Engine 只消费 IR，不重新按变量名猜测。测试同时提供“请求对象使用误导性变量名”和“DI 服务名称看起来像输入”两类反例，防止单向修复。

### 5. 补齐删除文件、动态 import 和 CommonJS require 的增量失效

跨文件 Checker 绑定完成后，另一个问题随之出现：项目初始化时能找到 handler，不代表文件变化后缓存仍然正确。

TypeScript Project 现在递归遍历 SourceFile，收集以下模块边：

```text
import ... from "./module"
export ... from "./module"
import name = require("./module")
await import("./module")
require("./module")
```

Workspace Engine 同时维护正向依赖和反向 dependents。更新文件时取变更前和变更后的 dependents 并集；删除文件时必须先保存旧 dependents，再从 TypeScript Project、增量缓存和 Tree-sitter runtime 中移除文件。随后重新解析消费方，比较旧、新函数 identity 和摘要，将受影响函数加入局部重算队列。

回归测试不只断言 `affectedFiles` 包含消费方，还检查消费方 IR 的真实变化。例如 provider 把回调参数从 `string` 改成 `number` 后，动态 import 消费方的参数类型必须同步变为 `number`；provider 删除后类型应退化为 unknown，`symbolKey` 也必须反映新的签名，而不能继续使用陈旧缓存。

### 6. 建立真正的跨文件路由 fixture

inline handler 测试只能覆盖 AST callback 提取，无法覆盖项目级 symbol、模块解析和入口失效。因此新增 fixture 按真实项目结构组织：

```text
project/
  routes.ts       # 注册路由，可能包含多个 middleware
  handlers.ts     # 导出最终 handler
  services.ts     # DI 服务或数据流中间层
  provider.ts     # 为类型变化/删除测试提供依赖
```

测试流程模拟完整生命周期：初始化工作区、确认跨文件入口、修改导出签名、增加或删除路由、删除被依赖文件，再检查 entry binding、parameter role、function summary、affected files 和最终 findings 是否一起变化。

尤其增加“先没有路由 → 增加跨文件路由 → handler 成为入口 → 删除路由 → handler 失去入口”的用例。它验证的不只是解析，还验证入口关系本身已经进入增量失效模型。

### 六项完成后的主链

框架语义绑定完成后，一条跨文件 Express 路由的分析过程变为：

```text
routes.ts 的 CallExpression
  → classifier 得到 GET /x 和全部 handlerIndexes
  → Checker 将 imported handler 解析到 handlers.ts declaration
  → declaration 复用统一 symbolKey
  → framework model 为参数写入 request/response provenance
  → request 参数成为 taint source
  → function summary/调用图继续传播
  → sink 生成可解释 finding
  → routes.ts 或 handlers.ts 变化时反向依赖触发局部重算
```

这部分的完成标准不是“能识别 `app.get`”，而是语法、项目符号、框架角色、数据流和增量失效使用同一套身份闭环。至此，0.7 的主要债务才从“框架调用约定尚未进入主链”缩小为“继续扩充框架模型的覆盖范围和真实项目语料”。

## 写代码时的具体落地过程和工程思路

这一节记录代码实际是如何逐层写出来的。它不是逐条 commit 的复述，而是可以从当前仓库结构中还原出的实施顺序、接口选择、失败点和调整依据。

### 第一步：先保留旧行为，再切分析入口

如果直接删除 Pattern 分析器并一次性替换七种语言，任何结果差异都很难定位究竟来自函数边界、signal 提取、入口绑定还是数据流。因此最先写的不是 Tree-sitter，而是 Frontend 契约和兼容层。

`src/frontends/registry.js` 中保留 `PatternLanguageFrontend` 作为默认实现，同时增加 preferred frontend：

```javascript
async function parseWithBestFrontend(input) {
  const fallback = frontendForLanguage(input.language);
  const preferred = preferredFrontendForLanguage(input.language);

  try {
    const ir = await preferred.parse(input);
    return ir;
  } catch (error) {
    const ir = fallback.parse(input);
    ir.frontend.degraded = true;
    ir.frontend.degradedReason = String(error.message || error);
    return ir;
  }
}
```

这里的思路是先把“选择哪个解析器”从业务控制器里拿出来。同步 `analyzeText()` 暂时保留给旧测试和兼容代码，正式 AST 路径通过异步 `analyzeTextAsync()` 进入 `parseWithBestFrontend()`。这样每迁移一种语言都不需要重写 Review/UI。

随后增加 differential 模式：同一文件同时跑 AST 和 Pattern，只比较函数、operation 和 entry 数量差异。它不是把两个结果混在一起，而是用于发现 AST 接入后是否意外少解析了某类结构。

### 第二步：先定 IR，再写具体解析器

Frontend 如果直接把 Tree-sitter node 或 TypeScript node 交给数据流层，后续每条规则都会绑定解析器 API。为避免这种扩散，先在 `src/ir/schema.js` 写出最小、版本化的 IR 构造器和校验器。

核心对象被限制为：

```text
FileIR
  frontend              实际解析模式、能力等级、降级原因
  functions[]
    id / symbolKey
    parameters[]         name、type、role
    operations[]         source/assignment/call/return/branch/guard/sink
    cfg
    entryPoints[]
  entryPoints[]
```

`location()` 一开始只有行号，后来补入 `startColumn/endColumn/startOffset/endOffset`。这些字段仍由统一构造器产生，避免某个 Frontend 用 0-based line、另一个 Frontend 用 1-based line。

每个 Frontend 返回前都经过 `validateFileIR()`。写这个校验器的目的不是追求完整类型系统，而是尽早抓住最危险的接口漂移：函数没有 symbol、operation kind 不合法、location 缺文件或参数 role 超出枚举。

为了不立即重写上层 UI，又写了 `src/frontends/ir-projection.js`，把 IR 投影回旧的 analysis/functions/entries/signals 形状。过渡阶段因此形成：

```text
新 Frontend → FileIR → compatibility projection → 旧 Review/UI
```

等上层逐步改为直接消费 IR 后，再缩小 projection 的职责。这个顺序比同时改解析器、数据流和 UI 更容易定位回归。

### 第三步：把 Pattern 解析器拆成可替换的基线

旧模式匹配代码没有直接删除，而是拆成几个可单测的步骤：

```text
findFunctions()      找函数范围
collectSignals()     找 source/sink/guard 线索
findEntries()        找框架入口
traceIdentifier()    做旧式变量追踪
parseSourceStructure() 组合兼容结果
```

`operation-extractor.js` 将这些旧结果转换为标准 operation，`normalized-frontend.js` 再组装 FileIR。这一步看起来像多绕了一层，但它让 Pattern fallback 和 AST Frontend 输出同一种 schema，数据流层不需要知道结果来自正则还是语法树。

拆分时先保持结果数量和位置兼容，再改内部实现。否则如果同一轮同时改变函数边界和规则结果，已有测试无法判断到底是哪一层退化。

### 第四步：编写 Tree-sitter WASM Runtime

Runtime 的代码先解决“加载和缓存”，再解决语义提取：

1. 按 language 映射对应 grammar WASM；
2. 延迟初始化 Parser，避免扩展激活时一次加载七种 grammar；
3. 按文件 identity 缓存 syntax tree；
4. 更新文件时把旧 tree 交给 parser 做增量解析；
5. 删除文件时同步释放对应 tree；
6. 将 parser error、tree error 和 incremental 状态写入 frontend metadata。

选择 WASM 而不是 native binding 的直接原因是 VSIX 分发。native addon 需要为 Windows、Linux、macOS 和不同架构分别编译，WASM 则可以使用同一套包内资源。代价是需要严格检查 WASM 是否真的进入 VSIX，所以后来增加了 `scripts/verify-packaged-runtime.js`。

`tree-sitter-frontend.js` 的实现顺序是：先收集函数节点，再在函数内部收集 assignment、call、return 和 branch，最后把 Pattern signals 映射到最接近的 AST operation。这样 AST 先解决边界和位置精度，旧规则线索仍可作为过渡输入，不必在第一天重写全部安全语义。

### 第五步：单独编写 JavaScript/TypeScript 增强前端

Tree-sitter 能看懂 JS/TS 语法，却不能提供完整的 import alias、上下文类型和跨文件 declaration。因此没有把 TypeScript 特例继续塞进通用 Frontend，而是建立：

```text
typescript-compiler.js   管理 Program、SourceFile、Checker 和模块依赖
typescript-frontend.js   将 Compiler AST/类型转换为统一 IR
```

具体代码顺序是：

1. 先根据扩展名实现 `scriptKindFor()`，区分 TS、TSX、JS、JSX；
2. 实现内存 CompilerHost，让未保存或刚更新的文件内容也能进入 Program；
3. 建立 `TypeScriptProject` 文件表和 generation，每次文件集合变化时重建 Program；
4. 用 Checker 补参数类型、alias declaration 和 imported handler；
5. 遍历 SourceFile 收集静态 import/export、动态 `import()` 和 `require()`；
6. 将 Compiler diagnostics、project mode、项目文件数和 generation 写入 IR frontend metadata。

这里没有把 Checker type object 保存进 IR，因为它不能安全跨 Worker 序列化，也会让缓存绑定具体 Program 实例。IR 只保存稳定字符串类型、symbolKey 和必要的语义事实。

### 第六步：将源码节点转换为 operation

数据流不直接遍历 AST，而是消费一组有序 operation。每识别一个语法节点，就生成类似以下事实：

```javascript
operation({
  kind: OperationKind.ASSIGNMENT,
  inputs: [symbol("request.query.cmd")],
  output: symbol("command"),
  location: exactSpan,
  certainty: "high"
});
```

实现时先支持最有价值且跨语言容易统一的边：

- `a = b`：assignment；
- `foo(a)`：argument/call；
- `return a`：return；
- `obj.url = input`：property path；
- `"/tmp/" + name` 和 template literal：concat；
- `b = a`：simple alias；
- `if (...)`：branch；
- source/sink/sanitizer 调用：带 security semantic 的 operation。

operation ID 由函数 identity、kind、source span 和关键 symbol 生成，不能只用数组序号。这样在函数前面插入无关语句时，后面的 review/finding 不会全部换 ID。

### 第七步：从 operation 构造 CFG 和 def-use

`src/dataflow/cfg.js` 先按 source span 排序 operation，再构造入口、普通 block、branch edge 和退出关系。最初只用行号比较范围，测试发现同一行内 `if` 后面的 sink 会被错误放入分支，于是比较逻辑升级为 offset 优先、line/column 兜底。

guard 不能因为“出现在 sink 前面”就视为有效。Path Engine 在传播时记录当前 CFG 路径，并检查 guard 所在 block 是否支配到达 sink 的路径。规则层只接收“观察到什么 guard capability”，再判断该能力对当前漏洞是否充分。

例如 `path.normalize()` 可以产生 normalization 事实，但路径穿越规则不会因此直接判定安全；只有路径被限制在可信根目录等 confinement capability 才能满足对应规则。

### 第八步：编写函数摘要和有限调用解析

跨函数分析没有反复遍历所有 callee AST，而是先由 `function-summary.js` 为每个函数计算摘要，例如：

```text
参数 0 → return
参数 1 → command sink
HTTP source → return
参数 0 → request.url property
参数 0 经过 PATH_CONFINEMENT guard
```

`call-resolver.js` 再按 symbol、名称、receiver、参数数量、import 和文件关系建立有界候选。能唯一解析时使用较高置信度；动态调用存在多个候选时保留 heuristic step 并降级，不能为了生成完整路径强行猜一个目标。

`path-engine.js` 负责把 source seed 放入工作队列，沿 def-use、call argument、return 和摘要边传播。为了防止递归、循环和大项目爆炸，状态键包含函数、operation 和 taint symbol，并设置路径深度、候选数和总探索预算。达到预算时返回 `truncated` metadata，而不是静默截断后假装分析完整。

### 第九步：把漏洞判断从路径搜索中拿出来

早期代码在找到调用时直接决定“是不是 SQL 注入”。重构后，Path Engine 只输出事实路径，`rule-engine.js` 再用声明式定义判断：

```text
Source + Propagator + Sink + Rule-specific Guard/Sanitizer
```

这样同一条路径可以被不同规则解释，数据流也不需要知道 SQL、SSRF 或路径穿越的具体充分条件。首批规则只迁移命令注入、SQL 注入、路径穿越、SSRF 和不安全反序列化，并为每条规则准备 vulnerable/safe 成对样本。

### 第十步：把 Worker 从一次性计算改为持久状态

第一版 Worker API 只有 `analyze(analyses)`，每次都需要把工作区结果整体复制过去。重写时先让 `worker.js` 内部持有唯一的 `WorkspaceAnalysisEngine`，然后逐个增加消息类型：

```text
initializeWorkspace
updateFile
removeFile
reanalyzeAffectedFunctions
configure
queryPaths
```

`worker-client.js` 保存发送给 Worker 的文件快照和配置。Worker 崩溃或超时后，客户端重新创建线程，并通过 `initializeWorkspace` replay 状态。相同文件的连续 update 使用 cancel key 丢弃旧 Promise；真正的计算取消仍受 JavaScript 同步任务限制，因此分析代码还要依靠合并请求和较小失效范围控制队列长度。

这里特别避免把 TypeScript AST、Tree-sitter node 或 Checker object 通过 `postMessage` 发送。它们留在 Worker 内部，主线程只传文件文本、版本和配置，返回可序列化的 finding delta。

### 第十一步：接入增量缓存和失效传播

`incremental-cache.js` 以文件版本、函数摘要和依赖函数为核心，不以“文件是否保存过”作为唯一 cache key。`workspace-engine.js` 接到更新后执行：

```javascript
const previousDependents = project.dependentsOf(path);
project.update(file);
const nextDependents = project.dependentsOf(path);

for (const dependent of union(previousDependents, nextDependents)) {
  reparse(dependent);
  invalidateChangedSummaries(dependent);
}

reanalyzeAffectedFunctions();
```

取前后 dependents 并集很重要：一个 import 被删除后，新依赖图里已经找不到旧消费方，如果只读取更新后的图，陈旧 IR 永远不会失效。删除文件同理，必须在 `project.remove()` 之前保存反向依赖。

函数摘要变化后继续沿 callers 传播，但只重算受影响集合。入口绑定也被视为依赖：路由文件增加或删除 imported handler 注册时，即使 handler 源码没变，它的 taint seed 和 finding 仍要更新。

### 第十二步：最后接回 Controller、Review 和 SARIF

引擎稳定前没有立即大改 UI。接回时由 `audit-controller.js` 负责文件事件和命令生命周期，分析逻辑仍留在 Worker/engine。Controller 收到 delta 后更新模型，`audit-providers.js` 只把模型转换为树节点和 CodeLens。

`review/targets.js` 直接使用 IR `symbolKey` 构建 target，`review/status-store.js` 负责旧 ID 迁移和 orphan 清理。只有完整扫描成功才能执行全量清理，单文件增量结果不能证明其他历史 target 已经不存在。

`sarif.js` 使用与 UI 相同的 finding，不重新扫描代码。这样 IDE、导出结果和未来 CI/headless 入口不会产生三套不同结论。Source → Sink steps 被写入 SARIF code flow，finding fingerprint 使用稳定语义身份。

### 一个阻断 Bug 的实际修复过程

“AST 前端整体静默失效”最能说明后期是如何调试的。实际处理顺序是：

1. 完整测试出现 24 个失败，直接调用 AST Frontend 得到 `dedupeFrameworkEntries is not a function`；
2. 对照 `tree-sitter-frontend.js` 的 import 和 `framework-entries.js` 的 `module.exports`，确认是重构后的调用方与旧模块契约不一致；
3. 继续查看失败测试，发现问题不止缺两个 export：测试已经要求 `handlerIndexes`、动态路由、Go 链式 method 和参数 provenance；
4. 没有只补空函数让异常消失，而是先统一 `classifyFrameworkCall()` 返回结构；
5. 重写 entry 去重和 parameter role 推断，再让 Tree-sitter Frontend 展开多个 handler；
6. 同步修改 TypeScript Frontend，使用 Checker 解析 imported handler；
7. 先跑 framework entry 和 AST language 聚焦测试，再跑完整套件；
8. 增加 `frontend.mode === "ast"` 和 `degraded === false` 断言，确保 fallback 不会把结构性故障伪装成成功；
9. 最后打包 VSIX，检查 WASM/runtime 存在并在 Extension Host 中实际加载。

这次修复留下的工程规则是：任何存在 fallback 的主链测试，都必须同时断言“输出结果”和“实际执行模式”。否则 fallback 越可靠，主实现失效时反而越不容易被发现。

### 框架语义闭环后的第二次边界加固

六项框架语义任务完成、110 项测试全绿后，又针对测试盲区手工构造了非典型调用。没有直接继续加规则，而是分别检查 `entryPoints`、parameter role 和最终 finding。第二轮稳定复现了三个缺口：

1. JavaScript 动态路由能保留 `<dynamic>`，但 PHP `Route::get($route, ...)`、C# `MapGet(route, ...)` 和 Go `HandleFunc(route, ...)` 仍被分类器直接丢弃；
2. `app.use(auth, handler)` 把第一个 middleware 误认为动态路径，`app.use(handler)` 甚至没有入口；
3. C# 参数虽然能根据 `CommandService` 类型判断 service，却不能识别 `[FromQuery]`、`[FromRoute]`、`[FromHeader]` 和 `[FromBody]`。

处理时先在 `framework-entries.test.js` 和 `release-blockers.test.js` 写出失败用例，确认六个新增断言均会失败，然后再修改实现：

- PHP、C#、Go 与 JS 使用相同的未知路径语义，无法静态求值时保留 `<dynamic>`；
- TypeScript `callDetails()` 使用 Checker 判断每个参数是否指向函数声明，将结果作为 `handlerArguments` 交给分类器；
- Express `use` 在第一个参数确认为 handler 时使用 `<all>`，并从参数 0 开始绑定全部 middleware；第一个参数不是 handler 时仍按动态路径处理；
- provenance 模式扩展到 Java 注解和 C# binding attribute，优先使用显式声明，再回退到参数类型和 unknown。

之后继续增加 imported handler 的 alias、namespace、default import 和 barrel re-export 场景。barrel 用例会修改真正的 handler 文件，并断言 `handlers.ts → index.ts → routes.ts` 的反向依赖全部重解析，旧 finding 被删除。

最终聚焦测试 29/29、完整测试 116/116 通过。这一轮说明“需求列表已经实现”不等于边界已经闭合；完成主路径后还要主动构造各语言不对称、API overload 和模块导入变体。

### 每次写完一层后如何验证

代码不是全部写完后一次测试，而是按层推进：

| 修改内容 | 先跑的聚焦验证 | 再跑的系统验证 |
| --- | --- | --- |
| IR/schema | `ir.test.js`、schema validation | 全部 Frontend 输出都能投影 |
| Tree-sitter | `tree-sitter-languages.test.js` | 七语言 AST mode、无静默 fallback |
| TypeScript Program | `typescript-frontend.test.js` | 多文件类型变化与 ScriptKind |
| 框架入口 | `framework-entries.test.js` | `release-blockers.test.js` 跨文件 fixture |
| CFG/dataflow | `core-rules.test.js`、`rule-engine.test.js` | 单行/多行不变性、safe/vulnerable 对照 |
| 增量 Worker | `incremental-cache.test.js`、`dataflow-worker.test.js` | 1,000 文件与 TS fan-out benchmark |
| Review/SARIF | `status-store.test.js`、`sarif.test.js` | 路径移动、部分扫描、状态迁移 |
| 发布包 | `scripts/verify-packaged-runtime.js` | Extension Host、离线 VSIX 安装 |

实际执行顺序保持为：聚焦测试 → `npm test` → `npm run check` → benchmark → Extension Host → package → packaged-runtime verification。只有前一层稳定，才继续改下一层。

### 0.7.1：把分散的追踪动作统一成审计查询

0.7.0 已经能够生成 Source → Sink Finding，但交互仍分散在“选中变量追踪”和“跨文件路径”两个入口中。它们的数据结构、展示方式和中断说明不同，无法回答“谁调用这里”“这个函数能否追到入口”“为什么分析停在这里”等人工审计问题。

0.7.1 的实现没有在 Controller 中再写七套搜索逻辑，而是先定义统一查询协议：

```text
Query request
  { kind, absolutePath, line, identifier, maxDepth, maxNodes }
        ↓
Persistent Workspace Worker
        ↓
IR function / operation / call index
        ↓
Expandable query tree
  { label, status, reason, location, details, children }
```

具体开发过程如下：

1. 在 `src/query/audit-query-engine.js` 建立纯分析模块，先实现 `Trace Backward`、`Trace Forward`、`Find Callers`、`Find Callees`、`Trace to Entry Point`、`Show Reachable Sinks` 和 `Explain Analysis Here` 七种 `QueryKind`。模块只消费统一 IR，不读取 VS Code 编辑器，也不依赖某个语言 AST。
2. 使用现有 `ir-adapter` 和 `call-resolver` 建立函数、incoming call、outgoing call 和 unresolved call 索引。这样查询结果与 Finding 使用同一套调用消歧逻辑，不会出现 UI 追踪能连上、规则引擎却连不上的两种结论。
3. Backward 查询从当前 Access Path 寻找最近的赋值、Source、调用返回、参数和 caller argument；Forward 查询沿赋值目标、调用参数、返回值、Guard 和 Sink 扩展。属性路径通过 rebasing 处理，例如 `req.body.cmd → value → options.command`，同时保证 `options.safe` 不会被同对象的 `options.command` 污染。
4. 每个节点必须带 `verified`、`syntax-only`、`heuristic` 或 `unresolved`，并提供自然语言 `reason`。达到深度、节点或循环限制时保留停止节点，而不是直接把路径截断成看似完整的结果。
5. 将 `queryAudit` 接入 `WorkspaceAnalysisEngine`、Worker 协议、Worker Client 和 `AuditSession`。查询直接在持久 Worker 的最新文件表上执行，文件保存后不需要把整个 workspace IR 再复制到 Extension Host。
6. 在 `audit-providers.js` 增加 `AuditQueryProvider`，将统一结果递归投影为可展开路径树。任意节点点击后通过统一 location 跳转源码，tooltip 同时展示连接理由和 IR 事实。
7. 在 `audit-controller.js` 只处理编辑器上下文、命令生命周期、剪贴板和文件导出。七个动作全部调用 `executeAuditQuery()`，旧 `Trace Selected Variable` 保留为 Forward alias，避免已有快捷键突然失效。
8. 增加 Finding 搜索和 Problems Diagnostic 映射；Debug JSON 导出当前文件的 frontend、IR、findings、query 与索引状态；Markdown 导出递归保留每一步的置信状态与原因。
9. 先写纯引擎测试，覆盖跨文件 entry → service → sink、unresolved call 和 sibling Access Path 隔离；再写 Worker 测试，证明查询读取的是增量更新后的 IR；最后在真实 Extension Host 中执行更新、查询、路径树接入、Debug JSON 序列化和 Problems 映射。

这一版刻意没有把 Tree View 变成新的分析器。UI 只消费协议，程序理解仍留在 Frontend、IR、call resolver 和 Worker 中。后续加入框架语义或更精确的数据流时，七个命令可以自动获得相同改进。

### 0.7.2：把项目知识编译成审计语义

真实项目最常见的缺口不是少一个通用 CWE，而是分析器不认识内部封装：输入可能来自 `getTenantValue()`，命令执行经过 `internalExec()`，URL 校验藏在公司自己的安全库中。0.7.2 因此没有继续修改内置 Pattern，而是建立 `.traceguard.json` 到 Semantic Model Registry 的编译链。

实际编码按以下顺序完成：

1. 新建 `src/config/project-config.js`，先限制配置为 256 KiB、版本 1、最多 200 个模型和 100 个排除模式，再解析 JSON。解析结果不是直接交给 Frontend，而是返回 `{ valid, config, issues }`；任何 error 都让整次配置更新失败，防止只加载一半模型。
2. 将 Source、Sink、Sanitizer、Propagator 和 Wrapper 统一编译成现有 `SemanticRole` 模型。Sink 参数位置变成 `taintArguments`，Sanitizer capability 通过 `guardAssociation()` 得到 applicable sink、output/receiver scope 和 semantic-proof 要求。
3. 为配置生成整体、semantic、rule 和 exclude 四种 fingerprint。整体 fingerprint 用于热更新判断；只有 semantic fingerprint 变化才重建 AST/IR，单纯关闭规则或覆盖 severity 只重新运行 Dataflow/Rule Engine。
4. 修改 `resolveSemanticCall()`，将自定义模型和内置模型放进同一个候选集。JS/TS 继续使用 Checker 验证 module、alias 和 shadowing；Java/Python/PHP/C#/Go 使用 import、qualified name 和 receiver type。只有函数名的模型被标成 syntax-only，不能作为需要符号证明的高置信 Sanitizer。
5. 在两个 AST Frontend 的 call operation 和 signal-candidate 路径都传入自定义 Registry，避免“普通调用能识别、Pattern 候选却看不到配置”的分叉。Pattern fallback 不伪造符号证明，解析降级时配置语义也随能力等级降低。
6. `WorkspaceAnalysisEngine` 在分析文件时把模型放进 Frontend options；`pipeline` 和增量合并路径把 rule controls 放进 `evaluateFlowPaths()`。规则关闭会产生 finding removal delta，severity 修改会产生 upsert delta，UI 不需要重新扫描或单独修结果。
7. `AuditSession` 负责从每个 workspace root 读取配置并原子合并。错误配置保留上一次有效 fingerprint，并把 source、JSON path、line/column 和错误原因交给 Controller；文件不存在等价于空配置，不产生噪声。
8. 自定义 exclude path 同时进入 VS Code `findFiles` exclude glob 和最终相对路径过滤。保存已排除文件时会把旧 analysis 从 Worker 删除，不能因为增量入口绕过全量扫描过滤。
9. `audit-controller.js` 监听配置保存、创建、删除和重命名，维护独立的 Configuration DiagnosticCollection。项目已经全量索引时，排除范围变化会重新发现 workspace；只索引过当前文件时，只重建已有文件，避免保存配置意外触发大扫描。
10. 打包 `resources/traceguard.schema.json` 并注册 `jsonValidation`，让 VS Code 在用户输入时提供字段、枚举和类型提示。`Open Project Audit Configuration` 命令只在用户触发时创建最小模板。
11. 测试先验证 schema 编译和非法配置原子拒绝，再验证 Worker 中的 custom Source → Propagator → imported Sink、精确 Sanitizer、规则开关、severity、alias、shadowing 和 Java receiver。receiver 对照测试实际发现 `logger.execute()` 被 `CommandService.execute()` 模型误绑，随后把 qualified name 改成包含 receiver type 才修复。
12. 最后在 Extension Host 中真实写入配置、更新 Worker、生成 custom Finding、跳过 excluded file，再故意写坏 JSON，确认 Problems 出现配置错误且上一次有效模型仍在运行；测试结束恢复原文件并清理 fixture。

这套实现的关键约束是：`.traceguard.json` 提供项目知识，但不能绕过语义证明。名字相同只产生候选，只有 module、qualified symbol 或 receiver type 对上，才允许成为 verified 的安全事实。

## 当前代码是怎样拼起来的

0.7 形成的主链和主要实现位置如下：

| 层 | 主要职责 | 关键实现 |
| --- | --- | --- |
| Extension/UI | 激活、命令、视图、配置与生命周期 | `extension.js`、`src/audit-controller.js`、`src/audit-providers.js` |
| Language Frontend | AST 解析、函数/调用/入口提取、降级 | `src/frontends/registry.js`、`tree-sitter-frontend.js`、`typescript-frontend.js`、`pattern-parser.js` |
| Project semantics | TypeScript Program、模块依赖、跨文件 symbol | `src/frontends/typescript-compiler.js`、`src/frontends/framework-entries.js` |
| Unified IR | 文件、函数、operation、位置、identity 契约 | `src/ir/schema.js`、`src/identity.js` |
| Incremental engine | 文件状态、缓存、失效范围、持久 Worker | `src/analysis/workspace-engine.js`、`incremental-cache.js`、`src/dataflow/worker.js`、`worker-client.js` |
| Dataflow | CFG、def-use、调用解析、函数摘要、路径传播 | `src/dataflow/cfg.js`、`path-engine.js`、`function-summary.js`、`call-resolver.js` |
| Rules | Source、Propagator、Sink、Guard/Sanitizer 语义 | `src/rules/definitions.js`、`rule-engine.js` |
| Product result | Finding 合并、review 状态、SARIF 与覆盖信息 | `src/review/`、`src/sarif.js` |

一份文件保存后的实际执行过程是：

```text
VS Code 文件变化
  → controller 发送 updateFile
  → Worker 更新该文件 AST 与 IR
  → workspace engine 查询反向依赖
  → 失效受影响函数摘要和入口绑定
  → 重建局部 CFG / def-use / 调用候选
  → path engine 传播 taint
  → rule engine 判断漏洞专用 guard/sanitizer
  → 返回新增、更新和删除的 findings
  → UI 合并结果并保留人工 review 状态
```

## 实际采用的开发与验收流程

0.7 后期不再采用“看到问题直接补一个正则”的方式，而是按以下闭环处理每个缺陷：

1. **用最小代码稳定复现。** 同时记录 frontend mode、函数 IR、entry point、CFG block、路径和 finding，确认问题发生在哪一层。
2. **先增加会失败的回归用例。** 对格式问题同时提供单行、多行版本；对数据流规则提供 vulnerable/safe 成对样本；对增量问题记录变更前后的消费方 IR。
3. **修负责该语义的模块。** 语法问题进 Frontend，位置和操作进 IR，传播问题进 Dataflow，漏洞充分性进 Rule，框架约定进 Framework model，避免在 controller 里打补丁。
4. **先跑聚焦测试。** 例如 framework entry、Tree-sitter language、release blocker 或 worker/incremental 测试，缩短调试反馈。
5. **再跑完整测试和语法检查。** 防止一个语言的修复破坏另一个 frontend 或 fallback。
6. **检查真实运行模式。** 不只检查“有没有 finding”，还断言使用的是 AST、是否降级、降级原因和能力等级。
7. **执行性能、Extension Host 和 VSIX 验证。** 检查主线程耗时、增量时间、内存、Worker 生命周期、WASM/runtime/许可证是否真的进入安装包。
8. **最后用真实项目人工复核。** 自动化测试保证已知问题不回归，真实项目负责发现测试语料没有覆盖的框架约定和误报模式。

发布相关操作单独放在开发流程之外：先完成本地改动和验证，再由维护者审核变更内容；只有明确确认后才整理 commit、tag、Release 或 Marketplace 发布。

## 制作过程中确认的工程原则

1. **AST 只负责看懂语法，框架语义必须单独建模。** 能识别调用节点不等于知道哪个参数是 handler、哪个参数来自 HTTP、哪个对象是 DI 服务。
2. **IR 是唯一分析契约。** 规则和数据流不能依赖 Tree-sitter、TypeScript AST 或某种语言节点。
3. **无法确定时保留结果并降低置信度。** `<dynamic>` 路由和 unknown parameter 比静默漏报更适合人工审计工具。
4. **身份必须来自语义，不来自行号。** 文件移动、代码插入、重载和匿名回调都不能串 review 状态。
5. **增量失效不仅是文件依赖。** 类型、入口绑定、函数摘要和被删除模块都会改变其他文件的语义。
6. **格式不应改变审计结论。** 多行、单行、注释和字符串必须进入回归测试。
7. **规则数量服从路径质量。** 先把命令注入、SQL 注入、路径穿越、SSRF、不安全反序列化做准，再扩展规则族。
8. **Extension Host、性能和打包产物都是产品测试。** 单元测试通过不代表 VSIX 中的 WASM、许可证、Worker 和运行时一定完整。

## 0.7 正式发布前还要做什么

0.7 进入功能冻结阶段后，只处理发布阻断问题：

1. 用多个真实开源项目运行 `0.7.0-rc.1`，记录漏报、误报、降级解析和内存；
2. 扩充七语言、跨框架、跨文件 vulnerable/safe 语料，单独记录 precision/recall；
3. 对入口绑定、类型变化、文件删除、路径移动和连续保存执行 Extension Host 回归；
4. 验证 VSIX 离线安装、升级迁移、SARIF 导出和第三方许可证；
5. RC 阶段不增加新规则，只修 P1/P2 和明显性能回退；
6. 用户验收后再整理提交、打 tag 和发布正式版。

## 接下来的开发路线

### 0.7.3：路径可信度——已经完成的开发过程

0.7.3 没有增加新的 CWE，目标是回答一个更基础的问题：路径树中相邻的两步为什么能够连接。实现不是在原有字符串集合上继续加特殊判断，而是从 IR 到 UI 统一重做值身份和传播证据。

#### 第一步：先用反例定位旧模型的边界

最先写的是几组会让旧引擎出错的最小样本：

```ts
const alias = payload;
exec(alias.command);       // 应追到 payload.command
exec(alias.safe);          // 不应因为 command 被污染而误报

let command = req.body.cmd;
command = "fixed";
exec(command);             // 精确覆盖后不应保留旧污点
```

这两组样本暴露出两个根因：旧实现主要保存变量名，无法表达“对象的哪个字段”；赋值只增加污点，从不撤销已经被覆盖的定义。于是先冻结预期结果，再修改引擎，而不是用 finding 数量判断修复是否成功。

#### 第二步：把 Access Path 抽成公共 IR 契约

新增 `src/ir/access-path.js`，统一规范化属性、引号键、数字下标和动态下标：

```text
request["body"].cmd  → request.body.cmd
items[0].url         → items[0].url
items[index].url     → items[*].url
```

这个模块同时定义 path 是否包含、是否相交、如何计算相对路径以及如何在别名之间 rebase。Frontend、Path Engine 和 Audit Query 都改用同一份实现，避免三处各自拆字符串后得出不同结论。PHP 超全局字段保留自己的根身份，防止 `$_SERVER.REQUEST_METHOD` 与 `$_SERVER.QUERY_STRING` 被折叠。

#### 第三步：区分三种赋值，而不是把所有表达式看成同一种传播

赋值 operation 增加了传播模式：

- `alias`：`b = a`，把 `a` 的所有已污染子路径重映射到 `b`；
- `aggregate`：对象、数组、模板或拼接表达式，只在子表达式实际读取污点时污染输出；
- `fallback`：通用 Tree-sitter 语言无法精确拆解时使用，只允许有方向的保守传播，不把同根 sibling 字段互相污染。

同时实现 strong update：对一个精确 Access Path 的新定义会清除该路径及其旧子路径。这里曾发现一个回归——Source 与 assignment 共用同一条语句时，strong update 把刚创建的 Source 也清除了。最终通过识别“同一 Source 定义同一值”保留初始事实，并加回归用例锁住行为。

#### 第四步：传播证据跟着 Access Path 走

旧实现主要回答“这个变量是否在 tainted 集合里”。新实现为每个路径保留来源证据，生成 finding 时把以下字段写进 propagation step：

- `analysisStatus`：`verified`、`syntax-only`、`heuristic` 或 `unresolved`；
- `propagationKind`：alias、assignment、collection、call、return、capture 等；
- `propagationReason`：为什么输入能够到达输出；
- `inputAccessPath` / `outputAccessPath`：传播前后的精确值身份。

Rule Engine 和交互式 Backward/Forward Query 使用同一份证据。启发式边会降低 finding confidence；未解析调用只展示为中断原因，不会伪装成 verified 路径。

这一轮还抓到两处“证据被覆盖”的问题：宽泛的 receiver 污染会掩盖精确 collection 证据；同一调用同时投影成 call 与 assignment 时，后者会覆盖前者。修复后保留最具体的 modeled-call/collection 证据，并新增断言确保 finding 的 Source 仍是真正 Source，而不是中途的语法候选。

#### 第五步：用 TypeScript Checker 建模集合读写

TypeScript Frontend 不再仅凭方法名猜测 `set`、`get` 或 `push`。它先读取 receiver 类型，再输出集合 operation：

- `Map.set(key, value)` 与 `Map.get(key)` 使用同一个精确键路径；
- 无法静态求值的键进入 `[*]`，并降低证明强度；
- 数组 `push`、`unshift`、`splice`、`fill`、`at`、`pop`、`shift`、`join` 等声明各自的输入、输出和 receiver effect；
- `Set.add` 以及 collection 的 `keys`、`values`、`entries` 明确记录传播方向。

测试不仅检查危险元素能够到达 Sink，也检查安全 sibling、覆盖写和无关元素不会被带上。这样“召回提高”不能靠把整个容器一律标脏来实现。

#### 第六步：闭包捕获变成真实调用边

对嵌套函数，TypeScript Checker 会比较符号声明作用域，找出来自外层函数的 captured symbol。Frontend 把捕获值作为角色为 `capture` 的 IR 参数，并从外层生成带精确 `targetFunctionId` 的合成 closure call。

因此：

```ts
const cmd = req.body.cmd;
queue.push(() => exec(cmd));
```

不再依赖“两个函数里都出现了名为 cmd 的变量”这种猜测，而是沿 capture 参数和确定的闭包目标传播。调用路径会显示 `explicit closure target` 作为连接依据。

#### 第七步：跨类调用先消歧，再保守保留接口候选

函数 IR 增加 `implementedTypes`，调用 operation 保存 receiver type。Call Resolver 的选择顺序调整为：

1. 明确的 `targetFunctionId`；
2. receiver 类型与 enclosing type 精确匹配；
3. receiver 接口与实现类的 `implementedTypes` 匹配；
4. 最后才使用已有的文件、导入和名称启发式。

同一文件中两个类拥有同名方法时，receiver 类型可以选出唯一目标。接口存在多个实现时，不强猜某一个：保留有界候选集，并把解析质量标为 `review`。这避免动态分派带来静默漏报，也不会把一个不确定候选宣传成高置信调用。

#### 第八步：回归、检查和真实产物验证

0.7.3 新增或加强了这些测试族：

- Access Path 规范化、包含关系、动态元素与 sibling 隔离；
- 容器别名、strong update 和同语句 Source 定义；
- typed Map/array 的精确传播及 finding 解释；
- 闭包捕获和精确目标边；
- receiver type 同名方法消歧；
- interface 多实现的有界候选和 ambiguity 标记；
- Backward/Forward Query 与 Finding 对同一边给出相同理由；
- semantic model 的 Source 和 unresolved call 证据不被中间 operation 覆盖。

开发顺序始终是失败样本、模块级修复、聚焦测试、完整回归、静态检查、coverage/benchmark、Extension Host、VSIX 解包核验。最后一轮完整回归为 167/167；版本产物只有在 runtime、WASM、配置 Schema 和许可证都能从实际 VSIX 中找到时才算完成。

0.7.3 仍有明确边界：Promise/async 调度、事件监听器、复杂 loop、exception/finally CFG 与开放世界 virtual dispatch 没有被假装成“已经精确支持”。这些场景继续通过状态和中断原因暴露不确定性，后续用真实语料逐步补充。

### 0.8.0：公共内核与 Java 主链

原计划把公共内核作为 0.7.4 单独发布，但实际开发中 CFG 改动会同时影响 Finding、Backward/Forward Query、函数返回传播和所有语言。为了避免先发布一个过渡版本，再让 Java 依赖尚未冻结的内核，最终把两部分合并为 0.8.0：先稳定公共控制流，再打穿第一门 Tier A 语言。

#### 第一轮：用条件赋值复现线性扫描错误

最先写入的失败样本不是新 Sink，而是 Java、PHP、Python 三份等价代码：一个分支把 HTTP 输入赋给 `command`，另一个分支赋常量，汇合后调用命令执行。旧 Path Engine 按源码顺序处理 assignment，最后出现的安全赋值会覆盖另一条分支的污点，代码只要交换 then/else 顺序就可能从有告警变成无告警。

修复时没有给 assignment 加特殊判断，而是让数据流按 CFG 可行路径分别执行。`cfg.js` 先把条件内部的 Guard/Call 作为真实 condition block，再从条件尾部分出 true/false 边；分支尾回到 join，每条路径独立执行 strong update，最后合并 Finding。这样安全分支不会抹掉危险分支，危险分支也不会污染只存在于安全路径的状态。

#### 第二轮：补循环、异常和提前终止

IR 增加 `throw`、`break` 和 `continue` operation；Tree-sitter 与 TypeScript Frontend 从 AST 发出相同控制操作。CFG 随后增加：

- `for`、`while`、`do` 和 foreach 的循环回边与零次执行出口；
- `continue` 回到循环条件，`break` 跳到循环 join；
- `try` 正常边、多个 `catch` 异常入口、`else/finally` 汇合；
- `throw` 到最近异常处理器，没有处理器时到函数出口；
- `return` 后操作标成不可达，不再进入 Finding 和 Reachable Sinks Query。

实现中曾出现一个具体回归：CFG 从 branch 直接跳到 then body，导致条件表达式里的 Guard block 变成不可达，已有路径约束全部失效。修复方式是显式建立 `branch → condition operations → true/false`，并重新跑全部 Guard dominance 样本，而不是把 Guard 恢复成“只要在 sink 前面就生效”。

#### 第三轮：统一 Finding 与审计查询的传播事实

此前 Path Engine 和 `audit-query-engine.js` 各自实现 assignment 输入、输出、Access Path rebase 和解释文字。0.8.0 新建公共传播模块，统一输出：

```text
input Access Path
→ assignment mode
→ output Access Path
→ verified / syntax-only / heuristic / unresolved
→ reason
```

同时建立公共 control-flow event sequence。Source-to-Sink、函数返回分析、Backward/Forward 和 Reachable Sinks 都从同一 CFG 可达性与传播事实读取事件。查询不再展示已被早返回截断的 Sink，Finding 与 Query 对同一 alias/aggregate 边给出同一理由。

#### 第四轮：把 Java 类型层写入 IR

Java Tree-sitter Frontend 从 enclosing class/interface/record AST 读取 `extends`、`implements`、声明类型和方法是否拥有可执行 body，并写入 Function IR。调用解析不再只比较方法名和文件名，而按以下证据排序：

1. receiver 具体类型；
2. receiver 接口与实现类 `implementedTypes`；
3. 可执行实现优先于只有签名的接口声明；
4. 参数个数；
5. 字符串、数值、构造表达式、参数和局部 typed receiver 推导出的参数类型；
6. 最后才使用导入、目录和名称启发式。

这一轮的测试同时放置同名重载、接口声明和实现类，要求 HTTP 输入只能进入匹配的 `String` overload，不能因为同名方法进入另一个安全/危险路径。

#### 第五轮：AST 原生 Spring/JAX-RS/Servlet 入口

Java 入口不再只依赖方法前八行正则。Frontend 直接读取 method/class modifiers 中的 annotation node：

- Spring `Get/Post/Put/Delete/PatchMapping` 与 `RequestMapping`；
- JAX-RS `GET/POST/...` 与 `Path`；
- Servlet `doGet/doPost/...` 和 `HttpServlet` 继承关系。

类级 `/api/tools` 与方法级 `/run` 在语义层合成为 `/api/tools/run`，参数继续通过 `@RequestBody`、`@RequestParam`、`@PathVariable`、`@RequestHeader` 和类型推断得到 body/query/path/header/request/service 等 provenance。Pattern 结果只在 AST 没有绑定到函数时补位。

#### 第六轮：打穿 Controller 到 Mapper

JavaBean getter 被投影为字段级 Access Path，例如：

```text
body.getCommand()
→ body.command
→ ToolService.run(command)
→ ToolServiceImpl.run(command)
→ ToolMapper.find(name)
```

Mapper 注解专门区分 MyBatis `${name}` 与 `#{name}`。前者是动态文本替换，生成 `java.mybatis.dynamic-sql` SQL Sink；后者是绑定占位符，不生成该 Sink。Sink operation 保留 annotation 的跳转位置，但通过 `functionAnnotation` 参与方法数据流，因此接口方法即使没有 body，也能接收调用方传来的参数并解释到 Mapper 声明。

#### 第七轮：补 Java 现有规则族的语义模型

0.8.0 没有新增 CWE，而是为已有命令注入、SQL 注入和 SSRF 规则补符号/receiver 约束：

- `Runtime.exec`、`ProcessBuilder`；
- JDBC `Statement`、JPA `EntityManager`、Spring `JdbcTemplate`；
- Spring `RestTemplate`、WebFlux `WebClient.uri`；
- MyBatis 动态 SQL annotation。

这些模型定义污染参数位置、receiver 类型、限定名和 SinkKind。同名业务方法只能作为低置信候选，不能伪装成框架 Sink；MyBatis 绑定占位符、安全常量和不匹配的 overload 都有对照样本。

#### 第八轮：0.8.0 回归门槛

新增 `common-kernel-java.test.js`，覆盖三门 Tier A 语言的条件赋值、早返回不可达、循环/异常边，以及完整 Java 多文件 fixture。固定路径为：

```text
Spring Controller
→ @RequestBody DTO field
→ Service interface
→ ServiceImpl
→ Mapper interface
→ MyBatis dynamic SQL Sink
```

开发过程仍按“失败样本 → 模块级修复 → 聚焦测试 → 全量测试 → 静态检查 → coverage/benchmark → Extension Host → VSIX 解包核验”推进。只有源码版本、package lock、README/CHANGELOG、运行时依赖、WASM、Schema、许可证和实际 VSIX 一致时，0.8.0 才算完成。

### 0.8.1：PHP 项目语义

下一版只集中处理 PHP，不同时扩 Java/Python 规则：

- Laravel/Symfony Route → Controller → Request → Service；
- Composer PSR-4、Namespace 与 `use ... as ...`；
- 类方法、继承、Interface、Trait 和有限动态调用；
- PDO、Doctrine、Guzzle、文件与 Shell Sink；
- 无法解析的 magic method、container resolve 和动态 method name 给出明确中断原因。

验收 fixture 必须跨 namespace 和文件，包含安全参数绑定、同名类、Trait wrapper、动态调用中断及 vulnerable/safe 对照。

### 0.8.2：Python 项目语义

随后单独打穿 Python：

- Flask、FastAPI、Django 入口与参数 provenance；
- Pydantic、Dataclass 和 dict 字段 Access Path；
- 包/相对导入、alias、类方法、继承和装饰器 wrapper；
- `*args`、`**kwargs`、async/await、context manager、closure 与跨模块返回；
- DB-API、Django raw、subprocess、文件、HTTP、反序列化、模板与 XML Sink；
- SQL 参数绑定、`shlex.quote` 返回值作用域、可信根目录、URL allowlist、safe loader、defusedxml 和字段级 validation。

目标 fixture 是：

```text
@router.post("/fetch")
→ Pydantic body.url
→ async service.download()
→ httpx.AsyncClient.get(url)
→ SSRF Finding
```

0.8.2 完成后再回到 Java/PHP/Python 循环提高，不把七门语言重新拉回平均投入。

## 暂时不做

- 不在 VS Code 插件内重造 CodeQL 级全局数据库；
- 不一次性扩充几十个浅层漏洞规则；
- 不把外部 CLI、云服务或代码上传变成强制依赖；
- 不宣称七种语言拥有相同深度，能力等级必须如实展示；
- 不为了“零误报”静默丢弃不确定入口和路径。

后续版本仍应围绕同一个标准推进：**结果是否能帮助用户更快地确认一条真实、可解释、可复现的安全路径。**
