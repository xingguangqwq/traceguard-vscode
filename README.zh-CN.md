# TraceGuard 白盒审计

[English](README.md)

TraceGuard 是一个给白盒审计用的 VS Code 插件。它帮你理清接口入口、排出该先看哪些代码、把变量在函数之间怎么传的搞清楚,再把审计过程里的判断记在代码旁边,省得回头去另一个文档里翻。

漏洞成不成立它不下结论。输入能不能被外部控制、中间的防护够不够、这条路径实际能不能利用,这些得靠人结合业务自己判断,插件只负责把线索摆出来。

> 下面的 GIF 和截图都是 TraceGuard 分析当前 Hack The Box Python/PHP 题目源码时的实际输出,不是界面示意图。

![TraceGuard 实际审计流程](docs/images/traceguard-audit-flow.gif)

## 大致流程

先看 **Scope**,确认接口入口和索引范围没有遗漏。

再看 **Review Queue**。它按能不能从入口触达、有没有敏感操作、解析有没有中断,把该先读的代码排出来。

进到某段代码后用 **Trace**,顺着变量往前查调用者、往后查被调用者,连带控制条件一起看,一直追到最后落在哪个 Sink 上。

看完写 **Notes**,把可控性是怎么判断的、缺了哪些上下文、利用条件是什么、结论是什么记下来。

### Scope 和 Review Queue

Scope 会列出入口数量、实际索引到的文件、跳过的文件,以及被预算截断的路径。Review Queue 分 P0、P1、P2 和 Backlog,点目标会跳到对应函数,状态自动切成 In review。

![真实项目中的 Scope 和 Review Queue](docs/images/traceguard-review-queue.png)

### Source → Sink Trace

在这个项目里,`/generate` 接口的 URL 参数被追成了这样一条三步路径:

```text
request.args.get('url')
  → scrape() 调用 peek_website(url, timestamp)
  → driver.get(url)
```

Trace 侧栏会同时显示每一步的证明状态和源码位置。切步骤时编辑器直接跳到 Source、跨函数调用或最后的 Sink,不用自己来回翻文件。

![真实 Source 到 Sink 路径](docs/images/traceguard-trace-sink.png)

### Notes

选中关键代码,可以把它记成 Controllability、Missing Context、Exploit Condition、False Positive Reason 等类型。截图里记的是 `driver.get(url)` 的可控性判断,笔记保留文件和行号,以后点一下就回到现场。

![真实审计笔记](docs/images/traceguard-notes.png)

## 功能

按请求方法和路由把 HTTP、Controller、框架入口理一遍,做攻击面梳理。

审计队列分 P0、P1、P2、Backlog。这只是阅读顺序,跟漏洞严不严重没关系,别搞混。

Source 到 Sink 的路径会展示数据源、赋值、调用、返回、控制条件,一路到最后的敏感操作。

支持几种交互查询:Trace Origin、Trace Uses、Callers、Callees、Trace to Entry、Reachable Sinks。

每一步分析都标了可信程度,分 `verified`、`syntax-only`、`heuristic`、`unresolved` 四档。不确定的就标不确定,不会硬说成已验证。

索引没覆盖到的地方也会告诉你:跳过的文件、只索引了一部分、路径被截断、某个调用解析不出来,都摆出来。不会因为没查出问题就让你以为代码是干净的。

Reviewed、False Positive、Accepted Risk、Suppressed、Needs Context 这些是你自己标的审计状态,跟工具自动分析的结果分开存,不会互相覆盖。

代码片段可以直接存成笔记,标成可控性说明、利用条件、缺失上下文或修复建议,方便回头看。

项目自己的 Source、Sink、Sanitizer、Propagator 定义,以及规则开关和要排除的路径,都写在 `.traceguard.json` 里,自己配。

整个过程在本地跑,代码不离开 VS Code,插件也不会去执行被审计的项目。

## 结果怎么理解

**Verified Flow**:从 Source 到 Sink 这条链路证据比较完整了,但能不能真的利用,还是你说了算。

**Review Hypothesis**:这条路径值得看,但中间有些调用、类型判断或取值传播还没完全证明。

**Dismissed / Resolved**:审计员已经给这条路径下过结论,不用再看。

再说一遍,P0/P1/P2/Backlog 只排阅读顺序,不是严重度评级。默认只有 Verified Flow 会进 VS Code 的 Problems 面板,其他的不打扰你。

## 各语言支持程度

Java 覆盖得比较全:Spring MVC、JAX-RS、Servlet,package/import 关系,接口实现,JDBC/JPA/MyBatis,以及文件操作、反序列化、命令执行、HTTP 调用这些常见 sink。

PHP 覆盖 Laravel、Symfony,Composer 的 PSR-4 自动加载,PDO/MySQLi,DB/Eloquent 的 raw query,文件、反序列化、cURL/Guzzle、命令执行。

Python 覆盖 FastAPI、Flask、Django,Pydantic 字段校验,DB-API/SQLAlchemy,文件、pickle/YAML、subprocess、HTTP 客户端。

JS/TS 保留完整 AST,项目级的 import、闭包、回调都能分析。

C# 和 Go 目前到框架入口、调用关系、局部数据流这一层,比前面几种语言薄一些。

Java、PHP、Python 的语法解析资源内置,离线就能审后端代码。其他语言首次使用时会去装,也可以自己配私有镜像源。

## 安装

去 [Releases](https://github.com/xingguangqwq/traceguard-vscode/releases/latest) 页下 `traceguard-vscode-1.0.0.vsix`,在 VS Code 里跑 **Extensions: Install from VSIX** 就行。

```powershell
code --install-extension .\traceguard-vscode-1.0.0.vsix
```

打开一个你信得过的源码目录,别拿来跑不明来源的代码。

## 开始审计

打开侧栏,点 **Build Review Queue**。开始前最好先看一眼 **Scope**,确认索引完整,不然队列可能有遗漏。

从 **Review Queue** 里挑一个开始看,选中代码用编辑器里的 **TraceGuard >** 菜单,让它解释这段代码或者追踪某个值。Trace 展开后,点任意一步都能跳到对应代码。

看完把关键代码存进 **Notes**,顺手把审计结论写上,不然过阵子自己都忘了当初怎么判断的。

## 自定义项目规则

跑 **TraceGuard: Open Project Audit Configuration**,会在项目根目录生成一份 `.traceguard.json`:

```json
{
  "version": 1,
  "sources": [
    {
      "language": "php",
      "function": "tenantInput",
      "returnsTaint": true
    }
  ],
  "sinks": [
    {
      "language": "php",
      "function": "internalExec",
      "arguments": [0],
      "kind": "COMMAND_EXEC"
    }
  ],
  "excludePaths": ["vendor/**", "generated/**"]
}
```

每个工作区根目录各存各的,互不影响。写错了会提示,但不会拿这次的错误配置覆盖上一次能跑的。

## 用之前该知道的

TraceGuard 做的是本地静态分析,预算有限,不会无限跑下去。文件太大或路径太深会被标成部分结果甚至跳过;遇到动态分派、反射、生成代码,或者依赖装不全,追踪链路也可能中断。

所以**没跑出结果,不代表这块代码没问题**,这点务必留意。

版本改动看 [CHANGELOG.md](CHANGELOG.md)。

[提交问题](https://github.com/xingguangqwq/traceguard-vscode/issues) · MIT License
