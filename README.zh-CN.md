# TraceGuard Local SAST

[English](README.md)

TraceGuard 是一个本地运行的 VS Code 代码审计插件。它会生成审计队列，并为 Java、PHP、Python 等受支持语言展示候选 Source → Sink 路径。

它给出的是待复核候选，不是已经确认的漏洞。

![TraceGuard 审计队列和代码提示](docs/images/traceguard-code-review.png)

## 安装

1. 从 [Releases](https://github.com/xingguangqwq/traceguard-vscode/releases/latest) 下载 VSIX。
2. 在 VS Code 中运行 **Extensions: Install from VSIX**。
3. 打开一个受信任的源码目录。

```powershell
code --install-extension .\traceguard-vscode-0.9.0.vsix
```

## 使用方法

1. 点击活动栏里的 TraceGuard 图标。
2. 选择 **Build Review Queue**，建立工作区索引。
3. 先看 **Attack Surface** 和 **Potential Findings**，再依次检查 P0、P1、P2。
4. 通过 CodeLens 或命令面板向前/向后追踪选中的值，查询 callers、callees、入口和可达 Sink。
5. 点击路径步骤可跳转到对应代码。
6. 将 Finding 标记为已复核、误报、接受风险或忽略。
7. 按需导出审计笔记、审计会话或 SARIF。

## 怎么看结果

- **Attack Surface** 展示路由、Controller 和其他外部入口。
- **Potential Findings** 按规则和最终 Sink 组织候选安全路径。
- **Review Targets** 用 P0、P1、P2 安排人工阅读顺序；它们是审计优先级，不是漏洞严重等级。

展开 Finding 可以查看完整 Source → Sink 步骤。每一步都会显示文件、函数和证据状态：

- `verified`：有直接 AST、类型或模块证据。
- `syntax-only`：语法结构匹配，但缺少完整的项目级证明。
- `heuristic`：存在合理候选，需要人工确认。
- `unresolved`：无法安全继续解析调用或数据流，路径在这里停止。

LOW/REVIEW Finding 会在 receiver 或调用目标无法完全证明时保留下来，但它们不能成为可信 Guard，也不会静默压掉其他 Finding。

## 语言重点

- **Java：** Spring MVC、JAX-RS、Servlet、package/import、接口实现、JDBC/JPA/MyBatis，以及常见命令和 HTTP Sink。
- **PHP：** Laravel、Symfony、Composer PSR-4、PDO、DB/Eloquent raw query 和命令执行。
- **Python：** FastAPI、Django、Pydantic 字段、DB-API/SQLAlchemy、subprocess 和 HTTP 客户端。
- JavaScript/TypeScript 继续支持 AST 和项目级分析；C#、Go 保留常见 AST 与框架入口能力，但分析深度较低。

## 项目配置

运行 **TraceGuard: Open Project Audit Configuration** 可创建 `.traceguard.json`，配置项目自己的 Source、Sink、Guard、规则开关和排除路径。

```json
{
  "version": 1,
  "excludePaths": ["vendor/**", "generated/**"],
  "rules": {
    "potential-command-injection": { "severity": "high" }
  }
}
```

每个工作区根会独立保存自己的配置和上一次有效状态。配置错误会显示在 Problems 中，不会阻断其他工作区根的分析。

## 常用设置和边界

- `traceguard.maxWorkspaceFiles`：全量索引文件上限，默认 1,000。
- `traceguard.indexTimeoutSeconds`：全量索引超时，默认 300 秒，设为 `0` 可关闭硬超时。
- `traceguard.liveIndex`：分析未保存的编辑器内容。
- `traceguard.indexOnStartup`：启动时建立工作区索引。

源码只在本地处理，插件不会执行被审计项目。大于 2 MB 的文件会被跳过，覆盖不完整时会明确提示。没有 Finding 不代表项目安全。

版本变化见 [CHANGELOG.md](CHANGELOG.md)。

[提交问题](https://github.com/xingguangqwq/traceguard-vscode/issues) · MIT License
