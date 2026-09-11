# 正确性修复与回归验证

## 本轮边界

这轮修改聚焦可靠性，没有扩语言、重写分析内核或发布新版本。语言资源仍使用现有 1.0.0 Release 地址。

### Worker 恢复

- 新请求先等工作区重放完成，不能仅因为线程已创建就读空索引。
- 取消、关闭扩展会立刻拒绝等待恢复的请求。
- 旧恢复任务迟到的文件读取不能覆盖新 Worker 的元数据。

### 文件变更同步

- 监听文件系统事件，而不只监听编辑器保存；每 250 毫秒合并同一路径的事件。
- 队列最多保留 1000 个文件事件，溢出改成一次受文件配额约束的完整扫描。
- 超过 32 个文件的批次、工作区根变更、项目配置变更走完整扫描。
- 单文件按处理时的磁盘状态同步，处理删除后重建、目录删除和未保存文本优先。
- 未开始审计的工作区不会仅因磁盘事件启动扫描。
- 同步中/失败时显示 Results pending refresh，暂不展示旧 Problems 诊断；失败后可手动刷新，下一次文件事件也会触发重试。
- VS Code 的 `files.watcherExclude` 仍可能屏蔽事件；此时用 Refresh Code Review Index。

### 笔记

- 新增、删除、导入、重命名迁移和定位更新串行写入，避免慢存储覆盖并发修改。
- 不再静默截断到 500 条，也不再只导入前 1000 条笔记。
- 打开笔记时按原始代码片段重新定位，重复片段尝试用前后文消歧。
- 片段不存在、文件删除或定位歧义时标记 stale，保留快照，不猜测旧行号。
- 旧版本笔记没有前后文锚点时，仍可通过唯一片段定位。

## 评测约定

`eval-corpus/manifest.json` 中默认检查所有输出规则。未匹配预期的告警计入误报，`expected: []` 表示负例，而不是“不检查”。

如果某个样例只评估部分规则，必须显式提供非空的 `checkedRules`；预期规则必须在其中。不要用规则范围隐藏未知误报。

基线样例消失、命中减少、误报增加、verified 路径减少都会失败。路径可信状态复用 UI 的统一判定，不再单独猜测。

目前语料包含 66 个场景：Java、PHP、Python 各 22 个，合计 33 个正例和 33 个负例。覆盖命令执行、SQL、路径、SSRF、反序列化，以及常量覆盖、分支、别名、跨文件传播。这些是本地最小回归样本，不代表真实仓库总体准确率。

`baseline-1.1.0.json` 固定全部场景的检出、误报和路径证明统计。已知只有语法或启发式证据的样本通过 `allowedProofStatuses` 显式声明，并必须说明 `proofLimitation`；不能因此接受 unresolved 路径。原有未知 PDO receiver 场景仍保留其 unresolved 基线。

`scripts/build-backend-corpus.js` 可重新生成新增的 60 个文件场景，预期由声明决定，不读取分析结果，也不改写基线。评测输出增加 `byLanguage` 和 `byRule`；分组 precision/recall 只表示当前样本集。

## 执行

PowerShell 下使用 `npm.cmd`，避免 `npm.ps1` 被执行策略阻止：

```powershell
npm.cmd test
npm.cmd run check
npm.cmd run eval:compare
npm.cmd run benchmark:java
npm.cmd run benchmark:php
npm.cmd run benchmark:python
npm.cmd run benchmark:stress
npm.cmd run package
npm.cmd run verify:package
```

Extension Host 冒烟使用独立临时工作区，不再改动开发仓库的 `.traceguard.json`；其运行命令为 `npm.cmd run test:extension-host`。
