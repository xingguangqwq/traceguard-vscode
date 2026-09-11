# TraceGuard 1.1 更新说明

## 使用变化

- **Changed since review**：在 Review Queue 筛选中查看需要重新复核的目标。代码、已解析的被调依赖或分析配置变化后，原人工结论保留在提示里，目标重新进入待审状态。
- **Needs re-review**：发现项旧的 False Positive、Accepted Risk、Suppressed 等结论失效时重新打开，避免继续隐藏变更后的路径。明确重新标记后才接受当前版本的结论。
- **断链处补模型**：点击 Trace 的断链提示，检查调用者所调用的目标，或添加项目 Source、Sink、参数到返回值的 Propagator 模型。保存后自动重新计算查询，未知身份仍标为不确定。
- **按根目录更新**：项目语义模型改变时，重新解析所属工作区根目录，并重算相关依赖；其他根目录的前端分析保留。

当前指纹采用文件及其依赖粒度，同文件其他函数、注释或路径位置变化也可能要求复核。旧会话没有指纹时保留原结论并提示重新确认。迁移到不同绝对路径的工作区也可能触发复核。

## 修正的分析问题

PHP/Python 常量字符串赋值过去可能未进入 IR，导致已被覆盖的变量继续污染 Sink。本版补齐这类赋值，并修正 Forward Query 在递归追踪别名时跳过后续覆盖的问题。扫描结果与交互查询有共同回归测试。

没有任何路径步骤的结果不再进入 Verified Flow。人工配置的低可信模型可以辅助追踪，但不能因为配置存在就自动取得符号级证明。

## 本机验证（2026-09-11）

- 257 项 Node 测试通过；69 个运行时 JavaScript 文件语法检查通过。
- 66 个本地评测场景，33 个预期发现全部检出，0 个误报，1.1 基线对比无回退。
- 评测包含 26 条 verified、16 条 heuristic（含语法级证据）和 1 条 unresolved 路径。一项发现可以有多条路径；这些数字不是发现数量。
- Java/PHP/Python 千文件增量 P95 约 55/66/113 ms；带审计指纹的 Java 编辑器模式约 69 ms。TypeScript 百文件依赖失效和 Java 8000 文件压力检查通过。
- 本机真实 Extension Host 尚未通过：缓存的 1.90.0 在启动时退出；本机已安装版本报告正在更新而拒绝启动。新增真实界面回归已放入现有 CI 冒烟流程，不能把本机尝试视为通过。

这些评测是最小回归样本，不代表真实仓库总体准确率。Java 部分 JDK 接收者、Python `open()` 和 PHP include 全局函数的证明能力仍有限，已在评测里保留明确说明。

## 复验

```powershell
npm.cmd test
npm.cmd run check
npm.cmd run eval:compare
npm.cmd run benchmark:review
npm.cmd run test:extension-host
npm.cmd run package
npm.cmd run verify:package
```
