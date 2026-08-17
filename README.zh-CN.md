# TraceGuard Code Audit Helper

[English](README.md)

第一次审计一个项目，通常会卡在第一步：文件很多，不知道先看哪里。TraceGuard 会在 VS Code 里整理一份阅读队列，标出值得留意的输入、敏感操作和校验位置，并帮你记录已经看过的内容。

它不会直接告诉你“这里一定有漏洞”。代码怎么走、限制是否有效，仍然需要你自己判断。

![TraceGuard 审计队列与代码行内线索](docs/images/traceguard-code-review.png)

## 三分钟上手

1. 从 [Releases](https://github.com/xingguangqwq/traceguard-vscode/releases/latest) 下载 `traceguard-code-audit-helper-0.5.0.vsix`。
2. 在 VS Code 中运行 **Extensions: Install from VSIX**，选择刚下载的文件。
3. 打开一个受信任的源码目录。
4. 点击活动栏里的 TraceGuard 代码路径图标。
5. 点击 **Build Review Queue**，从第一个 P0 或 P1 目标开始看。

也可以在 PowerShell 中安装：

```powershell
code --install-extension .\traceguard-code-audit-helper-0.5.0.vsix
```

## P0、P1、P2 怎么看

这些等级只是阅读顺序，不是漏洞等级：

- **P0 — Review first：** 同时出现入口、外部输入、敏感操作等强线索，建议先看。
- **P1 — High attention：** 有比较明显的安全相关代码，适合接着检查。
- **P2 — Review queue：** 其余值得阅读的函数。

打开一个目标后，可以按这个顺序检查：

1. 找入口：路由、Controller、Handler、命令入口或文件级执行代码。
2. 找输入：请求参数、Header、Cookie、消息内容、文件名等。
3. 追变量：看它经过了哪些赋值、条件和转换。
4. 找敏感操作：数据库、命令执行、文件、网络请求、反序列化等。
5. 看防护：输入校验、编码、身份认证和权限判断是否真的覆盖了这条路径。
6. 记下结论，把目标标记为已检查，再看下一个。

## 一个简单例子

```php
function read_file() {
    $name = $_GET['name'];
    return file_get_contents('/uploads/' . $name);
}
```

第一次看这段代码，不用急着套漏洞名称，先问四个问题：

- `$_GET['name']` 是不是外部可控？
- 它有没有进入文件读取操作？
- 拼接后的路径有没有规范化，并限制在指定目录？
- `../` 或绝对路径能不能改变最终读取的文件？

TraceGuard 可以帮你标出输入和文件操作，但是否真的能够利用，还要结合调用位置和周围代码确认。

## 阅读代码时常用的功能

- **Trace Selected Variable：** 按源码顺序查看变量的输入、赋值、条件、校验和敏感使用位置。
- **Show Security Clues Here：** 查看当前函数里有哪些审计线索。
- **Add Selection to Audit Notes：** 保存一段关键代码并写下原因。
- **Mark Current Target Reviewed：** 标记当前目标已经检查。
- **Export Audit Notes：** 导出 Markdown 审计记录。

## 支持语言

- Java / JSP
- PHP
- JavaScript / TypeScript
- Python
- C#
- Go

插件根据源码文本和常见框架写法整理线索。动态调用、项目自己的封装以及生成代码，仍然可能需要手动查找。

## 隐私和边界

- 不上传源代码。
- 不执行被审计项目。
- 不依赖 Python 或 Web 服务。
- 出现行内提示，只代表这里值得检查，不代表已经确认漏洞。
- 队列全部看完，也不代表项目一定安全。

导出的审计会话可能包含你主动保存的代码片段，分享或提交前记得检查。

## 开发

```powershell
npm install
npm test
npm run check
npm run package
```

使用 VS Code 打开插件目录，按 `F5` 启动 Extension Development Host。

[提交问题](https://github.com/xingguangqwq/traceguard-vscode/issues) · [参与开发](CONTRIBUTING.md) · MIT License
