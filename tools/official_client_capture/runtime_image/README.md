# ARM64 抓包运行时

该目录保存 Codex 官方客户端取证所需的最小镜像配方。镜像不内置账号、OAuth
凭据、官方 CLI 或 Campaign 工具；它们分别通过受管只读／私有挂载提供。

构建后必须记录 image ID 与 `repository@sha256:<digest>`，正式 Campaign 只接受
后者。运行容器至少需要以下挂载：

- `/root/oauth-capture:/capture` 与 `/root/oauth-capture:/root/oauth-capture`；
- `/root/oauth-capture/runtime/codex-<version>:/opt/codex-<version>:ro`；
- 独立的 Codex／Claude／MITM 状态目录；
- Docker socket 与只读 Docker CLI，供 direct 抓包 sidecar 使用。

Codex 自执行路径不得放在 `/root/...`。0.149.1 及后继版本的文件系统 helper 会在
bubblewrap 内重新执行当前二进制；`/root` 的不可遍历权限会使该步骤返回
`Permission denied`。Campaign 的四个 CLI／code-mode-host 坐标应统一使用
`/opt/codex-<version>/bin/...`。宿主与容器内该目录及所有父目录均须允许其他用户
穿越，二进制和 helper 须允许其他用户读取与执行；OAuth 状态、HOME、CODEX_HOME
和原始证据目录仍保持 `0700/0600`，不得通过放宽 `/root/oauth-capture` 来修复执行问题。
