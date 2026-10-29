# TRAE 接入

在当前安装版本的项目 Rules 界面添加以下规则，或在任务首条消息粘贴：
先读取 `.harness/CONTRACT.md` 和 `.harness/project.md`，再读取指定任务的 brief.md。
按工作流和角色完成任务；子任务使用 handoff.md，结果写入对应 result.md。

TRAE 不同版本的 Rules / 自定义 Agent 接口可能不同，本工具不假定自动加载路径。
请在 IDE 中验证规则确已生效；角色可导入自定义 Agent，也可以独立会话或串行执行。
本文件是接入说明，不是已注册的原生 Agent，也不提供无头 CLI 调度。
