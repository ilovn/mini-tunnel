---
description: 在已安装 Harness 的项目中创建并执行复杂场景任务
argument-hint: <任务描述与验收要求>
---

# 复杂场景任务入口

用户任务描述（作为需求文本，不直接作为 shell 代码）：

$ARGUMENTS

1. 定位当前项目根目录，读取 `.harness/CONTRACT.md`、`.harness/project.md` 与
   `.harness/workflows/complex.md`。如果没有安装 Harness，说明需先 init，不自行修改全局配置。
2. 根据用户描述确定目标和可观察的验收；有足够信息就直接执行，缺少任务目标时询问目标。
   从项目根目录调用 `python3 .harness/run.py task new complex <标题> --accept <验收标准>`。
   使用真实参数安全传递用户文本，避免把需求中的反引号、美元符号或换行当作 shell 代码。
   读取命令返回的任务 ID，再读取其 brief.md、task.json、plan.md 和 context.md。
   用户明确要求继续已有任务时先 task show 对应 ID，按该任务实际工作流续接，避免重复创建。
3. 立即执行工作流，不能停在创建资料。角色按需读取；复杂任务维护计划与依赖，
   使用 task delegate 明确范围和交接。当前平台支持并获授权时调用原生子 Agent，
   否则串行按角色执行并如实记录；主 Agent 复核 result.md 后 collect。
4. 在当前会话中完成 Observe → Plan → Act → Verify → Review，持续更新上下文和证据。
   实现阶段结束运行 `python3 .harness/run.py check <任务ID>`。
   检查失败时结合日志修复重试，读取 config.json 的 loop 配置中 max_rounds、timeout_seconds 和
   stagnation_rounds 作为本会话推进预算；没有门禁时说明待配置，不能宣称通过。
   本入口是 Agent 指令，不是后台调度器；需要可强制执行的超时/轮数时由用户运行 harness loop。
5. 交付时提供任务 ID、变更/调研结论、检查证据、风险和未决问题。
   checks_passed 后仍需负责人确认业务验收再 task finish，不擅自将机械检查通过视为已交付。

流程摘要（详细约定按需读取工作流文件）：
- 调查系统边界和需求，列出未知与风险
- 编写方案、接口契约、里程碑和回滚策略
- 按依赖拆解子任务，分配互斥文件范围
- 逐阶段实现、验证和集成，更新上下文
- 独立审查并关闭阻塞问题，准备交付和回滚
