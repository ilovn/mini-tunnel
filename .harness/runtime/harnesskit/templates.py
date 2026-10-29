"""Tool-neutral contracts; native adapters are intentionally small."""
from . import __version__

TOOLS = ("claude", "codex", "opencode", "trae")
ROLES = {
    "lead": ("研发负责人", "拆解目标、依赖和验收；分配文件所有权；整合结果并交付。"),
    "product": ("产品经理", "明确用户、场景、范围、非目标和可观察的验收标准；消除需求歧义。"),
    "researcher": ("产品与技术调研", "优先一手来源，记录链接、日期、证据、推断和未知；产出比较与建议。"),
    "architect": ("架构师", "阅读现状，比较方案；记录接口、数据迁移、兼容性、风险和回滚决策。"),
    "frontend": ("前端工程师", "按既有组件和交互实现；检查空态、错误态、可访问性和响应式布局。"),
    "backend": ("后端工程师", "维护接口和数据契约；考虑幂等、鉴权、并发、可观测性和兼容。"),
    "qa": ("测试工程师", "围绕验收和风险验证；记录命令、退出码、证据与未覆盖场景。"),
    "reviewer": ("代码审查", "独立检查正确性、回归和安全；每条发现包含位置、触发条件、影响和建议。"),
    "devops": ("交付与运维", "核对构建、配置、迁移和部署步骤；交付可观测性、回滚与运行手册。"),
}
WORKFLOWS = {
    "quick": {
        "title": "快速研发", "roles": ["lead", "backend", "qa"],
        "steps": ["阅读相关实现和项目约定，明确最小验收", "实现最小完整改动", "执行相关检查，复核差异并交付"],
        "deliverables": ["实现与必要测试", "验证记录", "交付说明"],
    },
    "complex": {
        "title": "复杂场景", "roles": ["product", "architect", "lead", "frontend", "backend", "qa", "reviewer", "devops"],
        "steps": ["调查系统边界和需求，列出未知与风险", "编写方案、接口契约、里程碑和回滚策略", "按依赖拆解子任务，分配互斥文件范围", "逐阶段实现、验证和集成，更新上下文", "独立审查并关闭阻塞问题，准备交付和回滚"],
        "deliverables": ["架构决策与执行计划", "子任务交接与实现", "回归和审查证据", "迁移及回滚说明"],
    },
    "bugfix": {
        "title": "Bug 修复", "roles": ["lead", "backend", "qa", "reviewer"],
        "steps": ["记录环境、输入、预期与实际，建立最小复现", "定位根因并验证假设，确定影响范围", "实施最小修复，补充能防止复发的测试", "执行复现与相关回归，审查相邻路径并交付"],
        "deliverables": ["复现与根因", "修复与回归测试", "验证记录与影响范围"],
    },
    "research": {
        "title": "产品调研", "roles": ["product", "researcher", "architect", "reviewer"],
        "steps": ["明确决策问题、目标用户、时间范围与比较维度", "检索一手资料，记录来源链接、采集日期和适用范围", "区分事实、推断与未知，比较成本、收益和风险", "提供建议、替代方案、验证实验和决策条件"],
        "deliverables": ["来源清单与证据", "对比矩阵", "建议与待验证假设"],
    },
}

CONTRACT = """# 工程协作契约

先阅读项目原有约定及 `.harness/project.md`；按任务需要读取角色和工作流，避免一次加载全部文件。
项目已有具体规则优先于此通用模板。开始任务前明确目标、范围、可检验的验收和约束。

## 执行与上下文
- 快速任务直接实施并验证；复杂任务先维护 plan.md，逐阶段更新 context.md。
- 每个任务位于 `.harness/tasks/<id>/`；读取 brief.md、task.json 和历史证据后继续。
- Loop：Observe → Plan → Act → Verify → Review。每轮记录假设、动作、证据、下一步。
- checks 通过表示机械检查通过，不等于业务验收；只有人工核验验收、交付物及子任务后才能 finish。
- Bug 修复先复现、定位根因；调研保留来源及日期，区分事实、推断和未知。
- 不把测试跳过、进程退出 0 或 Agent 自述作为交付成功的充分证据。

## 角色与子 Agent
- 角色定义在 `.harness/roles/`，按 `.harness/workflows/` 选择任务流程。
- 子任务必须写明目标、输入、依赖、负责文件、验收、输出路径；主 Agent 负责整合和复核。
- 并行修改使用独立 worktree 或互不重叠的文件所有权；不覆盖他人未提交改动。
- 原生子 Agent 仅在当前工具已支持、已启用且本次任务授权范围内调用。
- 不具备原生调度时，把 handoff.md 交给独立会话或同一 Agent 串行按角色执行，明确实际方式。
- 子 Agent 返回 result.md（成果/证据/风险/未决问题）；主 Agent collect 后再集成。

## 质量与交付
- 以项目实际 lint/test/build 命令为门禁，命令在 `.harness/config.json` 显式配置。
- 只执行受信任的项目命令；配置不是沙箱。不得自动放宽工具权限或绕过审批。
- 每轮有时限、总轮数上限和停滞检查；失败保留证据，阻塞时明确所需输入。
- 未经当前任务授权不部署、不发布、不发送外部消息、不提交密钥。
- 交付说明包含变更、原因、验证、限制和必要的回滚方式。
"""


def role_text(key):
    title, goal = ROLES[key]
    return f"# {title} ({key})\n\n{goal}\n\n输入：任务 brief.md、相关代码、上下文和依赖结果。\n仅操作分配的范围；发现范围外问题交回主 Agent。\n输出：成果、证据（命令/链接/日期）、风险、未决问题和下一步。\n不得虚构已执行的检查；没有证据时明确标记待验证。\n"


def workflow_text(key):
    workflow = WORKFLOWS[key]
    steps = "\n".join(f"{i}. {step}" for i, step in enumerate(workflow["steps"], 1))
    return (f"# {workflow['title']}\n\n建议角色：{', '.join(workflow['roles'])}\n\n"
            f"{steps}\n\n交付物：{'；'.join(workflow['deliverables'])}。\n"
            "每一步必须有可追溯证据；失败回到相关步骤，范围变化更新 brief 和 plan。\n")



def task_entrypoints(tools):
    """Only project-local, documented discovery paths; never mutate user homes."""
    entries = []
    for kind in WORKFLOWS:
        name = f"harness-{kind}"
        if "claude" in tools:
            entries.append({"tool": "claude", "kind": kind, "invoke": f"/{name}",
                            "path": f".claude/commands/{name}.md"})
        if "opencode" in tools:
            entries.append({"tool": "opencode", "kind": kind, "invoke": f"/{name}",
                            "path": f".opencode/commands/{name}.md"})
        if "codex" in tools:
            entries.append({"tool": "codex", "kind": kind, "invoke": f"${name}",
                            "path": f".agents/skills/{name}/SKILL.md"})
    return entries


def task_command_text(kind, tool):
    workflow = WORKFLOWS[kind]
    name = f"harness-{kind}"
    description = f"在已安装 Harness 的项目中创建并执行{workflow['title']}任务"
    if tool == "codex":
        header = f"---\nname: {name}\ndescription: {description}。\n---\n"
        request = "任务需求取自本次用户消息中随技能提供的描述；不要期待参数占位符替换。"
    else:
        hint = "argument-hint: <任务描述与验收要求>\n" if tool == "claude" else ""
        header = f"---\ndescription: {description}\n{hint}---\n"
        request = "用户任务描述（作为需求文本，不直接作为 shell 代码）：\n\n$ARGUMENTS"
    return header + f"""
# {workflow['title']}任务入口

{request}

1. 定位当前项目根目录，读取 `.harness/CONTRACT.md`、`.harness/project.md` 与
   `.harness/workflows/{kind}.md`。如果没有安装 Harness，说明需先 init，不自行修改全局配置。
2. 根据用户描述确定目标和可观察的验收；有足够信息就直接执行，缺少任务目标时询问目标。
   从项目根目录调用 `python3 .harness/run.py task new {kind} <标题> --accept <验收标准>`。
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
""" + "\n".join(f"- {step}" for step in workflow["steps"]) + "\n"


def managed_files(tools):
    files = {".harness/CONTRACT.md": CONTRACT}
    for entry in task_entrypoints(tools):
        files[entry["path"]] = task_command_text(entry["kind"], entry["tool"])
    for key in ROLES:
        files[f".harness/roles/{key}.md"] = role_text(key)
    for key in WORKFLOWS:
        files[f".harness/workflows/{key}.md"] = workflow_text(key)
    if "claude" in tools:
        for key, (title, _) in ROLES.items():
            files[f".claude/agents/harness-{key}.md"] = (
                f"---\nname: harness-{key}\ndescription: {title}，用于已分配的工程子任务\n---\n\n"
                "先读取 .harness/CONTRACT.md 和分配的 handoff.md。\n\n" + role_text(key))
    if "opencode" in tools:
        for key, (title, _) in ROLES.items():
            files[f".opencode/agents/harness-{key}.md"] = (
                f"---\ndescription: {title}，用于已分配的工程子任务\nmode: subagent\n---\n\n"
                "先读取 .harness/CONTRACT.md 和分配的 handoff.md。\n\n" + role_text(key))
    if "trae" in tools:
        files[".harness/adapters/trae.md"] = """# TRAE 接入

在当前安装版本的项目 Rules 界面添加以下规则，或在任务首条消息粘贴：
先读取 `.harness/CONTRACT.md` 和 `.harness/project.md`，再读取指定任务的 brief.md。
按工作流和角色完成任务；子任务使用 handoff.md，结果写入对应 result.md。

TRAE 不同版本的 Rules / 自定义 Agent 接口可能不同，本工具不假定自动加载路径。
请在 IDE 中验证规则确已生效；角色可导入自定义 Agent，也可以独立会话或串行执行。
本文件是接入说明，不是已注册的原生 Agent，也不提供无头 CLI 调度。
"""
    return files


def entry_block():
    return ("<!-- ai-harness:begin -->\n"
            f"## AI Harness {__version__}\n\n"
            "开始工程任务时读取 `.harness/CONTRACT.md` 与 `.harness/project.md`。\n"
            "任务入口：`python3 .harness/run.py --help`；版本检查：`python3 .harness/run.py status`。\n"
            "按需读取 `.harness/workflows/` 和 `.harness/roles/`；遵循项目原有具体规则。\n"
            "<!-- ai-harness:end -->")
