# dsh-cmd-guard 审计进度

最后更新：2026-11-09 16:30

> 经验与规矩已独立到 `LESSONS.md`。本文件只记录「现在在哪」，不记录「为什么」。
> **根因一律标注「已证实」或「推测」，不得混写。**

## 当前基线（实测，非估算）

- `npm run build`：通过，无 error（`build` 现在先清 `lib/` 再编译）
- `npm test`：**292 tests / 292 pass / 0 fail**
- 语料：`test/attacks.json`、`attacks-2.json` ～ `attacks-8.json`（**8 个，共 256 条**），`schema` 统一为 `3`
- `scripts/`：**1 个文件**（`sync-policy.mjs`），临时脚本已全部清除
- `npm pack --dry-run`：**36 个文件 / 54.5 kB**，无 `.map`
- 消费者验收：解包后按插件挂载，`pre-execute` 瀑布 **5/5 通过**
- **结论：功能面与发布面均已验收通过，可发布 0.1.0**

## 审计轮次记录

| 轮次 | 攻击角度 | 结果 | 冻结 |
|---|---|---|---|
| 1–2 | 词法拼写、包装器（env/nice/sudo/timeout） | 归零 | `attacks-2`～`-5` |
| 3 | 命令头可以是任何程序（反转白名单） | 归零 | 同上 |
| 4 | 豁免集本身（逐条去干最坏的事） | 48 条归零 | `attacks-6.json`（48） |
| 5 | why 能否解锁不可恢复删除 | 51 条归零 | `attacks-7.json`（51） |
| 6 | 工具身份、路径越界、Unicode 混淆、嵌套 | 41 条 0 不一致 | `attacks-8.json`（38） |
| 7 | 冻结期暴露的入参形状问题 | 4 项全修 | 并入 `attacks-8` + 单测 |
| 8 | 语料元数据与发布面（本轮） | 全部定性并结清 | 无新增攻击语料 |

## 架构层面的四处关键改动

1. **反转白名单**：不枚举危险命令，只枚举已知安全的豁免集；不在豁免集里就按能力判（目标敏感度 + 参数形状）。
2. **归一化前置**：`canonicalCommand` 位于流水线最前，做 NFKC 折叠、删除零宽/软连字符/控制字符，处理 `$IFS`，递归剥离包装器（深度上限 4）。
3. **why 不再是万能钥匙**：`WHY_IRRECOVERABLE` 使不可恢复操作不接受理由解锁。
4. **硬拒优先于软问**：entry 层给 ask 时，rules 再过一遍，`deny` 可覆盖 entry 的 `ask`（A1 修复）。

## 已修卡点

### B5 — 已修（旧文档根因记错）

```
copy a.txt C:\Windows\System32\drivers\etc\hosts
修前 ask / 修后 deny
```

- 旧文档记的根因：`copy` 不在 `MUTATION_VERBS` 里 → **已证伪**
- 实际根因（已证实）：`copy` 一直在 `MUTATION_VERBS` 里。`RULE_SYSTEM_PATH_MUTATION`（ask）分支在前先 return，`RULE_CRITICAL_SYSTEM_WRITE`（deny）永远走不到
- 修法：把 `RULE_CRITICAL_SYSTEM_WRITE` 提到 `RULE_SYSTEM_PATH_MUTATION` 之前
- 连带修正 4 条背书 bug 的老语料：`M-003` `M-004` `M-005` `W4-A8`，期望由 ask 改为 deny

### A1 — 已修（未知工具名洗白硬拒）

- 现象：`tool=newtool` + `del /s /q C:\` → ask
- 根因（已证实）：entry 层对未知工具直接 ask 并 return，rules 的硬拒没机会跑
- 修法：见架构改动第 4 条
- 连带：`mount.test.ts` 中 `some_future_shell` 断言拆为两层——危险命令走 rules deny，无害命令仍由 entry 层标记

### 命令键崩溃 / 命令键歧义 — 已修

- `verify({tool:'bash', command:'...'})` 抛 `TypeError`：`canonicalCommand` 对 undefined 调 `.normalize()`
- 两个命令键同时存在时判的是安全那个，真正会执行的没人看
- 根因（已证实）：`entry.ts` 的歧义检查注释写着「须在工具名分支之前」，实际排在 `if (input.tool === undefined) return null` **之后**。直调 `verify` 不带工具名时整段检查从未执行
- 修法：`canonicalCommand` 容忍非字符串；`cmd` 缺失回落读 `command`；`verify` 自行推导命令键；歧义检查前置到工具守卫之前
- 注意：mount 层原本做了映射，线上流量未受影响，但 `verify()` 是导出接口，不能靠调用方守规矩

### attacks-8 的三条空档 — 已由单测补齐

| 形状 | 覆盖方式 | 期望 |
|---|---|---|
| A1 工具名不洗白命令 | `mount.test.ts` | deny |
| A2 双命令键歧义 | `mount.test.ts` | ask；双键皆危险时 deny |
| A3 `content` 数据键藏命令 | `mount.test.ts` | pass（数据不是命令行） |

## 本轮（第 8 轮）：语料元数据与发布面

### layer 字段：不是错标，是没定义 — 已定性

批量核对 256 条，**47 条「声明 layer ≠ 实测 layer」，但 0 条 verdict 漂移**。逐条归因：

| 类别 | 条数 | 定性 |
|---|---|---|
| deny 类 | 26 | `rules` 是 deny 的唯一出口，`verify` 不变量强制如此 |
| pass 对照组（`clean`） | 16 | 无 finding 的合法取值 |
| note 已写明跨层（`N-004`、`I-023` 等） | 3 | 写的时候就说清了 |
| `R-007` `rm -rf ./build` | 1 | rules 先 ask，note 原文「it lands in the why layer instead」 |
| `W-002` `shutdown /r /t 0` | 1 | 已证实：`policyChange` 在 rules 层先 ask，why 层没机会参与 |

结论（已证实）：`split.ts` 解链后**故意保留内层 `layer:'rules'`**，`verify` 的 asymmetry 检查依赖这一点；runner 也明确不校验 layer（`guard.test.ts` 头注释）。所以这是**两义混用**，不是标注错误。

处理：
- README 新增「语料里的 `layer` 是什么」，写明它是**攻击面分桶**、不是返回层
- `clean` 无需改：`types.ts:81` 本来就是 `Layer | 'clean'`
- 新增断言：八批 `schema` 必须一致（已用 tamper 验证会红，验证后恢复）
- `corpus integrity` 补上 `capability`（语料里本有 40 条，此前的覆盖断言漏了它）

### 发布面 — 已结清

| 欠账 | 处理 | 证据 |
|---|---|---|
| I-023 层标注 | 不改语料，改文档（见上） | README「语料里的 layer」 |
| `description` | `Six layers` → `Eight layers` | 实际 8 层：entry/rules/capability/split/obfusc/unwrap/interp/why |
| `files` | 保持 `lib/src` + patch + README + LICENSE | `npm pack` 36 files，无测试、无源码 |
| `sourcemap` | 保持 `sourceMap: false`；真问题是 `lib/` 陈旧 `.map` 进包 | 根因（已证实）：`npm pack` 打 `lib/` 目录，旧构建残留不会自动消失。修法：`build` 前 `clean`。修后包内 0 个 `.map`，63.0 kB → 54.5 kB |
| changeset | **决定不引入** | 仓库无 changeset 基础设施，0.1.0 首版无升级说明可写；用 `prepublishOnly: npm test` 保证发布前全绿 |
| `interp_policy` | 已实现且已文档化，销账 | `interp.ts` 按路径来源判定；README「解释器判据」8 种情形 |

### README 过期表述 — 已修

- 「七层结构」→「八层结构」，表格补 `capability` 行
- 两处依赖数字的表述改为不依赖数字（「分层结构、逐层判定」「各层各自的攻击形态」），避免加层后再过期

## 未决卡点

### C8 — 定性为 ask，不修

三层 `bash -c` 套娃，第二层引号被拆散，第三个 `bash -c` 不再构成「主机 + 标志」形状。当前判定 **ask**，不是静默放行，且该串实际执行到不了 `rm -rf /`。已写入 README 残余风险第 9 条。

## 发布前最后一步

```
npm test          # 292/292
npm pack --dry-run   # 36 files, no .map
```

两条都对即可发 0.1.0。
