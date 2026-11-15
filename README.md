# dsh-cmd-guard

DeepSeek Harness 的命令结构解析护栏。

不是一份黑名单，而是一个解析器：把命令字符串拆成分层结构、逐层判定，并且校验模型给出的意图说明与命令本身是否一致。

---

## 快速开始

装进 DSH 宿主：

```bash
dsh plugin --profile web add dsh-cmd-guard
```

`--profile` 是必填项。不带它，`dsh plugin` 在参数解析阶段就退出：
`error: required option '--profile <name>' not specified`。
`web` / `tui` / `headless` 按要挂载的宿主形态选。
本机验证宿主版本：`0.2.2-rc.3`。

想跑断言看判定表，克隆仓库：

```bash
git clone https://github.com/silverwryyy/dsh-cmd-guard
cd dsh-cmd-guard
npm install
npm test
```

装完之后 `dsh` 的配置树里能看到 `cmd-guard`。

### 如果它开始问得太多

判定「相对路径是否在项目内」要靠两个基准：`cwd`（相对路径解析到哪）、
`workspaceRoot`（判断「在不在项目内」时拿哪个目录当项目）。都不配置时，两个都取宿主进程的启动目录。

问题出在 Web：会话能切工作区，宿主进程的目录不会跟着变。会话不在启动目录下时，
工作区里的相对路径会被判成区外，本来 pass 的命令变成 ask。**这不是误报，是基准没给。**

挂载时会打一行 info，直接写明当前用的是哪两个目录：

```
dsh-cmd-guard: relative paths resolve against <cwd>; workspace containment is judged against <workspaceRoot>.
```

对不上就显式指定：

```json
{ "guard": { "cwd": "D:/project", "workspaceRoot": "D:/project" } }
```

只写一个也够，另一个跟着走。两个都没配、又读不到进程目录时，相对路径一律 ask（`unknown-cwd`），
理由里会指出缺的是基准、不是路径。宁可多问一句，也不猜一个基准放过去。

### 如果链式命令问得太密

`a; b && c` 这类命令在默认模式下会整条 ask 一次。想按语句判，开 `guard.chain: decompose`，
见下面「`chain`：链式命令怎么判」一节。默认值没变，不写就是 `strict`。

`npm test` 只在仓库里成立 —— npm 包只含 `lib/src`，不含测试与语料，
`npm install dsh-cmd-guard` 之后没有测试可跑。
`npm install dsh-cmd-guard` 之后没有测试可跑，所以「357 条断言全绿」是仓库内的结果；
外部复现要靠 `git clone && npm ci && npm test`（tag `v0.4.0`），不是装上之后再验证。
从 0.3.0 起 `@deepseek-ai/dsh` 是 optional peer：干净目录实测 `added 1`，不拉宿主、无 peer 依赖；
插件本身零运行时依赖，`--legacy-peer-deps` 不再需要。
完整 headless 启动需要一个可用模型，当前本机没有凭证，见文末「兼容性」里的证据等级说明。

---

## 先说它不做什么

这一节放在最前面，因为它比功能更重要。

- **不读取脚本内容。** 插件不做文件 IO，从不打开解释器要执行的文件。
- **不为文件内容背书。** `python scripts\a.py` 判为通过，意思是「路径来源可解释」，不是「这个文件是安全的」。
- **不是沙箱。** 不隔离进程、不限制系统调用、不做权限降级。
- **不联网。** 不发任何网络请求，不上报任何数据。
- **不是规则库。** 判据建立在命令结构上，名单只是其中一层。
- **不保证模型说清意图。** 详见下一节：官方 schema 已经强制 `description`，所以「必填」不是本事。

---

## 关于「意图绑定」的一次更正

早期版本宣称的卖点是「模型必须说清为什么才能执行」。这个说法**是错的**。

核对 0.2.x 的 `pwsh` 工具 schema 后确认：`description` 本来就是 `required: true`，且有非空校验（`expected a non-empty string`）。模型想通过只要填 `run command`。**把一个已经强制存在的字段再要求一遍，是装饰，不是控制。**

现在做的是对说明的实质校验：

| 情形 | 判定 |
|---|---|
| 空 / 短于 8 字符 | ask（`WHY_MISSING` / `WHY_TOO_SHORT`） |
| 只写了动作、没写目的（`run command`、`do it`、`cleanup`） | ask（`WHY_GENERIC`） |
| 说明是命令原文的复述 | ask（`WHY_RESTATES_COMMAND`） |
| 说明声称是读取，命令却改状态 | ask（`WHY_CONTRADICTS`） |

这比「必填」弱，但**它是真的**，而「必填」不是。

### 一个必须承认的下限

`MIN_WHY_LENGTH = 8`，`sync upstream` 这类凑字数的说明就能解除 ask。

而 DSH 的 `description` 是必填字段，真实宿主里几乎永远带着说明。所以这一层在实战中更像「拦完全空白的调用」，
而不是「保证意图与动作一致」。**它能解除 ask，解除不了 deny** —— 这是有意的不对称。

---

## 残余风险

以下限制是已知的、设计上接受的，写在这里而不是等问题发生后再解释。

### 1. 工作区内脚本可以自己 shell out

`python scripts\build.py` 通过，但 `build.py` 内部完全可以 `os.system("del /s /q D:\\")`。
插件审计的是命令结构，不是程序行为。这是纯函数解析的硬边界。

### 2. 路径来源不等于内容可信

「工作区内相对路径」判为通过，只说明这个路径可以从工作目录解释、没有 `..` 逃逸。
如果工作区本身被写入过恶意文件，这条路径依然通过。**通过 = 可解释，不等于安全。**

### 3. TOCTOU 只覆盖会话内

写后即跑（`INTERP_RECENT_WRITE`）依赖会话内的写入账本。跨会话、或者由会话之外的工具写入的文件，不在覆盖范围内。
`guard.recordWrites: false` 会关掉整条规则，代价见「如果「写后即跑」总在问」一节。

### 4. 混淆检测是启发式

`base64 + exec`、`[char]` 拼接、dunder 动态导入这些信号命中即 ask。换一种编码方式就可能不命中。
它是「提高攻击成本」，不是「保证拦截」。

### 5. 链式命令不拆解

`a && b`、`a | b` 一律 ask，不分别判定两侧。这是有意的：判不了的结构就交给人，而不是假装判过了。

### 6. 平台语法覆盖不均

`cmd` / `powershell` 语法覆盖较全。POSIX shell 的边角语法（heredoc、复杂展开）识别较弱，通常会落到 ask，但不会是 deny。
Windows 盘符根与 POSIX 根 `/` 都在 deny 覆盖内，其他路径形态没有穷举。

### 7. 未知工具的识别靠形状启发式

`bash` / `pwsh` 之外的执行工具，靠「参数里有没有命令行特征」判断。特征是启发式的：
带可执行扩展名的路径、破坏性动词、`/s` `-rf` `--force`、管道接 shell、解释器前缀、命令拼接符。
纯路径（如 `D:/a.txt`）**不算**命令 —— 这一条是实测出的误判修正，不是推测。
反过来，一个形状极不典型的自定义执行工具可能识别不到。所以未知工具命中时判 ask，不判 deny。

### 8. `ask` 在没有审批服务时会退化为拒绝

`PreToolDecision` 的 `ask` 只有在审批服务返回 `allowed-once` 时才继续。
未组合审批服务、或调用没有 agent 时，框架把它降级为拒绝。
也就是说**没装审批 UI 的环境里，ask 等同于 deny**，护栏会显著变严。

### 9. 嵌套引号在第二层会失去结构

三层以上的 `bash -c "bash -c \"bash -c 'rm -rf /'\""`，引号在分词阶段就被剥掉，第二层之后
不再具备「主机 + 标志」的形状，第三层的 `rm -rf /` 识别不到。

实测这类三层套娃判定为 **ask 而不是 deny**。手工验证过，那串命令实际执行也到不了
`rm -rf /` —— 第三层的参数已经不是一条命令。因此没有为它重写分词器。
**多引号嵌套的结论是 ask，不是 deny。**

### 10. capability 层仍然是一份「已知安全」的清单

反转白名单降低了漏判，但没有消除：判定依据仍是信号表（目标敏感度、参数形状）。
**没有任何信号命中的新程序会静默通过。**

豁免集已被实测推翻过六次：`sort -o` 写文件、`rg --pre` 跑程序、`unzip -d` 解包到系统目录、
`setx` / `attrib` 改环境与属性、`net` / `schtasks` 停服务与删任务。
共同教训只有一条：**「看着只读」不是「只读」**。新加进豁免集的工具，第一件事应该是撞它最坏的那个用法。

### 11. Unicode 折叠只覆盖 NFKC 能归一的部分

全角拉丁、零宽空格、软连字符、NUL 在规范化阶段被折叠或剔除，这是实测撞出来的四种。
NFKC 折叠不了的等价写法（同形异码的西里尔字母、部分组合字符序列）不在覆盖内。

### 12. 宿主没有 `ctx.tools.guard` 时，硬拒绝层整体消失

`rules` 层的 deny 是挂在 `ctx.tools.guard` 上的 —— 那个挂载点没有 allow 出口，所以拒了翻不了案。
宿主不提供它时，插件只发一条 warn，然后照常装好、照常响应 `pre-execute`：

- 硬拒绝退化为 ask：`toHardDeny` 无处可挂，`verify` 的 deny 只能从 waterfall 出口出去
- 叠加第 8 条（无审批服务时 ask 等于 deny），两个降级合起来的行为取决于宿主版本，不是插件能保证的

这一层在不在，取决于宿主版本：

| 宿主 | `ctx.tools.guard` | 硬拒绝层 |
|---|---|---|
| `0.2.1-rc.2` 及更早 | 不存在 | 挂不上，deny 退化为 ask |
| `0.2.2-rc.x`（含本机 `0.2.2-rc.3`） | 存在 | 正常挂载，deny 翻不了案 |

**所以「装上了」不等于「拦住了」。** 判据是启动日志里有没有 `ctx.tools.guard is unavailable`。
有这条，就说明当前宿主上 deny 不可信，不能当最后一道闸；没有，就是挂上了。

---

## 八层结构

顺序固定，命中即返回，后面的层不能软化前面的判定。

| 层 | 判定 | 拦什么 |
|---|---|---|
| `entry` | ask | 未知执行工具带着命令行形状的参数；命令参数键名漂移（不是 `command`） |
| `rules` | **deny** | 卷格式化、递归删除系统根或文件系统根（`C:\`、`/`）、删除机器级注册表 hive |
| `capability` | ask | 未知程序的能力信号：指向系统或凭证位置、递归与强制同时出现、代码作为参数、目标由旗标值给出、携带破坏性动词。判断依据是目标与参数形状，不是程序名 |
| `split` | ask，一种结构 **deny** | `\|` `&&` `&` `;` 重定向、`^\|` 转义管道、进程替换 `<(...)`；下载器的输出直接进解释器（`curl … \| sh`）判 deny |
| `obfusc` | ask | base64 解码进 eval、`[char]` 拼接、dunder 动态导入、原生加载器、长十六进制串、词内插入 `^` |
| `unwrap` | ask | 嵌套 shell（`cmd /c`、`powershell -Command`）、`--` 参数透传、`git -c k=v` 配置注入 |
| `interp` | ask | 解释器的内联体、stdin、`-m` 模块、越界路径、临时目录、写后即跑 |
| `why` | ask | 意图说明是占位符、复述命令、或与命令动作矛盾 |

**deny 有两个出口，第二个是白名单。** `rules` 之外，只有 `STRUCTURAL_DENY` 里的码允许返回 deny，目前只有 `SPLIT_PIPE_TO_INTERPRETER`。入选条件是「整串成立、任何单段都不成立」——「这一段执行那一段的输出」读不出来自任何一条语句。其余非 `rules` 层若返回 deny，仍降级为 ask。这条不变式在 `verify.ts` 里是代码，在测试里是断言。

`entry` 放在第一位，是因为它出过一次真实的近失：早期版本按 `run_command` + `cmd` 接线，而实际工具是 `bash` / `pwsh`，参数是 `command`。那种护栏**装得上、启得动、一条都拦不住**，比装不上更糟。

---

## `chain`：链式命令怎么判

```yaml
guard:
  chain: strict      # 默认
  # chain: decompose
```

| 模式 | 行为 |
|---|---|
| `strict`（默认） | 见到 `;` `&&` `||` `|` 就 ask。解析器不为它没读全的结构背书 |
| `decompose` | 拆成语句逐条判；语句内的 `\|` 拆成阶段，阶段同样走完整八层（含 `why`）。全部通过才 pass |

`decompose` 不放宽的部分：

- **deny 优先**：`git status && rm -rf /` 仍是 deny，拆段绕不过 `rules`
- **每段都过意图层**：`git status; git push --force` 仍是 ask。第一段无害不能给第二段免检
- **读不成语句的结构仍 ask**：命令替换 `$(…)`、进程替换 `<(…)`、后台任务 `&`、超过四条语句
- **管道末段把上游当程序执行仍 ask**：`cat payload.sh | sh` 判 ask（`SPLIT_PIPE_TO_STDIN`）。两段单独看都干净，但真正执行的那段代码不写在这条命令里

明确**不拦**的（有意画的边界，不是漏）：`curl … | python setup.py` 判 pass —— 解释器带了脚本参数，管道里的内容是喂给脚本的数据，不是送去执行的代码；`bash script.sh` 同理，它不读 stdin。真正要拦的是没有脚本参数、直接吃流的那种，也就是 `curl … | sh`。

默认值没变：不写 `chain` 就是 `strict`，0.3.0 的行为一字不改。

### 如果「写后即跑」总在问

`guard.recordWrites`（默认 `true`）只控制一件事：把本会话的写入记进账本，喂给 `INTERP_RECENT_WRITE`。
源码里对它的约束是一句注释 —— `it only feeds the TOCTOU rule, so it must never alter a decision`。
它只提供这一条规则的输入，不影响任何其他层的判定。

所以关掉它**不是「少弹一次」**，是让这条规则永远不会命中：

| | `recordWrites: true`（默认） | `false` |
|---|---|---|
| 写后即跑检测 | 生效 | 永不命中 |
| 实际代价 | 脚本刚被本会话写过、随即执行时多一次 ask | 一条规则静默失效 |

宿主侧若把 ask 自动答成 `allowed-once`，关掉它的边际成本接近零；**人工审批的环境里不建议关**。
关之前要清楚关的是规则，不是弹窗。真有噪声，先确认 `chain` 是否配成了 `decompose` —— 那一条的收益比这个大得多。

**patch 层是整体替换，不深合并。** 只想改一个字段，也得把同级的 `guard.enabled` 重述一遍，
否则没写到的字段会回到默认值。这是宿主的行为，不是插件读配置时的处理。

---

## 解释器判据：按路径来源，不按文件是否存在

早期版本按「有没有文件参数」判定，这是个完整绕过：写个文件，再执行它。

现在的判据：

| 情形 | 判定 |
|---|---|
| 工作区内相对路径，无 `..` 逃逸 | pass |
| 内联程序体 `-c` / `-e` / `--eval` | ask |
| stdin / `con` / `/dev/stdin` | ask |
| `-m <module>`（模块选择器，不是路径） | ask |
| 工作区外绝对路径 | ask |
| `%TEMP%` / `AppData\Local\Temp` | ask |
| 任意 `..` 越界 | ask |
| 本会话刚写入、立即执行 | ask |

`python -v` 之类的版本查询是唯一不需要检查路径就放行的形态。

---

## 意图说明的判定

同一个命令字符串，说明不同，判定不同：

```
del D:\temp\a.txt  description: "run command"                    → ask（泛词）
del D:\temp\a.txt  description: "del D:\temp\a.txt"              → ask（复述）
del D:\temp\a.txt  description: "读一下确认没被占用"              → ask（矛盾：声称读，实际删）
del D:\temp\a.txt  description: "删掉构建残留，产物已重新生成"     → pass
```

**说法不能兑换 deny**：`rd /s /q C:\` 配上再详细的理由也还是 deny。

---

## 四态审批

框架的 `PreToolDecision` 是四态，不是三态：

| 结果 | 含义 | 本插件是否产出 |
|---|---|---|
| `allow` | 放行 | 由 `verify()` 的 pass 映射为 `null`（延迟给 `next()`） |
| `deny` | 拒绝，物化为模型可见的错误结果 | 是 |
| `cancel` | 规范化取消，不呈现为策略拒绝 | **否**——这是操作者按停止的意思，不是插件有权做的陈述 |
| `ask` | 转人工，仅 `allowed-once` 才继续 | 是 |

pass 映射成 `null` 而不是 `{kind:'allow'}` 是有意的：`pre-execute` 是 waterfall，返回决策会跳过之后挂载的所有监听器。

---

## 挂载

一个包，一行 `insert`，两个模块：

```yaml
- insert:
    - id: cmd-guard
      name: dsh-cmd-guard
```

实际接线（已对照 0.2.x 类型声明，并在真实宿主中运行时验证）：

| 用途 | 挂载点 | 签名 |
|---|---|---|
| 硬拒绝 | `ctx.tools.guard` | `(exec) => string \| undefined`，无 allow 出口 |
| ask / deny | `ctx.on('tools/pre-execute')` | waterfall `(exec, next) => PreToolDecision` |
| 写入账本 | `ctx.on('tools/post-execute')` | waterfall `(exec, result, next) => PostToolDecision` |

- `guard` 在所有 `pre-execute` 监听器之后、审批之后运行，所以拒了翻不了案，监听器顺序也改不回来
- `guard` 只返回拒绝理由，**不返回 allow**：它没有授予权限的能力，假装有会让护栏误以为自己放行了什么
- 决策形状在运行时不合法时**fail closed**（判 deny）。形状写错的护栏不会报错，只会静默失效，所以宁可拒

`changeset`（自举治理模块）默认关闭，需要 `danger-full-access`，不应该是装上就白送的能力。

---

## 测试

```bash
npm test
```

在 DSH 沙箱里跑可能直接 `EPERM`：`node --test` 默认每个测试文件起一个子进程，沙箱禁管道 stdio。
改在同一进程里跑：

```bash
npm run test:isolated
```

等价于 `node --test --test-isolation=none lib/test/*.test.js`，覆盖同一套 357 条断言。

**357 条断言全绿**：256 条命令语料（分 8 批）+ 101 条结构、挂载、管道与不变量断言。
其中一条是跨目录回归：整份语料在 `os.tmpdir()` 下重跑一遍，判定必须逐条不变。

语料是按轮次冻结的，每一批对应一次「换个角度攻击」，而不是一次随手补样：

| 批次 | 条数 | 撞的角度 |
|---|---|---|
| `attacks` | 37 | 各层各自的攻击形态，含本工作区真实发生过的 `--` 参数透传（`U-003`） |
| `attacks-2` | 6 | 语料外抽查出的漏杀（`git push --force`、`rm -rf /` 曾是静默通过） |
| `attacks-3` | 10 | 工具身份：`bash` / `pwsh` / 未知工具 / 键名漂移 / 意图说明的实质校验 |
| `attacks-4` | 22 | 包装器与变形（`env` / `nice` / `sudo`、`$IFS`、拼接） |
| `attacks-5` | 44 | 命令头可以是任何程序 |
| `attacks-6` | 48 | 豁免集本身：逐条去撞它最坏的用法 |
| `attacks-7` | 51 | `why` 能否解锁不可恢复删除 |
| `attacks-8` | 38 | 工具身份、路径越界、Unicode、结构化嵌套 |

### 语料里的 `layer` 是什么

`layer` 是**攻击面分桶**，不是这条命令最终被哪一层拦下。runner 故意不校验它（见 `test/guard.test.ts` 顶部注释）：同一条命令常由多层可达，钉死层名会把一次合理的重排变成测试失败，而真正不能漂移的是 `verdict`。

因此「声明 `split`、实测报 `rules`」不是错标：`split` 层解开外链后会把内层 finding 原样返回、保留内层层名，这是 `verify` 的「deny 只能来自 `rules`，外加 `STRUCTURAL_DENY` 白名单」不变量所依赖的行为。`layer: "clean"` 表示对照组，预期不产生任何 finding。

`layer` 唯一的硬约束是覆盖度：`entry` / `rules` / `capability` / `split` / `unwrap` / `interp` / `obfusc` / `why` 每层都必须有案例。`schema` 字段不描述行为，八批统一为 `3`，并由测试断言保持一致。

另有结构断言与挂载层断言：

- 语料完整性：id 唯一、层名合法、**deny 只来自 `rules`，或 `STRUCTURAL_DENY` 里的结构码**
- 意图绑定对照组；`U-003` 永不 pass；说法不能兑换 deny；不可恢复删除不接受 `why`
- 挂载层：`command` / `description` 映射、未知工具映射、命令形状识别、pass 必须延迟、
  ask / deny 决策形状合法、**`cancel` 永不产出**、硬拒绝只拒不放
- 语料 runner 表达不了的三种形状（数据键藏命令、双命令键、工具名不洗白命令）以单元测试形式钉住

---

## 明确不拦的

护栏的价值一半在拦了什么，一半在**没拦什么**。以下是已知的放行，不是漏判：

| 输入 | 判定 | 原因 |
|---|---|---|
| `git push --force` + 8 字符以上说明 | pass | 远端历史改写不属本机文件系统；只拦无说明的静默调用 |
| `rm -rf ./build` | ask | `rm` 不在已知工具表，且递归与强制标志同时出现；带说明可解除。`./build` 与 `./src` 判定逐字相同：它只看能力，不看目标 |
| `python scripts/a.py` | pass | 不做文件 IO，从不打开被执行的脚本 |
| `npm ci && npm test` | pass（`decompose`）/ ask（`strict`） | 每段都无害，链本身不构成新风险；`strict` 下只是结构怀疑 |
| 文件读写工具的参数 | 不覆盖 | 只接命令行类工具；`content` 是数据，不是命令 |
| 未来的 `0.2.5-rc.1` 等预发布宿主 | 装不上 | semver 无法通配任意 `-rc.N`，需人工加范围 |

`why` 下限 8 字符，所以「能凑出一句说明」即可解除 ask，但**解除不了 deny**。

### 结构解析的硬边界

护栏读的是命令字符串，不是程序行为。以下几条是设计边界，不是待修项：

- **不认未知写法。** 换一种编码、同形字符（homoglyph）、三层以上引号嵌套，静态规则识别不到。挡得住的是「已经写进规则的写法」。
- **不做语义判断。** `rm -rf ./build` 与 `rm -rf ./src` 判定逐字相同：评的是「递归强制删除 + 目标是否在区外」，不是「这个目录重要吗」。
- **不打开被执行的脚本。** `python scripts/a.py` 判 pass，脚本里的 `os.system("del /s /q D:\\")` 它看不见。
- **只管当前会话。** 跨会话的「写后即跑」没有状态可查，`INTERP_RECENT_WRITE` 只在同一进程内有效。
- **`ask` 在无审批服务时可能退化成 `deny`。** headless 宿主缺审批通道时，上游可能直接当拒绝处理，造成误伤。此条来自宿主侧观察，本仓库未复现，标为待证实。

---

## 兼容性

```
peerDependency: @deepseek-ai/dsh ">=0.2.0-0 <0.3.0 || >=0.2.1-rc.0 <0.3.0 || >=0.2.2-rc.0 <0.3.0"
```

DSH 当前版本线全部是预发布（`0.2.x-rc.*`），`^0.2.0` 匹配不到任何已发布版本，会直接装不上。

预发布还有第二层坑：semver 规定，预发布版本只在范围里显式出现同一 `major.minor.patch` 的预发布标记时才匹配。
所以 `>=0.2.0-0 <0.3.0` 对 `0.2.2-rc.1` 返回 **false**。
0.1.0 里「本范围实测基线为 `0.2.2-rc.1`」那句是错的 —— 实测安装会 ERESOLVE。这句话在 0.1.1 里删掉了，
换成两段并集：`>=0.2.2-rc.0` 显式放行 0.2.2 的预发布线。

0.1.4 又补了一段 `>=0.2.1-rc.0 <0.3.0`，不是顺手放宽，而是 0.2.1-rc.2 原本被排除在外：
它在 `>=0.2.0-0` 里不匹配（预发布要求同 `major.minor.patch` 显式出现），在 `>=0.2.2-rc.0` 里也够不着，
于是 `dsh plugin add` 直接 ERESOLVE 失败。实测三段并集下 `0.2.1-rc.2` 为 true，
`0.3.0-rc.1` / `0.1.9` 仍为 false，上限没有被放宽。

**范围能匹配，不等于宿主功能完整。** `0.2.1-rc.2` 及更早缺 `ctx.tools.guard`，硬拒绝层挂不上；
`0.2.2-rc.x` 有。按版本区分，见「残余风险」第 12 条的矩阵。

实测记录（宿主侧已装 `0.2.2-rc.1`）：

| 项 | 结果 |
|---|---|
| `npm i` 旧范围 `>=0.2.0-0 <0.3.0` | **ERESOLVE**，失败 |
| `npm i` 新范围（0.1.1） | `added 20 packages`，通过 |
| `npm i` 三段并集（0.1.4） | 通过；`0.2.1-rc.2` 与 `0.2.2-rc.1` 均满足，`0.3.0-rc.1` 不满足 |
| 真实宿主运行时（cordis + systemPrompt + tools） | 8 条命令：deny 3 / ask 1 / pass 4 |
| `bash -c "rm -rf /"` | deny `RULE_RECURSIVE_SYSTEM_DELETE`，套壳被穿透 |
| `git push --force` + 无说明 | ask（`WHY_MISSING`） |

证据等级：**宿主组件级真机验证** —— 真实 `cordis Context`、真实 `dsh-system-prompt`、真实 `dsh-tools`，
加载的是从 npm 安装的包，不是本地源码，也不是 mock。
`dsh plugin` 已在本机实跑通过（宿主 `0.2.2-rc.3`）：`dsh plugin --profile web add dsh-cmd-guard` 成功，
`--profile` 必填、`web` 为要挂载的 profile，
注册走 `dsh.profile.bundles`（不是 `--patch`），配置树里能看到 `cmd-guard`。
仍未覆盖：headless 启动——缺模型凭证，进程挂住，所以「启动之后真拦截」这一环没有取到证据。

这个范围的上限就是 semver 本身：未来任何新的 `0.2.x-rc.N` 想被匹配，都得再往范围里加一段。
它不能靠推理一次写死。

零运行时依赖。无网络请求。

---

## 0.4.0 改了什么

新增一个**可选**配置，默认行为与 0.3.0 逐字一致。

| 项 | 内容 |
|---|---|
| 新配置 | `guard.chain: 'strict' \| 'decompose'`，默认 `strict` |
| 新模式 | `decompose` 按语句判链，消除「一条命令一个审批」 |
| 新 deny | `SPLIT_PIPE_TO_INTERPRETER`：`curl` / `wget` / `iwr` 等下载器的输出直接进 `sh` / `bash` / `python` / `iex` 等解释器 |
| 新 ask 码 | `SPLIT_BACKGROUND`、`SPLIT_TOO_MANY_PARTS`、`SPLIT_PIPE_TO_STDIN` |
| 管道建模 | `\|` 不再计入语句数：`a \| b \| c \| d \| e` 是 1 条语句、5 个阶段，逐阶段判；语句上限仍是 4 条 |
| 架构变化 | 「只有 `rules` 可以 deny」改为白名单，见八层结构一节 |

这一版最该记的不是新功能，是一个**第一版 `decompose` 里真实存在的洞**：逐段判定时跳过了 `why` 层，只在最后对整条命令调一次，而 `why` 只看命令头。于是 `git status; git push --force` 判成 pass，`echo hi; del x` 同样。修法是让每段都过 `why`，并补四条回归（`test/decompose.test.ts` 末尾）。**「不弱化护栏」这句话，只有每段都走完整八层才成立。**

同一版里还修了一处**误报**，方向相反但同样是建模错：`chainSegments` 把 `|` 当成语句分隔符，而语句上限是 4 条，于是一条只读五段管道（`git log | head | sort | uniq | cat`）会因为「段太多」被判 ask。管道是同一语句内的阶段，不是语句。现在语句只按 `;` `&&` `||` 与换行数，管道阶段单独展开、逐段判定，上限仍按语句算。反过来也补了一条：拆开管道不能把 `cat payload.sh | sh` 变成两条干净语句 —— 末段把上游当流执行时判 ask（`SPLIT_PIPE_TO_STDIN`），因为真正运行的那段代码不写在这条命令里。

## 0.3.0 改了什么

这一版修的是**静默失效**，不是新功能。三处 bug 的共同点是「测试全绿、装上也像没事」：

| 问题 | 修前 | 修后 |
|---|---|---|
| 写工具名 | `WRITE_TOOLS` 里没有 `write` / `edit`，只有自造的 `write_file` / `edit_file` | 补上宿主真实注册的 `write` / `edit`。此前 `recordWrite()` 在真机上一次都没触发，`INTERP_RECENT_WRITE` 是死代码 |
| 路径基准 | 相对路径按 `process.cwd()` 解析，包含关系按 `workspaceRoot` 判断，两个基准可能不是同一个 | `GuardState.cwd` + 配置 `guard.cwd`，两层统一；基准缺失时判 `ask`（`unknown-cwd`）而不是猜 |
| 远程目标 | `curl https://...`、`scp a.txt host:/tmp` 被当成本地相对路径 | URL 与 `host:path` 识别为 remote，不进入本地路径判定。修前这两条的 pass 是侥幸：换个目录就变 ask |

**为什么之前测不出来。** 语料里硬编码了 `D:/AI_Assistant`。把同一棵树复制到别处，同一个二进制、同一份语料，会稳定产生 8 条失败（`I-005` `I-016` `O-009` `W4-E6` `W5-F2` `W5-F5` `W5-F7` `W6-G4`）。现在工作区从仓库位置推导，并新增一条回归：整份语料在 `os.tmpdir()` 下重跑，判定必须逐条不变。

**行为变化。** `GuardState` 多了 `cwd` 字段；写工具名补全后，「写后即跑」会开始真的报 ask；remote 目标不再报 ask。所以是 minor，不是 patch。

## License

MIT
