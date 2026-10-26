# selinux_hide：查询路径的时间结构

本文记录 selinux_hide 在 selinuxfs 上回答查询时，**时间**这一侧还有什么可被观察，
以及哪些已经被关掉。内容策略（答案是否随 payload 变化）不在这里讨论，它由
`kp_context_to_sid_clean*` 的判定顺序决定，代码注释里已有说明。

## 1. 三层模型

一个调用方可以从三个深度观察这个功能：

| 层 | 观察内容 | 当前状态 |
| --- | --- | --- |
| L1 内容 | 同样的请求，答案是否随 payload 变化 | `context` 与 `attr/current` 已关闭；`access` 关不掉（答案必须依赖 payload） |
| L2 代价 | 同样的合法请求，耗时是否有差异 | 仍然存在，见第 3 节 |
| L3 结构 | SID 编号、sidtab 规模、策略快照 | 已约束：`seqno` 钉成常数，只对快照接受的上下文做 live 注册 |

L1 能关掉的原因是判定顺序：`context` 先做权限检查（`check_context`），权限通过之后
才碰 payload；`attr/current` 同理，`kp_avc_check(SETCURRENT)` 在任何解析之前。所以
“无权限的探测”在 stock 和 hide 上都只走一条早退路径，payload 长什么样都不影响耗时。

`access` 不一样：它的答案（`av_decision` 那六个数）本身就是 payload 的函数，合法请求
必然比失败请求贵。这一层没有“等价”可做，只能把常数项压小。

## 2. 一次查询花在哪里

`context`（uid >= 10000，走快照）：

1. `current_uid()`、日志开关判断（关闭时只是一次比较）
2. `kp_avc_check(SECURITY__CHECK_CONTEXT)`：`security_cred_getsecid()` + `avc_has_perm()`
3. 快照解析：payload 拷进可写缓冲（现在优先栈缓冲）→ `string_to_context_struct()`
   （就地分词 + 策略哈希查找）→ `sidtab_context_to_sid()`
4. live 注册：`security_context_to_sid()`，内部还要 `kstrdup` 一次、自己再分词一次
5. `sid_to_context()`：sidtab 查找 + `sid2str`（首次分配并缓存，之后命中缓存）
6. 把规范串 `memcpy` 回内核缓冲

`access` 在第 3、4 步上做两遍（ssid、tsid），再加 `compute_av` 与十六进制/十进制格式化。

失败路径（快照不认识的上下文）在第 3 步就返回，**不做**第 4、5 步。L2 的来源就是这一层，
它和 stock 的“成功 vs 早退”差不是一回事。

## 3. 实测（hide ON，绑大核，成对 A/B）

| 指标 | 数值 |
| --- | --- |
| `context` A 的块中位数差（app 自身统计） | p10 / med / p90 = 2188 / 2240 / 2290 ns |
| 同量 A−B（stock） | 约 +990 ns |
| 同量 A−B（hook） | 约 +1875 ns |
| hook 的边际增量，`context` | 约 +0.9 µs（1.8 → 2.7 µs） |
| 同上，`access` | 约 +2.0 µs（10.1 → 12.1 µs） |
| 同上，`attr/current` accept | 约 +0.35 µs（6.98 → 7.58 µs，约 8%） |
| app 侧 A/B 比（屏幕值） | `context` 2.67×，`access` 4.30× |
| 跨会话方差 | 同一份代码两轮 `context` A 中位数 4115 → 1771 ns（×2.3） |

读法：

- 单轮之内判定很稳（信号约 18σ），加噪挡不住；
- 跨会话方差比我们引入的差值还大，纯跨设备比对拿不到结论；
- 想判定，攻击者需要同设备、同内核的 OFF 基线，也就是已经能刷 boot 或开关本功能，
  此时隐藏对他没有意义。这是这一层信道的现实边界。

## 4. 残余信道清单

| 编号 | 信道 | 现状 | 说明 |
| --- | --- | --- | --- |
| R1 | `context` 成功路径比失败路径贵 | 存在 | 快照解析 + live 注册 + sid2str + 拷贝；stock 也贵，我们更贵 |
| R2 | `access` 双倍策略工作 | 存在 | 两个上下文各一次“快照 + live”，stock 只做一次 live |
| R3 | `attr/current` accept 慢约 8% | 存在 | 来自快照解析；权限被拒时不发生 |
| R4 | `sid2str` 冷热 | 存在 | 首次分配并缓存，之后命中；同一 pid 重复查询能看到台阶 |
| R5 | 日志开关 | 运维项 | 等级 `on`/`verbose` 时 `logkfi` 的成本远大于查询本身，测时间前必须关 |
| R6 | sidtab 规模 | 已约束 | 只为快照接受的上下文注册；被拒的上下文（`u:r:su:s0` 之类）不注册 |
| R7 | `seqno` | 已钉死 | `KP_AVD_CLEAN_SEQNO` |

要真正做到“代价也对齐”，只有两条路，而且都有代价：

1. 让失败路径付同样的钱：等于改变 stock 的早退行为，反而制造新的可观察差；
2. 让成功路径免掉 live 注册或 sid2str：会破坏“交出去的 SID 在 live 策略里可解析”
   这个不变式，KernelSU a810677b 修的就是这个。

所以目标只能是把常数项压小，而不是归零。

## 5. 逐段计时

日志等级设成 `verbose`（control state = 2）后，两个 hook 会为每条 app 查询打印一行
纳秒级分段；等级为 `off`/`on` 时整块只是两次比较。

管理器界面目前只暴露“开 / 关”两档，够不到 `verbose`。想用一次刷机拿到数据，可以编一个
带预算的诊断 kpimg：

```sh
make TARGET_COMPILE=aarch64-linux-gnu- ANDROID=1 \
     CFLAGS="... -DANDROID -DKP_TRACE_BUDGET=500" kpimg
```

`KP_TRACE_BUDGET=N` 让开机后的前 N 次 app 查询打印分段、然后自动停止；正常构建里它是 0，
这块只剩两次比较。刷入诊断 kpimg、跑一轮 attrprobe、用 `dmesg | grep 'stage '` 取数，
再刷回正常 kpimg。

```
stage context uid=10443 size=33 log=0 avc=... snap=... live=... sid2str=... copy=... total=...
stage access  uid=10443 size=57 log=0 avc=... parse=... scon(snap=... live=...)
              tcon(snap=... live=...) conv=... avd=... fmt=... total=...
```

- `snap`：快照解析（就地分词 + sidtab 查找）
- `live`：live 策略注册那一次 `security_context_to_sid()`
- `sid2str`：反向取规范串（含首次分配）
- `conv`：两个上下文转换的合计（`access`）
- `avd`：`compute_av` 与字段填充
- `fmt`：格式化与回复

`g_stage_*` 只在该等级下写入，且不参与任何判定；超长 payload 走分配路线时两项打 `-1`，
表示这次没有分段。

复现步骤：

```sh
# 1. 打开 verbose（管理器里对应 control state 2）
# 2. 用 attrprobe / sfsprobe 让 app uid 触发若干次 context 与 access 查询
# 3. 取数
su -c "dmesg | grep 'stage '" | tail -40
# 4. 恢复 control state 0
```

注意：`verbose` 本身的开销会进入 `total`，也会影响调用方测到的绝对耗时，测时间前后都要
关掉；只有分段值之间互相比较才有意义，不要拿 `total` 和 stock 比。

## 6. 判定口径

改动验收用同一条口径：同一台设备、同一份 app 侧成对探针，比较

- `context` A 的块中位数（hide ON，改动前 vs 改动后）
- `access` A 的块中位数（同上）
- 以及 A−B 的差值

只有 A 的绝对值下降、而 A−B 的判定结论（是否可区分）不变，才算“代价对齐”有效；把差值
抹成 0 但换了指纹（例如引入缓存造成冷热台阶）不算。
