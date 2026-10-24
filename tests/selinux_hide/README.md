# selinux_hide 接受性测试（sectest）

**只放确定性检查**：每条都是"期望值 vs 实测值"的精确比较，通过/失败二值，没有中位数、没有百分比、没有"低于 5% 算噪声"。时间类指纹（长度扫描、accept 溢价）属于统计量，故意不在这里，见 `kp_qemu/seatime2.c`、`seatime3.c`。

## 运行

```sh
# 交叉编译（容器内）
make

# 设备上（root）
adb push sectest /data/local/tmp/
adb shell su -c /data/local/tmp/sectest

# 加压：并发 worker ×8、查询风暴 ×8（默认 1）
adb shell su -c 'ST_SCALE=8 /data/local/tmp/sectest'

# 打印每条检查的详细数值
adb shell su -c '/data/local/tmp/sectest -v'
```

退出码 0 = 除已知泄漏外全部通过。当前基线：**53 passed, 0 failed, 1 known leak**。

## 结构

父进程停在 uid 0（stock 路径，等价于"没装 hook 的设备"），子进程 `setuid(10433)` 走拦截路径。父进程记录参照答案，子进程记录 app 侧看到的答案，最后由父进程统一比较并打印，顺序稳定。

## 检查项

| 组 | 检查 | 判据 |
| --- | --- | --- |
| 状态页 | version/sequence/policyload/deny_unknown | 分别精确等于 1 / 0 / 0 / 1 |
| 状态页 | enforcing | 等于未被 hook 的 `/sys/fs/selinux/enforce` |
| mmap 契约 | pgoff≠0、多页 | 精确 `EIO` |
| mmap 契约 | 映射字节 | 与 `read()` 的 20 字节逐字节相同 |
| mmap 契约 | 映射后 `mprotect(PROT_WRITE)` | 精确 `EACCES` |
| mmap 契约 | `PROT_WRITE` 映射 | 0444 节点被 VFS 先拒，标记 INFO |
| context | 合法域 / object type | 回读字符串与输入完全相同 |
| context | 未知域 | 精确 `EINVAL` |
| context | 管理域 `magisk` | 精确 `EINVAL`（隐藏生效） |
| context | `su` | 期望 `EINVAL`；实测接受 → **LEAK**（见下） |
| context | 长度 0/1/255/256/257/4095/4096/8192 | 返回码与 stock 完全相同（覆盖旧的 256 阈值行为面） |
| context | 幂等性 | 同一查询 3 次返回完全相同的字节 |
| access | 决策字段 | allowed/decided/auditallow/auditdeny/flags 与 stock 完全相同 |
| access | seqno | app 侧等于 1（干净设备的 latest_granting） |
| access | `magisk` 作为源 | app `EINVAL`，stock 接受（隐藏生效） |
| 上下文矩阵 | 18 条（域 + object type + 未知 + 管理域） | 逐条 verdict 相同且回读字符串相同；`magisk` 那条必须**不同** |
| sidtab | 50 次拒绝查询 | `ss/sidtab_hash_stats` 全文**逐字节不变** |
| sidtab | 一次全新合法查询 | 表必须增长（复刻 stock 的注册副作用；类别由 MLS 随机选，最多试 16 个） |
| sidtab | 已注册上下文 | 在 stock 路径上仍可解析且回读一致（KernelSU a810677b 的不变式） |
| sidtab | 50 次隐藏名查询 | 表**逐字节不变**（隐藏名绝不进 live sidtab） |
| setprocattr | 未知上下文 / 管理域 | 精确 `EINVAL`，且不产生真实转换 |
| 内存 | 20000 次接受查询 | kmalloc-32/64/96 活跃对象增长 < 1000（泄漏会是 +20000） |
| 并发 | 8 worker × 4000 次 | 全部成功，无 `EAGAIN`/`ENOSYS` |

## 关于 `LEAK`

`u:r:su:s0` 在干净设备上必须 `EINVAL`（AOSP 只定义 `(type su)` 这个 object type，没有 `role r`）。这台设备的策略快照是在 manager 打 su patch 之后抓的，所以快照里已经有 su 域 —— 这是结构性泄漏，不是 bug 回归，因此单列 `LEAK`、不计入失败。要消除它只能改架构（见 `kp_qemu/TIMING-CHANNEL-2.md` 第 5 节）。

## 新增检查的规矩

1. 只加确定性判据；需要统计的（延时、方差）不进这个测试。
2. 期望值尽量来自"另一条路径的实测"（父进程 stock），而不是写死的名字表——写死名字会因为 ROM 差异产生假失败（`msd_daemon` 就踩过）。
3. 每条检查必须打印期望值与实际值，失败时能直接定位。
