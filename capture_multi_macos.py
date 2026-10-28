#!/usr/bin/env python3
"""多候选捕获：窗口内抓取所有 32 字节派生调用，逐个用 HMAC 校验挑出真正能开库的那个。

背景
----
单次捕获（`capture_passphrase_lldb`）命中第一个长度 32 的派生就 detach。但微信登录
过程中会先为设备级凭据库之类的对象做一次 32 字节派生，紧接着才为账号库派生 ——
单命中脚本常常拿到前者，表现就是"PBKDF2 派生 0/N 验证通过"，看起来像参数错了，
实际是抓错了那一次调用。

本脚本改成：窗口内持续抓、全部留底，再用数据库第一页的 HMAC 做裁判。
**命中不算数，校验通过才算数。**

用法
----
    python3 capture_multi_macos.py --db-dir <db_storage> --duration 300

命令挂住后，在微信里**退出登录 → 重新登录**（退出登录指账号登出，不是退出 App）。

说明
----
- 只针对 macOS 微信 4.1.10+（走 LLDB 断点），寄存器约定按 arm64 / x86_64 自动切换。
- 需要 lldb（`xcode-select --install`）。SIP 开启时微信须先重签名去掉 Hardened
  Runtime，否则 attach 会被拒绝。
- 捕获到的 passphrase 不打印到终端，只写 `~/.wcdb-key-tool/wechat-passphrase.json`（0600）。
"""
from __future__ import annotations

import argparse
import os
import platform
import re
import select
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wcdb_key_tool_macos as T  # noqa: E402

DERIVE_FN = "CCKeyDerivationPBKDF"
DEFAULT_PBKDF2_ITER = 256000


def say(msg: str) -> None:
    print(msg, flush=True)


def parse_candidates(buf: str) -> list[str]:
    """把 lldb 的 hexdump 按出现顺序切成若干 32 字节候选（去重保序）。"""
    by: list[str] = []
    for line in buf.splitlines():
        m = re.match(r"\s*0x[0-9a-f]+:\s+((?:0x[0-9a-f]{2}\s*)+)$", line)
        if m:
            by += re.findall(r"0x([0-9a-f]{2})", m.group(1))
    out, seen = [], set()
    for i in range(0, len(by) - 31, 32):
        cand = "".join(by[i : i + 32])
        if cand not in seen:
            seen.add(cand)
            out.append(cand)
    return out


def build_lldb_script(pid: int, duration: int) -> str:
    is_arm = platform.machine() in ("arm64", "aarch64")
    pw_reg, len_reg = ("x1", "x2") if is_arm else ("rsi", "rdx")
    return (
        "settings set target.preload-symbols false\n"
        f"process attach -p {pid}\n"
        f"breakpoint set -n {DERIVE_FN} -c '${len_reg} == 32'\n"
        "breakpoint command add 1\n"
        f"memory read --size 1 --count 32 --format x ${pw_reg}\n"
        "continue\n"
        "DONE\n"
        "process continue\n"
    )


def run_window(pid: int, duration: int) -> str:
    """attach 并在窗口内持续收集断点输出。返回 lldb 的原始文本。"""
    script = build_lldb_script(pid, duration)
    fd, sp = tempfile.mkstemp(suffix=".lldb", prefix="wxmulti_")
    with os.fdopen(fd, "w") as f:
        f.write(script)

    # 用 sleep 保活 stdin：lldb continue 之后是异步的，stdin 一 EOF 就退出，
    # 根本等不到用户重新登录触发断点。
    proc = subprocess.Popen(
        ["bash", "-c", f"( cat {sp}; sleep {duration} ) | TERM=dumb lldb"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    buf, deadline = "", time.time() + duration
    try:
        while time.time() < deadline:
            r, _, _ = select.select([proc.stdout], [], [], 2.0)
            if not r:
                continue
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue
            buf += line
    finally:
        for act in (proc.terminate, proc.kill):
            try:
                act()
            except Exception:
                pass
        try:
            proc.wait(timeout=3)
        except Exception:
            pass
        if os.path.exists(sp):
            os.unlink(sp)
        T._cleanup_lldb_orphans()
        try:
            os.kill(pid, signal.SIGCONT)  # 防止断点把微信留在暂停态
        except Exception:
            pass
    return buf


def resolve_db_dir(arg: str | None) -> str | None:
    if arg:
        return os.path.expanduser(arg)
    guess = T.auto_detect_db_dir()
    if guess:
        say(f"[!] 未指定 --db-dir，自动探测到: {guess}")
        say("[!] 同机登录过多个微信号时，自动探测可能指向另一个账号 —— 建议显式指定。")
    return guess


def main() -> int:
    ap = argparse.ArgumentParser(description="多候选捕获 macOS 微信数据库 passphrase")
    ap.add_argument("--db-dir", help="微信 db_storage 目录（默认自动探测）")
    ap.add_argument("--output", default="all_keys.json", help="密钥输出文件")
    ap.add_argument("--duration", type=int, default=300, help="捕获窗口秒数（默认 300）")
    a = ap.parse_args()

    issues = T.check_lldb_prerequisites()
    if issues:
        say("PREREQ_FAIL: " + "; ".join(issues))
        return 2

    pid = T._find_wechat_pid()
    if not pid:
        say("NO_WECHAT: 未找到微信进程，请先启动并登录微信")
        return 2

    db_dir = resolve_db_dir(a.db_dir)
    if not db_dir:
        say("NO_DB_DIR: 找不到 db_storage，请用 --db-dir 指定")
        return 2

    db_files, salt_to_dbs = T.collect_db_files(db_dir)
    if not db_files:
        say(f"NO_DB: {db_dir} 下没有可解密的 .db")
        return 2

    # 裁判库：挑体积最大的那个，确保它是真实账号库而不是空壳库。
    judge = max(db_files, key=lambda r: r[2])
    j_salt, j_page1, j_name = judge[3], judge[4], judge[0]
    say(f"[*] 数据库 {len(db_files)} 个 / 盐 {len(salt_to_dbs)} 个；裁判库 = {j_name}")
    say(f"[*] 已 attach pid={pid}，窗口 {a.duration}s")
    say("[*] 现在请在微信里：退出登录 → 重新登录（不要退出 App）")

    buf = run_window(pid, a.duration)
    cands = parse_candidates(buf)
    say(f"[*] 窗口内捕获到 {len(cands)} 个候选")
    if not cands:
        say("NO_CANDIDATE: 窗口内没有发生派生调用（多半是没做「退出登录→重新登录」）")
        return 3

    iter_n = getattr(T, "ITER", DEFAULT_PBKDF2_ITER)
    for i, cand in enumerate(cands, 1):
        key = T.hashlib.pbkdf2_hmac(
            "sha512", bytes.fromhex(cand), bytes.fromhex(j_salt), iter_n, dklen=T.KEY_SZ
        )
        if not T.verify_enc_key(key, j_page1):
            say(f"    候选 {i}/{len(cands)} → 裁判库 HMAC 不匹配")
            continue
        say(f"    候选 {i}/{len(cands)} → 裁判库 HMAC 通过，开始全量派生")
        key_map = T._derive_keys_from_passphrase(bytes.fromhex(cand), db_files, salt_to_dbs)
        if len(key_map) == len(salt_to_dbs):
            T.save_passphrase(cand)
            T._save_results(db_files, salt_to_dbs, key_map, db_dir, a.output)
            say(f"VERIFIED {len(key_map)}/{len(salt_to_dbs)} —— passphrase 与密钥已保存")
            return 0
        say(f"    部分通过 {len(key_map)}/{len(salt_to_dbs)}，继续试下一个候选")

    say("ALL_FAIL: 所有候选都没通过校验。请确认 --db-dir 与当前登录账号一致。")
    return 4


if __name__ == "__main__":
    sys.exit(main())
