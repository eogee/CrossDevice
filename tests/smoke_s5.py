#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""smoke_s5 —— M4 后补批次自测（B42/B43，node v0.5.1 / 契约 V1.6）。

覆盖两条用户反馈 issue 的修复：
  E1  exec cmd 形态：引号逐字透传（B43 前 ["cmd","/c",cmd] 列表形态经
      list2cmdline 的 \\" 转义 + cmd /c 首尾引号剥除，带引号命令全失效）
  E2  exec powershell 形态：-EncodedCommand 免引号歧义（B43 前 -Command
      形态深层嵌套引号不可靠——PS 5.1 原生传参不转义内嵌双引号）
  E3  exec none 形态：CommandLineToArgvW 按 Windows argv 语义切分
      （B43 前 prompt.split() 按空格硬切，拆散带引号参数）+ 白盒断言
  W1  默认暂存目录（B42）：无 workspace 配置时 <config 目录>/tmp 恒可写
      （fs/write + upload/begin），SANDBOX_DENIED 报错携带允许根列表与
      配置指引（error.allowed_roots 机读 + message 人读），/v1/info 增
      workspace_roots/workspace_staging 字段，横幅展示，审计仍照常落
  W2  显式 workspace 配置：info 列出 用户根+暂存目录，越界报错 message
      含"当前允许的根"全列表

复用 smoke_s1/smoke_s2 脚手架（NODE_PY / S2Node / raw2 / 证书 / 令牌）。
仅标准库。运行：python tests/smoke_s5.py [--keep]
"""

import argparse
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import smoke_s1                     # noqa: E402  复用 S1 脚手架
import smoke_s2                     # noqa: E402  复用 S2 脚手架（S2Node/raw2/node_tokens）

HOST = smoke_s1.HOST
TOKEN_DEFAULT = smoke_s1.TOKEN_DEFAULT
NODE_PY = smoke_s1.NODE_PY

RESULTS = []


def record(code, title, ok, evidence):
    RESULTS.append((code, title, bool(ok)))
    evidence = " ".join(str(evidence).split())
    print("%s %s %s（%s）" % (code, title, "PASS" if ok else "FAIL", evidence))


def norm(path):
    """与 node 侧 normalize_real 的 normcase 口径对齐（盘符/大小写归一）。"""
    return os.path.normcase(os.path.normpath(str(path)))


def jdata(body):
    try:
        parsed = json.loads(body.decode("utf-8"))
        return parsed.get("data") if parsed.get("ok") else None
    except Exception:
        return None


def jerror(body):
    """node 错误信封 → error 对象（B42 起可能含 allowed_roots/staging_root）。"""
    try:
        parsed = json.loads(body.decode("utf-8"))
        return parsed.get("error") if parsed.get("ok") is False else None
    except Exception:
        return None


def run_job(port, payload, timeout=45):
    """发起 exec 并轮询到终态，返回 (http_status, job_dict 或 None)。"""
    st, _, body = smoke_s2.raw2(HOST, port, "POST", "/v1/exec", token=TOKEN_DEFAULT,
                                payload=payload, timeout=10)
    if st != 200:
        return st, None
    job_id = (jdata(body) or {}).get("job_id")
    if not job_id:
        return st, None
    job = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, _, b2 = smoke_s2.raw2(HOST, port, "GET", "/v1/job/%s?wait=2" % job_id,
                                 token=TOKEN_DEFAULT, timeout=10)
        job = jdata(b2) or {}
        if job.get("status") != "running":
            return st, job
        time.sleep(0.3)
    return st, job


def make_node(tag, cfg_dir, extra_cfg=None):
    """起一个测试 node：config 目录 <tmp>/<tag>/，返回 (S2Node, cfg 文件, 端口)。"""
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_file = cfg_dir / "node.json"
    cfg = {
        "version": 1,
        "tokens": smoke_s2.node_tokens(),
        "tls": {"cert": str(CTX.cert1), "key": str(CTX.key1)},
        "audit": {"retention_days": 180},
    }
    if extra_cfg:
        cfg.update(extra_cfg)
    smoke_s1.write_json(cfg_file, cfg)
    port = smoke_s1.free_port()
    node = smoke_s2.S2Node(tag, CTX.tmp, ["--config", str(cfg_file), "--port", str(port)])
    node.ready(TOKEN_DEFAULT, port)
    return node, cfg_file, port


def load_node_module():
    """白盒加载 node.py 模块（smoke_s2 C3 同款口径；不起服务）。"""
    spec = importlib.util.spec_from_file_location("node_s5_wb", str(NODE_PY))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---- 用例 ------------------------------------------------------------------

def e1_exec_cmd_quotes(ctx, opts):
    """E1 cmd 形态：带引号命令逐字透传（B43 修复验证）。"""
    notes = []
    # ① cmd 字符串比较：引号若被剥则条件不成立、无输出
    st, job = run_job(ctx.port_main,
                      {"cmd": 'if "a b" == "a b" echo QUOTEOK_CMD',
                       "shell": "cmd", "timeout": 20})
    ok_cmp = (st == 200 and job and job.get("status") == "done"
              and "QUOTEOK_CMD" in (job.get("stdout") or ""))
    notes.append("if 比较 stdout=%r" % ((job or {}).get("stdout", "")[:60],))

    # ② 空格参数经引号保护（B43 前必现：无效参数/选项 - 'eq'）
    st, job = run_job(ctx.port_main,
                      {"cmd": 'tasklist /FI "IMAGENAME eq nonexist_dummy_s5.exe"',
                       "shell": "cmd", "timeout": 30})
    out = (job or {}).get("stdout") or ""
    err = (job or {}).get("stderr") or ""
    ok_fi = (st == 200 and job and job.get("status") == "done"
             and job.get("exit_code") == 0
             and "无效参数" not in err and "'eq'" not in (out + err))
    notes.append("tasklist /FI exit=%s err=%r"
                 % ((job or {}).get("exit_code"), err.strip()[:60]))
    return ok_cmp and ok_fi, "；".join(notes)


def e2_exec_powershell_quotes(ctx, opts):
    """E2 powershell 形态：-EncodedCommand，单层与嵌套引号均逐字生效。"""
    notes = []
    st, job = run_job(ctx.port_main,
                      {"cmd": 'Write-Output "HE LLO"',
                       "shell": "powershell", "timeout": 45})
    ok_simple = (st == 200 and job and job.get("status") == "done"
                 and "HE LLO" in (job.get("stdout") or ""))
    notes.append("单层 stdout=%r" % ((job or {}).get("stdout", "")[:60],))

    # 嵌套双引号（B43 前 -Command 形态深层嵌套不可靠的形态）
    st, job = run_job(ctx.port_main,
                      {"cmd": 'Write-Output \'SAY "HI" S5\'',
                       "shell": "powershell", "timeout": 45})
    ok_nested = (st == 200 and job and job.get("status") == "done"
                 and 'SAY "HI" S5' in (job.get("stdout") or ""))
    notes.append("嵌套 stdout=%r" % ((job or {}).get("stdout", "")[:60],))
    return ok_simple and ok_nested, "；".join(notes)


def e3_exec_none_argv(ctx, opts):
    """E3 none 形态：Windows argv 语义切分（白盒 + 黑盒）。"""
    notes = []
    wb = ctx.node_mod
    # 白盒：切分/编码/分支契约
    ok_split = (wb.split_windows_argv('tasklist /FI "IMAGENAME eq X"')
                == ["tasklist", "/FI", "IMAGENAME eq X"])
    ok_ps = wb.build_argv('Write-Output "x"', "powershell")[-2] == "-EncodedCommand"
    ok_none = wb.build_argv('echo "a b"', "none") == ["echo", "a b"]
    try:
        wb.build_argv("x", "cmd")
        ok_branch = False
    except ValueError:
        ok_branch = True
    ok_wb = ok_split and ok_ps and ok_none and ok_branch
    notes.append("白盒 split/EncodedCommand/none/cmd拒绝=%s/%s/%s/%s"
                 % (ok_split, ok_ps, ok_none, ok_branch))

    # 黑盒：引号内空格不拆散（B43 前 .split() 拆散 → if 条件失败无输出）
    st, job = run_job(ctx.port_main,
                      {"cmd": 'cmd /c if "x y" == "x y" echo QUOTEOK_NONE',
                       "shell": "none", "timeout": 20})
    ok_bb = (st == 200 and job and job.get("status") == "done"
             and "QUOTEOK_NONE" in (job.get("stdout") or ""))
    notes.append("黑盒 stdout=%r" % ((job or {}).get("stdout", "")[:60],))
    return ok_wb and ok_bb, "；".join(notes)


def w1_default_staging(ctx, opts):
    """W1 默认暂存目录：无 workspace 配置时 <config 目录>/tmp 恒可写 + 报错可发现。"""
    notes = []
    node, cfg_file, port = make_node("w1", ctx.tmp / "w1")
    ctx.nodes.append(node)
    staging = ctx.tmp / "w1" / "tmp"

    # ① 暂存目录启动即创建；fs/write / upload/begin 均可写入
    ok_created = staging.is_dir()
    st_w, _, b_w = smoke_s2.raw2(HOST, port, "POST", "/v1/fs/write", token=TOKEN_DEFAULT,
                                 payload={"path": str(staging / "hello.txt"),
                                          "text": "s5"}, timeout=10)
    ok_write = st_w == 200
    st_u, _, b_u = smoke_s2.raw2(HOST, port, "POST", "/v1/fs/upload/begin",
                                 token=TOKEN_DEFAULT,
                                 payload={"path": str(staging / "up.bin"),
                                          "size": 4, "md5": "0" * 32}, timeout=10)
    ok_upload = st_u == 200
    notes.append("暂存创建/写/上传=%s/%s/%s" % (ok_created, st_w, st_u))

    # ② /v1/info：workspace_roots == [暂存目录]、workspace_staging 指向暂存目录
    st_i, _, b_i = smoke_s2.raw2(HOST, port, "GET", "/v1/info",
                                 token=TOKEN_DEFAULT, timeout=10)
    info = jdata(b_i) or {}
    ok_info = (st_i == 200 and info.get("workspace_roots") == [norm(staging)]
               and info.get("workspace_staging") == norm(staging))
    notes.append("info roots=%s" % (info.get("workspace_roots"),))

    # ③ 暂存目录外写入 → 403 SANDBOX_DENIED，报错自带指引（B42 核心）
    st_d, _, b_d = smoke_s2.raw2(HOST, port, "POST", "/v1/fs/write", token=TOKEN_DEFAULT,
                                 payload={"path": str(ctx.tmp / "w1_out.txt"),
                                          "text": "x"}, timeout=10)
    err = jerror(b_d) or {}
    msg = err.get("message") or ""
    ok_denied = (st_d == 403 and err.get("code") == "SANDBOX_DENIED"
                 and norm(staging) in [norm(p) for p in (err.get("allowed_roots") or [])]
                 and "暂存目录" in msg and "workspace" in msg)
    notes.append("越界 %s/%s allowed_roots=%s msg含指引=%s"
                 % (st_d, err.get("code"),
                    [norm(p) for p in (err.get("allowed_roots") or [])],
                    ("暂存目录" in msg)))

    # ④ 横幅可见性：node 日志含白名单/暂存目录行（子进程 print 落管道，编码 GBK/UTF-8 二选一）
    try:
        log_bytes = ctx.tmp.joinpath("node_w1.log").read_bytes()
    except OSError:
        log_bytes = b""
    ok_banner = any(all(kw.encode(enc) in log_bytes for kw in ("白名单", "暂存目录"))
                    for enc in ("gbk", "utf-8"))

    # ⑤ 审计回归：SANDBOX_DENIED 照常落审计（§8.2 例外，message 变更不破坏）
    audit_files = sorted((ctx.tmp / "w1" / "audit").glob("audit-*.jsonl"))
    ok_audit = False
    for f in audit_files:
        try:
            if "SANDBOX_DENIED" in f.read_text(encoding="utf-8", errors="replace"):
                ok_audit = True
                break
        except OSError:
            continue
    notes.append("审计落 SANDBOX_DENIED=%s" % ok_audit)
    return (ok_created and ok_write and ok_upload and ok_info
            and ok_denied and ok_banner and ok_audit), "；".join(notes)


def w2_explicit_workspace(ctx, opts):
    """W2 显式 workspace：info 列 用户根+暂存目录；越界报错含全量允许根。"""
    notes = []
    user_root = ctx.tmp / "w2ws"
    user_root.mkdir(parents=True, exist_ok=True)
    node, cfg_file, port = make_node("w2", ctx.tmp / "w2",
                                     extra_cfg={"workspace": [str(user_root)]})
    ctx.nodes.append(node)
    staging = ctx.tmp / "w2" / "tmp"

    st_i, _, b_i = smoke_s2.raw2(HOST, port, "GET", "/v1/info",
                                 token=TOKEN_DEFAULT, timeout=10)
    info = jdata(b_i) or {}
    roots = [norm(p) for p in (info.get("workspace_roots") or [])]
    ok_info = (st_i == 200 and roots == [norm(user_root), norm(staging)]
               and info.get("workspace_staging") == norm(staging))
    notes.append("info roots=%s" % roots)

    st_w, _, _ = smoke_s2.raw2(HOST, port, "POST", "/v1/fs/write", token=TOKEN_DEFAULT,
                               payload={"path": str(user_root / "in.txt"),
                                        "text": "s5"}, timeout=10)
    ok_write = st_w == 200

    st_d, _, b_d = smoke_s2.raw2(HOST, port, "POST", "/v1/fs/write", token=TOKEN_DEFAULT,
                                 payload={"path": str(ctx.tmp / "w2_out.txt"),
                                          "text": "x"}, timeout=10)
    err = jerror(b_d) or {}
    msg = (err.get("message") or "").lower()
    ok_denied = (st_d == 403 and err.get("code") == "SANDBOX_DENIED"
                 and "当前允许的根" in (err.get("message") or "")
                 and norm(user_root) in msg and "tmp" in msg
                 and len(err.get("allowed_roots") or []) == 2)
    notes.append("写=%s 越界=%s allowed_roots=%s"
                 % (st_w, st_d, err.get("allowed_roots")))
    return ok_info and ok_write and ok_denied, "；".join(notes)


# ---- 主流程 ----------------------------------------------------------------

class _Ctx:
    pass


CTX = _Ctx()


def main():
    parser = argparse.ArgumentParser(description="smoke_s5：B42/B43 后补批次自测")
    parser.add_argument("--keep", action="store_true", help="保留临时目录")
    opts = parser.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="smoke_s5_"))
    # W1 断言读 node 子进程日志：stdout 落文件为块缓冲，terminate() 强杀会丢缓冲，
    # 强制子进程不缓冲（S2Node 复制 os.environ 传入）
    os.environ["PYTHONUNBUFFERED"] = "1"
    ctx = CTX
    ctx.tmp = tmp
    ctx.nodes = []
    ctx.port_main = None
    ctx.node_mod = load_node_module()

    print("smoke_s5（B42 白名单可发现性/B43 exec 引号，node v0.5.1 / 契约 V1.6）")
    print("临时目录：%s" % tmp)
    print("node.py：%s" % NODE_PY)
    print("-" * 76)

    exit_code = 1
    try:
        # 主实例（E 组共用）：标准 TLS + default/tester 两身份，无 workspace 配置
        tls1 = tmp / "tls1"
        tls1.mkdir(parents=True, exist_ok=True)
        ctx.cert1, ctx.key1 = tls1 / "cert.pem", tls1 / "key.pem"
        smoke_s1.gen_cert(tls1)
        main_cfg = tmp / "main" / "node.json"
        smoke_s1.write_json(main_cfg, {
            "version": 1, "tokens": smoke_s2.node_tokens(),
            "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
            "audit": {"retention_days": 180},
        })
        ctx.port_main = smoke_s1.free_port()
        main_node = smoke_s2.S2Node("main", tmp,
                                    ["--config", str(main_cfg),
                                     "--port", str(ctx.port_main)])
        main_node.ready(TOKEN_DEFAULT, ctx.port_main)
        ctx.nodes.append(main_node)

        for code, title, fn in [
            ("E1", "exec cmd 引号透传", e1_exec_cmd_quotes),
            ("E2", "exec powershell 引号", e2_exec_powershell_quotes),
            ("E3", "exec none argv 语义", e3_exec_none_argv),
            ("W1", "默认暂存目录与报错指引", w1_default_staging),
            ("W2", "显式 workspace 与允许根列表", w2_explicit_workspace),
        ]:
            try:
                ok, evidence = fn(ctx, opts)
            except Exception as exc:
                ok, evidence = False, "测试框架异常：%r" % (exc,)
            record(code, title, ok, evidence)

        passed = sum(1 for _, _, ok in RESULTS if ok)
        print("-" * 76)
        print("S5 自测：%d/%d 通过" % (passed, len(RESULTS)))
        for code, title, ok in RESULTS:
            if not ok:
                print("  未通过：%s %s" % (code, title))
        exit_code = 0 if passed == len(RESULTS) else 1
    finally:
        for node in ctx.nodes:
            try:
                node.stop()
            except Exception:
                pass
        if opts.keep:
            print("临时目录保留：%s" % tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
