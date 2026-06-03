#!/usr/bin/env python3
"""
netpeek.py — 监控任意命令的 HTTP/S 请求

用法:
    python netpeek.py '<命令>'

示例:
    python netpeek.py 'curl https://httpbin.org/get'
    python netpeek.py 'wget -q -O- https://example.com'
    python netpeek.py 'python3 my_script.py'
    python netpeek.py '/Applications/MyApp.app/Contents/MacOS/MyApp --update'

依赖:
    pip install mitmproxy
"""

import asyncio
import subprocess
import sys
import os
import threading
import time
import json
from datetime import datetime

try:
    from mitmproxy import options
    from mitmproxy.tools import dump
    from mitmproxy import http as mhttp
except ImportError:
    print("[错误] 未安装 mitmproxy，请先运行：pip install mitmproxy")
    sys.exit(1)


# ── 配置 ──────────────────────────────────────────────────────────

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 18080          # 如有冲突可改为其他端口
CA_DIR     = os.path.expanduser("~/.mitmproxy")
CA_CERT    = os.path.join(CA_DIR, "mitmproxy-ca-cert.pem")


# ── 拦截插件 ──────────────────────────────────────────────────────

class Sniffer:
    def __init__(self, verbose: bool):
        self.verbose  = verbose
        self.entries: list[dict] = []
        self._lock    = threading.Lock()

    # ── 请求阶段 ──────────────────────────────────────────────────
    def request(self, flow: mhttp.HTTPFlow):
        entry = {
            "id":      id(flow),
            "time":    datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "method":  flow.request.method,
            "url":     flow.request.pretty_url,
            "host":    flow.request.host,
            "port":    flow.request.port,
            "scheme":  flow.request.scheme,
            "headers": dict(flow.request.headers),
            "body":    flow.request.get_text(strict=False) if flow.request.content else "",
            "status":  None,
            "size":    None,
            "ctype":   None,
        }
        with self._lock:
            self.entries.append(entry)

        scheme_tag = "HTTPS" if entry["scheme"] == "https" else "HTTP "
        print(f"\033[36m[→ {scheme_tag}]\033[0m  {entry['time']}  "
              f"\033[1m{entry['method']}\033[0m  {entry['url']}")

        if self.verbose and entry["body"]:
            _print_body("  ↑ body", entry["body"])

        if self.verbose:
            for k, v in entry["headers"].items():
                print(f"  \033[90m{k}: {v}\033[0m")

    # ── 响应阶段 ──────────────────────────────────────────────────
    def response(self, flow: mhttp.HTTPFlow):
        status = flow.response.status_code
        size   = len(flow.response.content)
        ctype  = flow.response.headers.get("content-type", "-")
        body   = flow.response.get_text(strict=False) if flow.response.content else ""

        # 回填到对应 entry
        with self._lock:
            for e in self.entries:
                if e["id"] == id(flow):
                    e["status"] = status
                    e["size"]   = size
                    e["ctype"]  = ctype
                    break

        color = "\033[32m" if status < 300 else "\033[33m" if status < 400 else "\033[31m"
        print(f"  \033[90m←\033[0m  {color}{status}\033[0m  "
              f"{size} bytes  \033[90m{ctype}\033[0m")

        if self.verbose and body:
            _print_body("  ↓ body", body)

    # ── 汇总 ─────────────────────────────────────────────────────
    def print_summary(self):
        entries = self.entries
        total   = len(entries)

        print("\n" + "═" * 64)
        print(f"  共捕获 \033[1m{total}\033[0m 个请求")
        print("═" * 64)

        if not entries:
            print("  （无请求）")
            return

        # 按 host 分组
        hosts: dict[str, list[dict]] = {}
        for e in entries:
            hosts.setdefault(e["host"], []).append(e)

        for host, reqs in hosts.items():
            https_count = sum(1 for r in reqs if r["scheme"] == "https")
            tag = "\033[32mHTTPS\033[0m" if https_count == len(reqs) \
                  else "\033[33mHTTP\033[0m " if https_count == 0 \
                  else "\033[33mMIXED\033[0m"
            print(f"\n  {tag}  \033[1m{host}\033[0m  ({len(reqs)} 次)")
            for r in reqs:
                status_str = f"\033[90m[{r['status']}]\033[0m" if r["status"] else ""
                print(f"    {r['method']:<6} {r['url']}  {status_str}")

        print("\n" + "═" * 64)

    def save_json(self, path: str):
        data = []
        for e in self.entries:
            data.append({k: v for k, v in e.items() if k != "id"})
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"  已保存到 {path}")


# ── 工具函数 ──────────────────────────────────────────────────────

def _print_body(label: str, text: str, max_len: int = 300):
    preview = text[:max_len].replace("\n", " ")
    suffix  = "…" if len(text) > max_len else ""
    print(f"  \033[90m{label}: {preview}{suffix}\033[0m")


# ── 代理线程 ──────────────────────────────────────────────────────

class ProxyThread(threading.Thread):
    def __init__(self, sniffer: Sniffer):
        super().__init__(daemon=True)
        self.sniffer = sniffer
        self.ready   = threading.Event()
        self.master  = None
        self._loop   = None

    def run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._start())

    async def _start(self):
        opts = options.Options(
            listen_host  = PROXY_HOST,
            listen_port  = PROXY_PORT,
            ssl_insecure = True,
            confdir      = CA_DIR,
        )
        self.master = dump.DumpMaster(
            opts,
            with_termlog = False,
            with_dumper  = False,
        )
        self.master.addons.add(self.sniffer)
        self.ready.set()
        try:
            await self.master.run()
        except asyncio.CancelledError:
            pass

    def stop(self):
        if self.master:
            self.master.shutdown()


# ── 主程序 ────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="监控任意命令的 HTTP/S 请求",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python netpeek.py 'curl https://httpbin.org/get'
  python netpeek.py -v 'curl https://httpbin.org/get'
  python netpeek.py -o result.json 'wget -q -O- https://example.com'
        """,
    )
    parser.add_argument("command", help="要监控的命令（用引号包裹）")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="显示请求头和 body")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="将结果保存为 JSON 文件")
    args = parser.parse_args()

    sniffer      = Sniffer(verbose=args.verbose)
    proxy_thread = ProxyThread(sniffer)
    proxy_thread.start()

    # 等代理就绪
    if not proxy_thread.ready.wait(timeout=8):
        print("[错误] 代理启动超时")
        sys.exit(1)

    proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
    print(f"\033[90m代理: {proxy_url}   CA: {CA_CERT}\033[0m")
    print(f"\033[90m命令: {args.command}\033[0m")
    print("─" * 64)

    # 构建环境变量，让子进程走代理
    env = os.environ.copy()
    env.update({
        "http_proxy":         proxy_url,
        "https_proxy":        proxy_url,
        "HTTP_PROXY":         proxy_url,
        "HTTPS_PROXY":        proxy_url,
        # 让常见工具信任 mitmproxy 的 CA
        "SSL_CERT_FILE":      CA_CERT,
        "REQUESTS_CA_BUNDLE": CA_CERT,
        "CURL_CA_BUNDLE":     CA_CERT,
        "NODE_EXTRA_CA_CERTS": CA_CERT,
    })

    try:
        result = subprocess.run(
            args.command,
            shell=True,
            env=env,
        )
        returncode = result.returncode
    except KeyboardInterrupt:
        returncode = 130

    # 稍等，确保最后的响应都已记录
    time.sleep(0.8)
    proxy_thread.stop()

    # 输出汇总
    sniffer.print_summary()

    if args.output:
        sniffer.save_json(args.output)

    sys.exit(returncode)


if __name__ == "__main__":
    main()