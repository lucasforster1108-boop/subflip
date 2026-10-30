#!/usr/bin/env python3
"""
subflip - flip proxy share links between formats. One file, zero dependencies.

Reads vless:// vmess:// trojan:// ss:// links (one per line, or a whole
base64 subscription blob) and writes Clash YAML, sing-box JSON, or
normalized share links back out.

Usage:
    python3 subflip.py to-clash   links.txt [--full] [-o out.yaml]
    python3 subflip.py to-singbox links.txt [-o out.json]
    python3 subflip.py to-links   sub.txt   [-o links.txt]
    cat sub.txt | python3 subflip.py to-clash

Python 3.8+, standard library only.
"""

import argparse
import base64
import json
import sys
import urllib.parse

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def b64_decode(data):
    """base64-decode tolerating missing padding and urlsafe alphabets."""
    data = data.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data.replace("-", "+").replace("_", "/"))


def b64_encode(raw):
    return base64.b64encode(raw).decode()


def q(params):
    """url-encode a dict of query params, dropping empty values."""
    return urllib.parse.urlencode({k: v for k, v in params.items() if v not in ("", None)})


# ---------------------------------------------------------------------------
# link parsers -> one plain dict per node
# ---------------------------------------------------------------------------

def parse_vless(url):
    u = urllib.parse.urlparse(url)
    p = dict(urllib.parse.parse_qsl(u.query))
    node = {
        "type": "vless",
        "name": urllib.parse.unquote(u.fragment) or u.hostname,
        "server": u.hostname,
        "port": u.port or 443,
        "uuid": urllib.parse.unquote(u.username or ""),
        "network": p.get("type", "tcp"),
        "tls": p.get("security", "") in ("tls", "reality"),
        "security": p.get("security", ""),
        "sni": p.get("sni", ""),
        "fp": p.get("fp", ""),
        "flow": p.get("flow", ""),
        "alpn": p.get("alpn", ""),
    }
    if p.get("security") == "reality":
        node["reality"] = {"public_key": p.get("pbk", ""), "short_id": p.get("sid", "")}
    if node["network"] == "ws":
        node["ws"] = {"path": p.get("path", "/"), "host": p.get("host", "")}
    if node["network"] == "grpc":
        node["grpc"] = {"service_name": p.get("serviceName", "")}
    return node


def parse_vmess(url):
    raw = b64_decode(url[len("vmess://"):].split("#")[0].split("?")[0])
    d = json.loads(raw)
    node = {
        "type": "vmess",
        "name": d.get("ps") or d.get("add"),
        "server": d.get("add"),
        "port": int(d.get("port") or 443),
        "uuid": d.get("id", ""),
        "alter_id": int(d.get("aid") or 0),
        "cipher": d.get("scy", "auto"),
        "network": d.get("net", "tcp"),
        "tls": d.get("tls", "") == "tls",
        "sni": d.get("sni", "") or d.get("host", ""),
    }
    if node["network"] == "ws":
        node["ws"] = {"path": d.get("path", "/"), "host": d.get("host", "")}
    if node["network"] == "grpc":
        node["grpc"] = {"service_name": d.get("path", "")}
    return node


def parse_trojan(url):
    u = urllib.parse.urlparse(url)
    p = dict(urllib.parse.parse_qsl(u.query))
    node = {
        "type": "trojan",
        "name": urllib.parse.unquote(u.fragment) or u.hostname,
        "server": u.hostname,
        "port": u.port or 443,
        "password": urllib.parse.unquote(u.username or ""),
        "network": p.get("type", "tcp"),
        "tls": True,
        "sni": p.get("sni", "") or p.get("peer", ""),
        "alpn": p.get("alpn", ""),
        "allow_insecure": p.get("allowInsecure", "") in ("1", "true"),
    }
    if node["network"] == "ws":
        node["ws"] = {"path": p.get("path", "/"), "host": p.get("host", "")}
    if node["network"] == "grpc":
        node["grpc"] = {"service_name": p.get("serviceName", "")}
    return node


def parse_ss(url):
    body = url[len("ss://"):]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = urllib.parse.unquote(frag)
    plugin = ""
    if "?" in body:
        body, qs = body.split("?", 1)
        plugin = dict(urllib.parse.parse_qsl(qs)).get("plugin", "")
    if "@" in body:  # SIP002: base64(method:password)@host:port
        cred_b64, hostport = body.rsplit("@", 1)
        try:
            cred = b64_decode(cred_b64).decode()
            method, password = cred.split(":", 1)
        except Exception:
            method, password = urllib.parse.unquote(cred_b64), ""
        host, _, port = hostport.rpartition(":")
        if host.startswith("["):
            host = host[1:host.rindex("]")]
    else:  # legacy: base64(method:password@host:port)
        raw = b64_decode(body).decode()
        cred, hostport = raw.rsplit("@", 1)
        method, password = cred.split(":", 1)
        host, _, port = hostport.rpartition(":")
    return {
        "type": "ss",
        "name": name or host,
        "server": host,
        "port": int(port or 8388),
        "method": method,
        "password": password,
        "plugin": plugin,
    }


PARSERS = {"vless": parse_vless, "vmess": parse_vmess,
           "trojan": parse_trojan, "ss": parse_ss}


def parse_text(text):
    """Parse share links out of raw text; auto-decodes a base64 blob."""
    text = text.strip()
    if "://" not in text:
        try:
            decoded = b64_decode(text).decode()
            if "://" in decoded:
                text = decoded
        except Exception:
            pass
    nodes, skipped = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        scheme = line.split("://", 1)[0].lower()
        if scheme in PARSERS:
            try:
                nodes.append(PARSERS[scheme](line))
            except Exception as exc:
                skipped.append("%s (%s)" % (line[:60], exc))
        else:
            skipped.append(line[:60])
    return nodes, skipped


# ---------------------------------------------------------------------------
# emitters
# ---------------------------------------------------------------------------

def to_link(node):
    t = node["type"]
    host = node["server"]
    if ":" in str(host) and not str(host).startswith("["):  # IPv6
        host = "[%s]" % host
    name = urllib.parse.quote(node.get("name") or host)
    if t == "vless":
        p = {"encryption": "none"}
        if node.get("flow"):
            p["flow"] = node["flow"]
        if node.get("security"):
            p["security"] = node["security"]
        if node.get("sni"):
            p["sni"] = node["sni"]
        if node.get("fp"):
            p["fp"] = node["fp"]
        if "reality" in node:
            p["pbk"] = node["reality"]["public_key"]
            p["sid"] = node["reality"]["short_id"]
        p["type"] = node.get("network", "tcp")
        if "ws" in node:
            p["host"] = node["ws"]["host"]
            p["path"] = node["ws"]["path"]
        if "grpc" in node:
            p["serviceName"] = node["grpc"]["service_name"]
        if node.get("alpn"):
            p["alpn"] = node["alpn"]
        return "vless://%s@%s:%s?%s#%s" % (node["uuid"], host, node["port"], q(p), name)
    if t == "vmess":
        d = {
            "v": "2", "ps": node.get("name", ""), "add": node["server"],
            "port": str(node["port"]), "id": node["uuid"],
            "aid": str(node.get("alter_id", 0)), "scy": node.get("cipher", "auto"),
            "net": node.get("network", "tcp"), "type": "none",
            "host": "", "path": "", "tls": "tls" if node.get("tls") else "",
            "sni": node.get("sni", ""),
        }
        if "ws" in node:
            d["host"] = node["ws"]["host"]
            d["path"] = node["ws"]["path"]
        if "grpc" in node:
            d["path"] = node["grpc"]["service_name"]
        return "vmess://" + b64_encode(json.dumps(d, ensure_ascii=False).encode())
    if t == "trojan":
        p = {}
        if node.get("sni"):
            p["sni"] = node["sni"]
        if node.get("network") and node["network"] != "tcp":
            p["type"] = node["network"]
        if "ws" in node:
            p["host"] = node["ws"]["host"]
            p["path"] = node["ws"]["path"]
        if "grpc" in node:
            p["serviceName"] = node["grpc"]["service_name"]
        if node.get("alpn"):
            p["alpn"] = node["alpn"]
        qs = ("?" + q(p)) if p else ""
        return "trojan://%s@%s:%s%s#%s" % (
            urllib.parse.quote(node["password"], safe=""), host, node["port"], qs, name)
    if t == "ss":
        cred = b64_encode(("%s:%s" % (node["method"], node["password"])).encode())
        cred = cred.rstrip("=")  # SIP002 style
        extra = ("?plugin=" + urllib.parse.quote(node["plugin"])) if node.get("plugin") else ""
        return "ss://%s@%s:%s%s#%s" % (cred, host, node["port"], extra, name)
    raise ValueError("unknown node type %r" % t)


def _yq(value):
    """Quote a scalar for YAML (JSON strings are valid YAML strings)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def _clash_proxy(node):
    lines = ["  - name: %s" % _yq(node.get("name") or node["server"])]
    t = node["type"]
    lines.append("    type: %s" % t)
    lines.append("    server: %s" % _yq(node["server"]))
    lines.append("    port: %s" % node["port"])
    lines.append("    udp: true")
    if t in ("vless", "vmess"):
        lines.append("    uuid: %s" % _yq(node["uuid"]))
    if t == "vless":
        if node.get("flow"):
            lines.append("    flow: %s" % _yq(node["flow"]))
        if node.get("network") and node["network"] != "tcp":
            lines.append("    network: %s" % node["network"])
        if node.get("tls"):
            lines.append("    tls: true")
        if node.get("sni"):
            lines.append("    servername: %s" % _yq(node["sni"]))
        if node.get("fp"):
            lines.append("    client-fingerprint: %s" % _yq(node["fp"]))
        if node.get("alpn"):
            lines.append("    alpn: [%s]" % ", ".join(_yq(a) for a in node["alpn"].split(",")))
        if "reality" in node:
            lines.append("    reality-opts:")
            lines.append("      public-key: %s" % _yq(node["reality"]["public_key"]))
            if node["reality"]["short_id"]:
                lines.append("      short-id: %s" % _yq(node["reality"]["short_id"]))
    elif t == "vmess":
        lines.append("    alterId: %s" % node.get("alter_id", 0))
        lines.append("    cipher: %s" % _yq(node.get("cipher", "auto")))
        if node.get("network") and node["network"] != "tcp":
            lines.append("    network: %s" % node["network"])
        if node.get("tls"):
            lines.append("    tls: true")
        if node.get("sni"):
            lines.append("    servername: %s" % _yq(node["sni"]))
    elif t == "trojan":
        lines.append("    password: %s" % _yq(node["password"]))
        if node.get("sni"):
            lines.append("    sni: %s" % _yq(node["sni"]))
        if node.get("network") and node["network"] != "tcp":
            lines.append("    network: %s" % node["network"])
        if node.get("allow_insecure"):
            lines.append("    skip-cert-verify: true")
        if node.get("alpn"):
            lines.append("    alpn: [%s]" % ", ".join(_yq(a) for a in node["alpn"].split(",")))
    elif t == "ss":
        lines.append("    cipher: %s" % _yq(node["method"]))
        lines.append("    password: %s" % _yq(node["password"]))
        if node.get("plugin"):
            name, _, opts = node["plugin"].partition(";")
            lines.append("    plugin: %s" % _yq(name))
            if opts:
                lines.append("    plugin-opts:")
                for kv in opts.split(";"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        lines.append("      %s: %s" % (k, _yq(v)))
    if "ws" in node:
        lines.append("    ws-opts:")
        lines.append("      path: %s" % _yq(node["ws"]["path"]))
        if node["ws"]["host"]:
            lines.append("      headers:")
            lines.append("        Host: %s" % _yq(node["ws"]["host"]))
    if "grpc" in node:
        lines.append("    grpc-opts:")
        lines.append("      grpc-service-name: %s" % _yq(node["grpc"]["service_name"]))
    return lines


def to_clash(nodes, full=False):
    out = []
    if full:
        out += ["port: 7890", "socks-port: 7891", "allow-lan: false",
                "mode: rule", "log-level: info", ""]
    out.append("proxies:")
    for node in nodes:
        out += _clash_proxy(node)
    if full:
        names = [_yq(n.get("name") or n["server"]) for n in nodes]
        out += ["", "proxy-groups:",
                "  - name: PROXY", "    type: select",
                "    proxies: [%s]" % ", ".join(names + ["DIRECT"]),
                "", "rules:", "  - MATCH,PROXY"]
    return "\n".join(out) + "\n"


def _singbox_outbound(node):
    t = node["type"]
    ob = {"type": t, "tag": node.get("name") or node["server"],
          "server": node["server"], "server_port": node["port"]}
    if t == "vless":
        ob["uuid"] = node["uuid"]
        if node.get("flow"):
            ob["flow"] = node["flow"]
    elif t == "vmess":
        ob["uuid"] = node["uuid"]
        ob["security"] = node.get("cipher", "auto")
        ob["alter_id"] = node.get("alter_id", 0)
    elif t == "trojan":
        ob["password"] = node["password"]
    elif t == "ss":
        ob["method"] = node["method"]
        ob["password"] = node["password"]
        if node.get("plugin"):
            name, _, opts = node["plugin"].partition(";")
            ob["plugin"] = name
            if opts:
                ob["plugin_opts"] = opts
    if node.get("tls") or t == "trojan":
        tls = {"enabled": True}
        if node.get("sni"):
            tls["server_name"] = node["sni"]
        if node.get("allow_insecure"):
            tls["insecure"] = True
        if node.get("alpn"):
            tls["alpn"] = node["alpn"].split(",")
        if node.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": node["fp"]}
        if "reality" in node:
            tls["reality"] = {"enabled": True,
                              "public_key": node["reality"]["public_key"],
                              "short_id": node["reality"]["short_id"]}
        ob["tls"] = tls
    if "ws" in node:
        tr = {"type": "websocket", "path": node["ws"]["path"]}
        if node["ws"]["host"]:
            tr["headers"] = {"Host": node["ws"]["host"]}
        ob["transport"] = tr
    if "grpc" in node:
        ob["transport"] = {"type": "grpc", "service_name": node["grpc"]["service_name"]}
    return ob


def to_singbox(nodes):
    doc = {"outbounds": [_singbox_outbound(n) for n in nodes]}
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="subflip",
        description="Flip proxy share links between formats. One file, zero deps.")
    ap.add_argument("command", choices=["to-clash", "to-singbox", "to-links"],
                    help="output format")
    ap.add_argument("input", nargs="?", default="-",
                    help="input file (default: stdin)")
    ap.add_argument("-o", "--output", default="-", help="output file (default: stdout)")
    ap.add_argument("--full", action="store_true",
                    help="to-clash only: wrap proxies in a complete runnable config")
    args = ap.parse_args(argv)

    raw = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8").read()
    nodes, skipped = parse_text(raw)
    for line in skipped:
        print("subflip: skipped unparseable line: %s" % line, file=sys.stderr)
    if not nodes:
        print("subflip: no usable links found", file=sys.stderr)
        return 1

    if args.command == "to-clash":
        text = to_clash(nodes, full=args.full)
    elif args.command == "to-singbox":
        text = to_singbox(nodes)
    else:
        text = "".join(to_link(n) + "\n" for n in nodes)

    if args.output == "-":
        sys.stdout.write(text)
    else:
        open(args.output, "w", encoding="utf-8").write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
