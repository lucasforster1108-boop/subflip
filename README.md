[English](README.md) | [中文](README_zh.md)

# subflip

One Python file that flips proxy share links into Clash or sing-box configs. No server, no dependencies, works offline.

## Why I wrote this

I run a few self-hosted nodes, and every client wants a different format. v2rayN eats share links, Clash wants YAML, sing-box wants its own JSON, and half the subscriptions out there are just base64 blobs. The usual fix is deploying a whole subconverter service, which felt like renting a truck to move a chair. So I wrote the converter I actually needed: a single file I can scp anywhere and run.

It is not a subscription host, not a panel, and it never touches the network. It just converts text you already have.

## What it does

- Parses `vless://`, `vmess://`, `trojan://` and `ss://` links, one per line
- Feeding it a base64 subscription blob works too — it detects and decodes it first
- Transports: tcp, websocket, grpc; TLS and Reality (public key / short id / fingerprint included)
- Outputs:
  - `to-clash` — a `proxies:` YAML block, or a complete runnable config with `--full`
  - `to-singbox` — an `outbounds` JSON document
  - `to-links` — normalized share links (handy for cleaning up a messy subscription)

## Usage

```bash
# links -> Clash proxies block
python3 subflip.py to-clash links.txt

# links -> complete Clash config (ports, one proxy group, MATCH rule)
python3 subflip.py to-clash links.txt --full -o config.yaml

# links -> sing-box outbounds
python3 subflip.py to-singbox links.txt -o outbounds.json

# a base64 subscription -> plain links
python3 subflip.py to-links subscription.txt

# stdin works too
cat links.txt | python3 subflip.py to-clash
```

Python 3.8+, standard library only. If a line can't be parsed it gets reported on stderr and skipped — one rotten link doesn't kill the batch.

See `examples/` for sample input and the exact output it produces.

## Honest limits

- It converts, it doesn't fetch. Paste the subscription content yourself; the tool stays offline on purpose.
- No Hysteria2 / TUIC yet. I don't run them, so I won't pretend to support them.
- Shadowsocks plugin support is basic (SIP002 `plugin` string is carried over, not interpreted).

## License

MIT
