[English](README.md) | [中文](README_zh.md)

# subflip

一个 Python 文件，把代理分享链接转成 Clash 或 sing-box 配置。零依赖、不用部署服务、完全离线。

## 为什么写这个

我自己有几个自建节点，每个客户端要的格式都不一样：v2rayN 吃分享链接，Clash 要 YAML，sing-box 有自己的 JSON，订阅又大多是一坨 base64。常见的解法是专门部署一个 subconverter 服务——为了转几条链接养一个服务，我嫌重。所以写了这个单文件版，scp 到哪台机器都能直接跑。

它不是订阅托管、不是面板，也永远不联网，只转换你手里已有的文本。

## 功能

- 解析 `vless://`、`vmess://`、`trojan://`、`ss://` 链接，一行一条
- 直接喂 base64 订阅也可以，会自动识别并解码
- 传输层支持 tcp、websocket、grpc；TLS 和 Reality（公钥 / short-id / 指纹都带上）
- 三种输出：
  - `to-clash`：`proxies:` YAML 片段，加 `--full` 输出一份能直接跑的完整配置
  - `to-singbox`：`outbounds` JSON
  - `to-links`：把链接规范化重写一遍，适合清理乱七八糟的订阅

## 用法

```bash
# 链接 -> Clash 节点片段
python3 subflip.py to-clash links.txt

# 链接 -> 完整 Clash 配置（端口、一个策略组、MATCH 规则）
python3 subflip.py to-clash links.txt --full -o config.yaml

# 链接 -> sing-box outbounds
python3 subflip.py to-singbox links.txt -o outbounds.json

# base64 订阅 -> 明文链接
python3 subflip.py to-links subscription.txt

# 也支持管道
cat links.txt | python3 subflip.py to-clash
```

需要 Python 3.8+，只用标准库。某一行解析不了会打到 stderr 并跳过，不会让整批跟着挂。

`examples/` 里有样例输入和它实际生成的输出，可以先对一眼再用。

## 说清楚的局限

- 只做转换，不负责拉取订阅。内容自己粘进来——离线是故意的设计。
- 暂不支持 Hysteria2 / TUIC，我自己不用，就不装样子支持了。
- Shadowsocks 插件只做基础处理（SIP002 的 `plugin` 字段原样带过去，不解析）。

## 许可证

MIT
