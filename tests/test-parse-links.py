#!/usr/bin/env python3
"""parse_link 回归: 各类代理链接 + Surge ss 行 → 正确 sing-box 出站 dict。纯 stdlib, CI 可跑。
嵌套字段用 __ 表示层级, 如 tls__server_name → tls.server_name。"""
import base64
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("pdgbot", os.path.join(ROOT, "deploy/bot/pdg-bot.py"))
m = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(m)
except SystemExit:
    pass

from pdg_links import parse_subscription  # noqa: E402

fails = 0


def _deep(d, path):
    cur = d
    for k in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def check(name, got, **want):
    global fails
    bad = {}
    for k, v in want.items():
        key = k.replace("__", ".")
        if _deep(got, key) != v:
            bad[key] = (_deep(got, key), v)
    if bad:
        print("[FAIL]", name, bad); fails += 1
    else:
        print("[OK]  ", name)


# Surge ss 行(SS2022 + tfo + udp-relay)
check("Surge ss 行",
      m.parse_link('🇭🇰 X = ss, 1.2.3.4, 11111, encrypt-method=2022-blake3-aes-128-gcm, '
                   'password="ab+C/9==", tfo=true, udp-relay=true'),
      type="shadowsocks", tag="🇭🇰-X", server="1.2.3.4", server_port=11111,
      method="2022-blake3-aes-128-gcm", password="ab+C/9==", tcp_fast_open=True)

# ss:// SIP002
ui = base64.urlsafe_b64encode(b"aes-256-gcm:pass123").decode().rstrip("=")
check("ss:// (b64 用户信息)", m.parse_link("ss://%s@5.6.7.8:8388#name" % ui),
      type="shadowsocks", server="5.6.7.8", server_port=8388, method="aes-256-gcm", password="pass123")
check("节点名 + 还原空格", m.parse_link("ss://%s@5.6.7.8:8388#Hong+Kong+01" % ui),
      type="shadowsocks", tag="Hong-Kong-01")
check("节点名编码加号保留", m.parse_link(f"ss://{ui}@5.6.7.8:8388#Premium%2BNode"),
      type="shadowsocks", tag="Premium+Node")

# hysteria v1
check("hysteria://",
      m.parse_link("hysteria://token@hy.example.com:8443?peer=cdn.example.com&insecure=1&"
                   "upmbps=20&downmbps=100&obfs=mask&alpn=h3#HY1"),
      type="hysteria", server="hy.example.com", server_port=8443, auth_str="token",
      up_mbps=20, down_mbps=100, obfs="mask", tls__server_name="cdn.example.com",
      tls__insecure=True, tls__alpn=["h3"])

# hysteria2
check("hysteria2://",
      m.parse_link("hysteria2://mypass@h2.example.com:8443?sni=h2.example.com&insecure=1&"
                   "obfs=salamander&obfs-password=ob#HY2"),
      type="hysteria2", server="h2.example.com", server_port=8443, password="mypass",
      tls__server_name="h2.example.com", tls__insecure=True, obfs__type="salamander", obfs__password="ob")

# tuic
check("tuic://",
      m.parse_link("tuic://uuid-1234:tpass@tuic.example.com:443?sni=tuic.example.com&"
                   "congestion_control=bbr&alpn=h3#TUIC"),
      type="tuic", server="tuic.example.com", server_port=443, uuid="uuid-1234", password="tpass",
      tls__server_name="tuic.example.com", tls__alpn=["h3"], congestion_control="bbr")

# vless reality
check("vless:// reality",
      m.parse_link("vless://uuid-9@r.example.com:443?security=reality&pbk=PUBKEY&sid=ab12&"
                   "fp=chrome&flow=xtls-rprx-vision&type=tcp&sni=www.microsoft.com#REALITY"),
      type="vless", server="r.example.com", server_port=443, uuid="uuid-9", flow="xtls-rprx-vision",
      tls__server_name="www.microsoft.com", tls__reality__enabled=True, tls__reality__public_key="PUBKEY",
      tls__reality__short_id="ab12", tls__utls__enabled=True, tls__utls__fingerprint="chrome")

check("vless:// reality 默认 uTLS",
      m.parse_link("vless://uuid-10@r.example.com:443?security=reality&pbk=PUBKEY&sid=cd34&"
                   "sni=www.microsoft.com#Reality+Hong+Kong"),
      type="vless", tag="Reality-Hong-Kong", tls__reality__enabled=True, tls__utls__enabled=True,
      tls__utls__fingerprint="chrome")

# vless gRPC: serviceName= 要进 transport.service_name(不是只看 path)
check("vless:// grpc serviceName",
      m.parse_link("vless://11111111-2222-3333-4444-555555555555@g.example.com:443?"
                   "security=tls&type=grpc&serviceName=mygrpc&sni=g.example.com#GRPC"),
      type="vless", transport__type="grpc", transport__service_name="mygrpc")

# anytls
check("anytls://", m.parse_link("anytls://atpass@a.example.com:443?sni=a.example.com#ANYTLS"),
      type="anytls", server="a.example.com", server_port=443, password="atpass", tls__server_name="a.example.com")

# shadowtls v3
check("shadowtls://",
      m.parse_link("shadowtls://secret@st.example.com:443?version=3&sni=www.microsoft.com&fp=chrome#ST"),
      type="shadowtls", server="st.example.com", server_port=443, version=3, password="secret",
      tls__server_name="www.microsoft.com", tls__utls__enabled=True, tls__utls__fingerprint="chrome")

# ssh 密码认证
check("ssh://", m.parse_link("ssh://alice:p%40ss@ssh.example.com:2222#SSH"),
      type="ssh", server="ssh.example.com", server_port=2222, user="alice", password="p@ss")

# socks5
check("socks5://", m.parse_link("socks5://user:pass@1.2.3.4:1080#SOCKS"),
      type="socks", server="1.2.3.4", server_port=1080, version="5", username="user", password="pass")

# http
check("http://", m.parse_link("http://user:pass@1.2.3.4:8080#HTTP"),
      type="http", server="1.2.3.4", server_port=8080, username="user", password="pass")

# Base64 节点订阅与 SIP008
subscription = base64.urlsafe_b64encode(
    "socks5://u:p@one.example:1080#🇭🇰 香港 01\ninvalid://skip".encode()
).rstrip(b"=")
nodes, skipped = parse_subscription(subscription)
check("Base64 节点订阅", nodes[0], type="socks", server="one.example", tag="🇭🇰-香港-01")
if len(nodes) != 1 or len(skipped) != 1:
    print("[FAIL] Base64 订阅跳过统计", len(nodes), len(skipped)); fails += 1
else:
    print("[OK]   Base64 订阅跳过统计")
sip_nodes, _ = parse_subscription(json.dumps({"servers": [{
    "server": "sip.example", "server_port": 8388, "method": "aes-128-gcm",
    "password": "secret", "remarks": "SIP",
}]}).encode())
check("SIP008 节点订阅", sip_nodes[0], type="shadowsocks", server="sip.example", tag="SIP")

# Clash YAML：块映射、嵌套 WS/Reality、流式映射和不支持节点隔离
clash_yaml = b'''mixed-port: 7890
proxies:
  - name: "HK SS"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "p#ss"
  - name: VM WS
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    alterId: 0
    cipher: auto
    tls: true
    servername: vm.example.com
    network: ws
    ws-opts:
      path: /websocket
      headers:
        Host: cdn.example.com
  - name: VLESS Reality
    type: vless
    server: reality.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    flow: xtls-rprx-vision
    servername: www.microsoft.com
    client-fingerprint: chrome
    reality-opts:
      public-key: PUBKEY
      short-id: ab12
  - {name: SOCKS, type: socks5, server: 5.6.7.8, port: 1080, username: user, password: pass}
  - {name: SKIP, type: wireguard, server: 9.9.9.9, port: 51820}
proxy-groups:
  - name: Auto
    type: url-test
'''
clash_nodes, clash_skipped = parse_subscription(clash_yaml)
check("Clash YAML SS", clash_nodes[0], type="shadowsocks", tag="HK-SS", method="aes-256-gcm", password="p#ss")
check("Clash YAML VMess WS", clash_nodes[1], type="vmess", tls__server_name="vm.example.com",
      transport__type="ws", transport__path="/websocket", transport__headers__Host="cdn.example.com")
check("Clash YAML VLESS Reality", clash_nodes[2], type="vless", flow="xtls-rprx-vision",
      tls__reality__enabled=True, tls__reality__public_key="PUBKEY", tls__reality__short_id="ab12")
check("Clash YAML 流式 SOCKS", clash_nodes[3], type="socks", username="user", password="pass")
if len(clash_nodes) != 4 or len(clash_skipped) != 1 or "wireguard" not in clash_skipped[0]:
    print("[FAIL] Clash YAML 跳过统计", len(clash_nodes), clash_skipped); fails += 1
else:
    print("[OK]   Clash YAML 跳过统计")

# 非法
try:
    m.parse_link("ssh://alice@ssh.example.com:22#SSH")
    print("[FAIL] ssh 缺密码未报错"); fails += 1
except ValueError:
    print("[OK]   ssh 缺密码正确报错")

try:
    m.parse_link("garbage no scheme")
    print("[FAIL] 非法输入未报错"); fails += 1
except ValueError:
    print("[OK]   非法输入正确报错")

print("─" * 40)
print("失败 %d" % fails)
sys.exit(1 if fails else 0)
