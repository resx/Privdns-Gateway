# Zashboard Distribution

- Upstream: https://github.com/Zephyruso/zashboard
- Release: v3.14.0 `dist-no-fonts.zip`
- SHA256: `4c959eb6b19fad01d173a3501b1d7ec7dc8d3e7165f513398cfac8742c7e62aa`
- License: MIT, included in `LICENSE`

PrivDNS serves it at `/zashboard/` and proxies a limited, authenticated Clash
REST surface at `/zashboard/api/`. The sing-box controller remains bound to
`127.0.0.1:9090`.

Do not edit generated assets manually. Replace this directory with a verified
upstream release when upgrading, retain the license, and run the panel tests.
