"""远程 RULE-SET 下载与缓存。

不在每次 compile 时直连 GitHub raw。下载成功才覆盖缓存; 失败保留旧缓存。
缓存目录: <var>/rulesets/cache/
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from pathlib import Path

from .parser import ParseResult, parse_ruleset_list

USER_AGENT = "pdg/0.1 (+privdns-gateway)"
TIMEOUT = 20


def cache_path(cache_dir: Path, url: str) -> Path:
    """url → 稳定的缓存文件名。"""
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    # 取末段做人类可读前缀
    tail = url.rstrip("/").split("/")[-1] or "ruleset"
    safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in tail)
    return cache_dir / f"{safe}.{digest}.list"


def download(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 (受信 https)
        return resp.read().decode("utf-8", errors="replace")


def refresh(cache_dir: Path, url: str) -> Path:
    """下载并原子写入缓存。失败抛异常 (调用方决定是否回退旧缓存)。"""
    cache_dir.mkdir(parents=True, exist_ok=True)
    dest = cache_path(cache_dir, url)
    text = download(url)
    if not text.strip():
        raise ValueError(f"远程规则为空: {url}")
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(dest)
    return dest


def load(cache_dir: Path, url: str, policy: str, *,
         force: bool = False, allow_download: bool = True) -> ParseResult:
    """取得某 RULE-SET 的解析结果。

    优先用缓存; force 或缓存缺失时下载。下载失败但有旧缓存则回退旧缓存。
    """
    dest = cache_path(cache_dir, url)
    need = force or not dest.exists()
    if need and allow_download:
        try:
            refresh(cache_dir, url)
        except (urllib.error.URLError, ValueError, OSError) as exc:
            if not dest.exists():
                raise RuntimeError(f"下载失败且无缓存: {url} ({exc})") from exc
            # 有旧缓存 → 回退
    if not dest.exists():
        raise RuntimeError(f"无缓存可用: {url}")
    return parse_ruleset_list(dest.read_text(encoding="utf-8"), policy, source=url)
