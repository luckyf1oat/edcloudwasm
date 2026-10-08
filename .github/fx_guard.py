#!/usr/bin/env python3
"""FX abuse guard patcher.

Idempotently injects an ASN / CN-Hubei(Wuhan) block into the worker's fetch entry.
Re-applied after every upstream merge by .github/workflows/sync-upstream.yml, so it
survives the daily upstream sync of this fork.

Blocked: ASN 203090 (BITSFLOWCLOUD, JP VPS) and CN clients whose Cloudflare
geolocation is Hubei (regionCode HB / region Hubei) or city Wuhan.
Debug  : GET https://<host>/?__fxdbg=fx9d2c7b1a -> request.cf geo + wouldBlock
"""
import sys

MARK = "FX-ABUSE-GUARD-20261008"
ANCHOR = "async fetch(request, env) {"
GUARD = """
        // FX-ABUSE-GUARD-20261008  (由 .github/fx_guard.py 在每次上游同步后自动重打)
        // 拦截被外泄的免费搭车者: ASN 黑名单 + 中国湖北(武汉)地域
        {
            const _c = request.cf || {};
            const _asn = Number(_c.asn) || 0;
            const _ctry = (_c.country || '') + '';
            const _reg = ((_c.regionCode || _c.region || '') + '').toUpperCase();
            const _city = ((_c.city || '') + '').toUpperCase();
            const _blk = ([203090].indexOf(_asn) >= 0) ||
                (_ctry === 'CN' && (['HB', 'HUBEI'].indexOf(_reg) >= 0 || _city.indexOf('WUHAN') >= 0));
            if (new URL(request.url).searchParams.get('__fxdbg') === 'fx9d2c7b1a') {
                return new Response(JSON.stringify({ asn: _c.asn, country: _c.country, region: _c.region, regionCode: _c.regionCode, city: _c.city, colo: _c.colo, wouldBlock: _blk, ua: request.headers.get('user-agent') }), { headers: { 'content-type': 'application/json' } });
            }
            if (_blk) return new Response('Access denied', { status: 403 });
        }
"""


def main(path="_worker.js"):
    src = open(path, encoding="utf-8").read()
    if MARK in src:
        print("FX guard already present, nothing to do")
        return 0
    if ANCHOR not in src:
        print("ANCHOR NOT FOUND: upstream changed the fetch entry, guard NOT applied")
        return 1
    src = src.replace(ANCHOR, ANCHOR + GUARD, 1)
    open(path, "w", encoding="utf-8").write(src)
    print("FX guard injected into " + path)
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
