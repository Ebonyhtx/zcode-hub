#!/usr/bin/env python
"""只读兼容性探针：用 ZCode Hub 的密钥派生 + enc:v1 布局解密当前凭据。

不打印任何明文/令牌，只报告成功与否、字段名与条目数量。
用法: python -I scripts/probe-client-compat.py [credentials.json 路径]
"""
import base64
import hashlib
import json
import os
import sys

ENC_PREFIX = "enc:v1:"
HOME = os.path.expanduser("~")
USER = os.environ.get("USERNAME") or os.environ.get("USER") or ""


def derive_key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def decrypt_field(key: bytes, value: str):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    payload = value[len(ENC_PREFIX):]
    parts = payload.split(".")
    if len(parts) != 3:
        return None, "invalid format (parts=%d)" % len(parts)
    dec = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    try:
        iv, tag, ct = dec(parts[0]), dec(parts[1]), dec(parts[2])
    except Exception as e:
        return None, "base64: %s" % e
    if len(iv) != 12:
        return None, "iv len=%d" % len(iv)
    if len(tag) != 16:
        return None, "tag len=%d" % len(tag)
    try:
        plain = AESGCM(key).decrypt(iv, ct + tag, None)
    except Exception as e:
        return None, "decrypt failed: %s" % type(e).__name__
    try:
        return plain.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "not utf-8"


def main(argv):
    path = argv[1] if len(argv) > 1 else os.path.join(HOME, ".zcode", "v2", "credentials.json")
    with open(path, encoding="utf-8") as f:
        creds = json.load(f)

    candidates = {
        "win32 home-style": "zcode-credential-fallback:win32:%s:%s" % (HOME, USER),
        "win32 forward-slash": "zcode-credential-fallback:win32:%s:%s" % (HOME.replace("\\", "/"), USER),
        "darwin-style": "zcode-credential-fallback:darwin:%s:%s" % (HOME, USER),
    }

    enc_fields = [k for k, v in creds.items() if isinstance(v, str) and v.startswith(ENC_PREFIX)]
    print("credentials.json: %d keys, %d enc:v1 fields" % (len(creds), len(enc_fields)))
    print("USERNAME=%r HOME=%r" % (USER, HOME))
    print()

    for label, secret in candidates.items():
        key = derive_key(secret)
        ok = fail = 0
        first_fail = None
        for k in enc_fields:
            plain, err = decrypt_field(key, creds[k])
            if plain is None:
                fail += 1
                if first_fail is None:
                    first_fail = (k, err)
            else:
                ok += 1
        status = "ALL OK" if fail == 0 else "FAIL %d" % fail
        print("[%s] %s (ok=%d fail=%d)" % (status, label, ok, fail))
        if first_fail:
            print("    first failure: %s -> %s" % first_fail)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
