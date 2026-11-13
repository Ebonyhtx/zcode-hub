#!/usr/bin/env python
"""只读兼容性探针：用 ZCode Hub 的密钥派生 + 加密布局解当前凭据。

覆盖两代格式（不打印任何明文/令牌，只报告成功与否、字段名与条目数量）：
  - enc:v1:<iv>.<tag>.<ct> —— 固定派生密钥（AES-256-GCM）
  - enc:v2:<os|env>:<fp>:<iv>.<tag>.<ct> —— 随机 32 字节密钥（3.18.0 起）
    os：Windows Credential Manager（service = ZCode Credential Encryption）；
    env：ZCODE_CREDENTIAL_SECRET / _FILE
用法: python -I scripts/probe-client-compat.py [credentials.json 路径]
"""
import base64
import ctypes
import hashlib
import json
import os
import sys

ENC_PREFIX = "enc:v1:"
V2_PREFIX = "enc:v2:"
OS_PREFIX = "enc:v2:os:"
HOME = os.path.expanduser("~")
USER = os.environ.get("USERNAME") or os.environ.get("USER") or ""


def derive_key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def aes_gcm_decrypt(key: bytes, payload: str):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


def decrypt_field(key: bytes, value: str):
    return aes_gcm_decrypt(key, value[len(ENC_PREFIX):])


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:24]


class _CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TargetName", ctypes.c_wchar_p),
        ("Comment", ctypes.c_wchar_p),
        ("LastWritten", ctypes.c_uint64),
        ("CredentialBlobSize", ctypes.c_uint32),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", ctypes.c_uint32),
        ("AttributeCount", ctypes.c_uint32),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.c_wchar_p),
        ("UserName", ctypes.c_wchar_p),
    ]


def os_keys():
    """枚举 Windows Credential Manager 的 generic 条目，解码 32 字节密钥（只读）。"""
    if sys.platform != "win32":
        return []
    advapi32 = ctypes.windll.advapi32
    count = ctypes.c_uint32(0)
    array = ctypes.POINTER(ctypes.POINTER(_CREDENTIALW))()
    if not advapi32.CredEnumerateW(None, 0, ctypes.byref(count), ctypes.byref(array)):
        return []
    keys = []
    try:
        for i in range(count.value):
            entry = array[i]
            if not entry:
                continue
            cred = entry.contents
            if cred.Type != 1 or not cred.CredentialBlobSize or not cred.CredentialBlob:
                continue
            blob = bytes(cred.CredentialBlob[: cred.CredentialBlobSize])
            text = None
            try:
                text = blob.decode("utf-16-le").strip().strip("\x00")
            except UnicodeDecodeError:
                pass
            if text is None:
                text = blob.decode("utf-8", "replace").strip().strip("\x00")
            try:
                key = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
            except Exception:
                continue
            if len(key) == 32:
                keys.append(key)
    finally:
        advapi32.CredFree(array)
    return keys


def probe_v2(creds):
    fields = [k for k, v in creds.items() if isinstance(v, str) and v.startswith(V2_PREFIX)]
    if not fields:
        return
    print()
    print("enc:v2 fields: %d" % len(fields))
    os_fields = [k for k in fields if creds[k].startswith(OS_PREFIX)]
    env_fields = [k for k in fields if creds[k].startswith("enc:v2:env:")]
    if env_fields:
        print("  enc:v2:env fields: %d（由 ZCODE_CREDENTIAL_SECRET[_FILE] 提供密钥）" % len(env_fields))
    if not os_fields:
        return
    candidates = os_keys()
    if not candidates:
        print("[FAIL] os keyring: 未在 Credential Manager 找到候选密钥（系统库不可用/未登录）")
        return
    # 按文件里的指纹挑出对应密钥
    wanted = set()
    for k in os_fields:
        rest = creds[k][len(OS_PREFIX):]
        fp = rest.split(":", 1)[0]
        if fp:
            wanted.add(fp)
    by_fp = {key_fingerprint(k): k for k in candidates}
    for fp in sorted(wanted):
        if fp not in by_fp:
            print("[FAIL] fingerprint %s: 系统库中没有匹配密钥" % fp)
            continue
        key = by_fp[fp]
        ok = fail = 0
        first_fail = None
        for name in os_fields:
            rest = creds[name][len(OS_PREFIX):]
            if rest.split(":", 1)[0] != fp:
                continue
            plain, err = aes_gcm_decrypt(key, rest.split(":", 1)[1])
            if plain is None:
                fail += 1
                if first_fail is None:
                    first_fail = (name, err)
            else:
                ok += 1
        status = "ALL OK" if fail == 0 else "FAIL %d" % fail
        print("[%s] enc:v2:os fp=%s (ok=%d fail=%d)" % (status, fp, ok, fail))
        if first_fail:
            print("    first failure: %s -> %s" % first_fail)


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
    v2_fields = [k for k, v in creds.items() if isinstance(v, str) and v.startswith(V2_PREFIX)]
    print(
        "credentials.json: %d keys, %d enc:v1 fields, %d enc:v2 fields"
        % (len(creds), len(enc_fields), len(v2_fields))
    )
    print("USERNAME=%r HOME=%r" % (USER, HOME))
    print()

    if enc_fields:
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

    probe_v2(creds)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
