#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BIP39 → BIP32 → 多链地址初始化器（BTC/ETH/TRON/EOS）
- 生成/验证助记词，按路径导出各链 xpub/zpub 与地址
- 所有链的私钥（xprv/zprv）统一打包为一个 bundle，并通过 YubiKey FIDO2 PRF → HKDF → AES‑GCM **一次性加密**
- 顶层仅保留一份加密信息：ciphertext/salt/nonce/info/credential_id
- 各链对象中不再保留明文私钥，只保留公钥与派生地址

依赖：
  - pyzipper                 : 写入 AES-256 加密 ZIP
  - cryptography[AESGCM]     : 对称加密（AES-GCM）
  - fido2_kek.py             : FIDO2 PRF 客户端封装（本地/离线实验用）
  - hdkeys                   : 你现有的派生实现（Mnemonic, Wallet, XpubAddress, Bech32）

用法（首次使用前，先注册 FIDO2 凭证，得到 credential_id_hex）：
  from fido2_kek import Fido2PRFClient, register_credential
  client = Fido2PRFClient(rp_id="wallet.local")
  cred_id_hex = register_credential(client)

运行本脚本：
  python3 init.py  # 在 __main__ 示例中填入你的 cred_id_hex
"""

from __future__ import annotations
from typing import Dict, Any, Optional, List, Union

import json
import os
import time
from getpass import getpass

import base64, binascii

import pyzipper
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fido2_kek import Fido2PRFClient, get_kek

# 你已有的本地模块（保持与原项目一致）
from hdkeys import Mnemonic, Wallet, XpubAddress, Bech32


# ------------------------------ Helpers ------------------------------

def _normalize_cred(s: str) -> str:
    """Accept hex / 0x-prefixed hex / base64 / base64url and return hex string.
    Raises ValueError if not parseable."""
    if not isinstance(s, str) or not s.strip():
        raise ValueError("credential_id_hex is empty")
    x = s.strip().lower().replace("-", "").replace(" ", "")
    if x.startswith("0x"):
        x = x[2:]
    # try hex
    try:
        _ = bytes.fromhex(x)
        return x
    except ValueError:
        pass
    # try base64 / base64url
    try:
        pad = "=" * ((4 - (len(x) % 4)) % 4)
        raw = base64.urlsafe_b64decode(x + pad)
        return raw.hex()
    except (binascii.Error, ValueError):
        pass
    raise ValueError("credential_id_hex is neither hex nor base64/base64url")

# ------------------------------ Types ------------------------------
NotesType = Dict[str, Union[str, Dict[int, str]]]


# ---------------------- ZIP 保存助记词（强加密） ----------------------
def mnemonic2zip(mnemonic: str, zip_path: str = "mnemonic.zip") -> str:
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        raise ValueError("Mnemonic is empty.")

    pwd = getpass("为助记词 ZIP 设置密码（不会回显）：").encode("utf-8")
    if not pwd:
        raise ValueError("密码不能为空。")

    content = (
        f"# BIP-39 Mnemonic (UTF-8)\n"
        f"# Generated at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n"
        f"# 请妥善保管,切勿泄露！\n\n"
        f"{mnemonic.strip()}\n"
    ).encode("utf-8")

    # 强加密：WZ_AES + 256-bit；压缩用 LZMA
    with pyzipper.AESZipFile(zip_path, "w", compression=pyzipper.ZIP_LZMA) as zf:
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        zf.setpassword(pwd)
        zf.writestr("mnemonic.txt", content)
    try:
        os.chmod(zip_path, 0o600)  # 收紧权限（类 Unix）
    except Exception:
        pass

    print(f"[OK] 助记词已加密保存到: {zip_path}（AES-256）")
    return zip_path


# --------------- YubiKey PRF/HKDF：一次派生 KEK，逐链加密 ---------------

def _derive_kek(*, rp_id: str, credential_id_hex: str, info_tag: bytes) -> tuple[AESGCM, bytes, str, str]:
    """派生一次 KEK，返回 (AESGCM(kek), salt_bytes, info_str, credential_id_hex)。
    注意：同一 KEK 可用于多个明文，但 **AES-GCM 的 nonce 必须不同**，每条链各用一个随机 nonce。"""
    client = Fido2PRFClient(rp_id=rp_id)
    kek, salt = get_kek(client=client, credential_id_hex=credential_id_hex, info=info_tag)
    return AESGCM(kek), salt, info_tag.decode(), credential_id_hex


def decrypt_priv(priv_enc: dict, kek_info: dict, *, rp_id: str) -> str:
    """解密单条链的加密私钥。
      - priv_enc: {"ciphertext","nonce","alg":"AES-GCM"}
      - kek_info: {"salt","info","credential_id"}
    返回：明文 xprv/zprv 字符串。
    """
    info_tag = kek_info.get("info", "wallet-priv-bundle-v1").encode()
    credential_id_hex = kek_info["credential_id"]
    salt = bytes.fromhex(kek_info["salt"])
    nonce = bytes.fromhex(priv_enc["nonce"])
    ct = bytes.fromhex(priv_enc["ciphertext"])

    client = Fido2PRFClient(rp_id=rp_id)
    kek, _ = get_kek(client=client, credential_id_hex=credential_id_hex, info=info_tag, salt_prf=salt)
    aesgcm = AESGCM(kek)
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode("utf-8")


# ------------------------------ 主流程 ------------------------------
def init_addr(
    mnemonic: Optional[str] = None,
    *,
    passphrase: str = "",
    strength: int = 256,
    paths: Optional[Dict[str, str]] = None,
    address_indices: Optional[Dict[str, List[int]]] = None,
    address_notes: Optional[NotesType] = None,
    # 统一硬件加密配置
    use_yubikey_encrypt: bool = True,
    rp_id: str = "wallet.local",
    credential_id_hex: Optional[str] = None,
    info_tag: bytes = b"wallet-priv-bundle-v1",
) -> Dict[str, Any]:

    # 1) 助记词
    if mnemonic is None:
        mnemo = Mnemonic.generate(strength)
    else:
        if not Mnemonic.is_valid(mnemonic):
            raise ValueError("Invalid BIP-39 mnemonic (length/words/checksum).")
        mnemo = Mnemonic._normalize(mnemonic)

    wal = Wallet(mnemo, passphrase=passphrase)

    # 2) 默认路径
    default_paths: Dict[str, str] = {
        "BTC":  "m/84'/0'/0'/0",
        "ETH":  "m/44'/60'/0'/0",
        "TRON": "m/44'/195'/0'/0",
        "EOS":  "m/44'/194'/0'/0",
    }
    path_map = paths or default_paths

    # 3) 索引
    indices_map: Dict[str, List[int]] = {k.upper(): [0] for k in path_map.keys()}
    if address_indices:
        for k, idxs in address_indices.items():
            key = k.upper()
            merged = set(indices_map.get(key, []))
            merged.update(idxs or [])
            indices_map[key] = sorted(merged)

    # 4) 备注
    notes_raw = address_notes or {}
    notes: Dict[str, Union[str, Dict[int, str]]] = {k.upper(): v for k, v in notes_raw.items()}

    out: Dict[str, Any] = {"Mnemonic": mnemo, "Chains": {}}

    # —— 统一派生 KEK（一次），逐链加密 ——
    aesgcm: Optional[AESGCM] = None
    kek_info_obj: Optional[Dict[str, str]] = None
    if use_yubikey_encrypt:
        if not credential_id_hex:
            raise ValueError("credential_id_hex is required when use_yubikey_encrypt=True")
        credential_id_hex = _normalize_cred(credential_id_hex)
        aesgcm, _salt, _info_str, _cred = _derive_kek(
            rp_id=rp_id, credential_id_hex=credential_id_hex, info_tag=info_tag
        )
        kek_info_obj = {"salt": _salt.hex(), "info": _info_str, "credential_id": _cred}

    # （未启用硬件加密时，将在链内保留明文私钥——仅测试用）

    # 5) 主循环
    for name, path in path_map.items():
        key = name.upper()

        # 取节点 xkeys：BTC 生成 zprv/zpub，其它链 xprv/xpub
        if key == "BTC":
            # 可选：强制校验路径为 BIP84
            norm = wal.normalize_path(path)
            if not norm.startswith("m/84'/0'/"):
                raise ValueError(f"BTC path must be BIP84 e.g. m/84'/0'/0'/0, got: {path}")
            node = Bech32._bc1_node_xkeys(wal, norm)      # {"Path","zprv","zpub"}
            xpub = node["zpub"]
            priv_key_name = "zprv"
        else:
            node = wal.node_xkeys(path)                    # {"Path","xprv","xpub"}
            xpub = node["xpub"]
            priv_key_name = "xprv"

        # —— 处理私钥：加密后写回当前链；若未启用硬件加密则保留明文（不推荐） ——
        priv_clear = node.get(priv_key_name)
        if not priv_clear:
            raise RuntimeError(f"No private key found for {key}.")
        if aesgcm is not None:
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, priv_clear.encode(), None)
            node["PrivEnc"] = {
                "alg": "AES-GCM",
                "nonce": nonce.hex(),
                "ciphertext": ct.hex(),
            }
            node.pop(priv_key_name, None)
        else:
            # 仅测试：不加密保留原字段
            pass

        # 生成地址
        idxs = indices_map.get(key, [0])
        addrs = []
        for i in idxs:
            if key == "BTC":
                item = XpubAddress.zpub2BTC(xpub, i)       # 用 zpub 生成 bech32
            elif key == "ETH":
                item = XpubAddress.eth(xpub, i)
            elif key == "TRON":
                item = XpubAddress.tron(xpub, i)
            elif key == "EOS":
                item = XpubAddress.eos(xpub, i)
            else:
                raise ValueError(f"Unsupported chain key: {name}")

            # 注入备注
            note_cfg = notes.get(key)
            if isinstance(note_cfg, str):
                item["note"] = note_cfg
            elif isinstance(note_cfg, dict) and i in note_cfg:
                item["note"] = note_cfg[i]

            addrs.append(item)

        out["Chains"][key] = {**node, "Address": {"extra": sorted(addrs, key=lambda a: a["index"])}}

    # 6) 顶层写入 KEKInfo（统一 salt/info/credential_id），每条链各自有 PrivEnc
    if kek_info_obj is not None:
        out["KEKInfo"] = kek_info_obj
    return out


# ------------------------------ CLI 示例 ------------------------------
if __name__ == "__main__":
    # 请先用 fido2_kek.py 注册并替换为你的 credential_id_hex
    CRED_ID_HEX = "dc76a66fada74a2c58b76b314ac8544fbcdd45593951494467f4ffe3ab08af3b5df4ac89450cc19441bb618828509176"  # e.g. 'f3ab...'
    # Accept hex / base64 / base64url / 0x-prefixed, normalize to hex
    CRED_ID_HEX = _normalize_cred(CRED_ID_HEX)

    res = init_addr(
        strength=256,
        address_indices={"ETH": [0], "BTC": [0]},
        address_notes={
            "ETH": {0: "EVM 收款地址"},
            "BTC": "主钱包收款地址",
        },
        # 统一加密启用 & 参数
        use_yubikey_encrypt=True,
        rp_id="wallet.local",
        credential_id_hex=CRED_ID_HEX,
        info_tag=b"wallet-priv-bundle-v1",
    )

    # 仅把助记词加密保存到 ZIP（ZIP 密码需人工输入）
    mnemonic2zip(res["Mnemonic"], "mnemonic.zip")

    # 打印去敏数据（不包含明文助记词），并保存到本地文件
    sanitized = {k: v for k, v in res.items() if k != "Mnemonic"}
    out_path = os.path.abspath("wallet_init.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sanitized, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(out_path, 0o600)
    except Exception:
        pass

    print(json.dumps(sanitized, ensure_ascii=False, indent=2))
    print(f"[OK] 已保存到本地: {out_path} (mode 600)")

    # 清掉内存引用
    res["Mnemonic"] = None
