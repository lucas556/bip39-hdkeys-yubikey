from typing import Dict, Any, Optional, List, Union
import json
import os
import time
from getpass import getpass

import pyzipper
from hdkeys import Mnemonic, Wallet, XpubAddress, Bech32


NotesType = Dict[str, Union[str, Dict[int, str]]]


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

def init_addr(
    mnemonic: Optional[str] = None, *, passphrase: str = "", strength: int = 256, paths: Optional[Dict[str, str]] = None, address_indices: Optional[Dict[str, List[int]]] = None, address_notes: Optional[NotesType] = None) -> Dict[str, Any]:

    if mnemonic is None:
        mnemo = Mnemonic.generate(strength)
    else:
        if not Mnemonic.is_valid(mnemonic):
            raise ValueError("Invalid BIP-39 mnemonic (length/words/checksum).")
        mnemo = Mnemonic._normalize(mnemonic)

    wal = Wallet(mnemo, passphrase=passphrase)

    default_paths: Dict[str, str] = {
        "BTC":  "m/84'/0'/0'/0",
        "ETH":  "m/44'/60'/0'/0",
        "TRON": "m/44'/195'/0'/0",
        "EOS":  "m/44'/194'/0'/0",
    }
    path_map = paths or default_paths

    # 4) 需要生成的索引：默认每链 [0]
    indices_map: Dict[str, List[int]] = {k.upper(): [0] for k in path_map.keys()}
    if address_indices:
        for k, idxs in address_indices.items():
            key = k.upper()
            merged = set(indices_map.get(key, []))
            merged.update(idxs or [])
            indices_map[key] = sorted(merged)

    # 5) 备注：统一 key 大写
    notes_raw = address_notes or {}
    notes: Dict[str, Union[str, Dict[int, str]]] = {k.upper(): v for k, v in notes_raw.items()}

    out: Dict[str, Any] = {"Mnemonic": mnemo, "Chains": {}}

    # 6) 正确的循环主体（注意缩进！）
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
        else:
            node = wal.node_xkeys(path)                    # {"Path","xprv","xpub"}
            xpub = node["xpub"]

        # 要生成的索引列表
        idxs = indices_map.get(key, [0])

        # 生成地址列表（全部进入 Address.extra）
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

    return out


if __name__ == "__main__":
    res = init_addr(
        strength=256,
        address_indices={"ETH": [0], "BTC": [0]},
        address_notes={
            "ETH": {0: "EVM 收款地址"},
            "BTC": "主钱包收款地址",
        },
    )

    # 仅把助记词加密保存到 ZIP
    mnemonic2zip(res["Mnemonic"], "mnemonic.zip")
    sanitized = {k: v for k, v in res.items() if k != "Mnemonic"}
    print(json.dumps(sanitized, ensure_ascii=False, indent=2))

    # 把内存里的助记词引用清掉
    res["Mnemonic"] = None
