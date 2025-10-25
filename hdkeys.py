#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BIP39 -> BIP32 -> BTC/ETH/TRON/EOS (BIP44 only, change node xkeys)
库文件：只生成 助记词 + 各链 change 层 xprv/xpub
"""

from __future__ import annotations
from typing import Tuple, Dict, Any, Optional
import struct, hashlib, base58, unicodedata, secrets, hmac
from pathlib import Path
from dataclasses import dataclass

# --- secp256k1 via coincurve (libsecp256k1) ---
from coincurve import PublicKey as CC_PublicKey, PrivateKey as CC_PrivateKey
from Cryptodome.Hash import keccak

HARDENED = 0x80000000
SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

# ========= Crypto =========
class Crypto:
    @staticmethod
    def hmac_sha512(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha512).digest()

    @staticmethod
    def sha256(b: bytes) -> bytes:
        return hashlib.sha256(b).digest()

    @staticmethod
    def ser32(i: int) -> bytes:
        return struct.pack(">L", i & 0xFFFFFFFF)
    
    @staticmethod
    def _ripemd160(b: bytes) -> bytes:
        return hashlib.new("ripemd160", b).digest()
    
    @staticmethod
    def _keccak256(b: bytes) -> bytes:
        k = keccak.new(digest_bits=256); k.update(b); 
        return k.digest()

    # ---- secp256k1 (coincurve) ----
    @staticmethod
    def priv2pubkeys(sk: bytes) -> tuple[bytes, bytes]:
        """返回 (compressed(33B), uncompressed(65B))"""
        if len(sk) != 32:
            raise ValueError("Private key must be 32 bytes")
        d = int.from_bytes(sk, "big")
        if not (1 <= d < SECP256K1_N):
            raise ValueError("Invalid secp256k1 private key")
        pub = CC_PrivateKey(sk).public_key
        return pub.format(compressed=True), pub.format(compressed=False)

# ========= Mnemonic =========
class Mnemonic:
    """BIP-39（英文词表）：懒加载并做 SHA-256 完整性校验"""
    WORDS = []
    WORD_INDEX = {}
    _VALID_STRENGTHS = (128, 160, 192, 224, 256)

    WORDLIST_PATH = Path(__file__).with_name("english.txt")
    EXPECTED_WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

    @staticmethod
    def _normalize(m: str) -> str:
        return " ".join(unicodedata.normalize("NFKD", m).strip().split())

    @classmethod
    def _load_wordlist_from_file(cls, path: Path, expected_sha256: str) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Missing BIP-39 wordlist: {path}. Put english.txt next to this file.")
        blob = path.read_bytes()
        digest = hashlib.sha256(blob).hexdigest()
        if digest != expected_sha256:
            raise RuntimeError(
                "english.txt sha256 mismatch. Expected "
                f"{expected_sha256}, got {digest}. Use the official BIP-39 English wordlist."
            )
        text = blob.decode("utf-8")
        words = [line.strip() for line in text.splitlines() if line.strip()]
        word_index = {w: i for i, w in enumerate(words)}
        cls.WORDS = words
        cls.WORD_INDEX = word_index

    @classmethod
    def ensure_wordlist(cls) -> None:
        if cls.WORDS and cls.WORD_INDEX:
            return
        cls._load_wordlist_from_file(cls.WORDLIST_PATH, cls.EXPECTED_WORDLIST_SHA256)

    @classmethod
    def is_valid(cls, mnemonic: str) -> bool:
        try:
            cls.ensure_wordlist()
            m = cls._normalize(mnemonic)
            words = m.split()
            if len(words) not in (12, 15, 18, 21, 24):
                return False
            total = 0
            for w in words:
                try:
                    idx = cls.WORD_INDEX[w]
                except KeyError:
                    return False
                total = (total << 11) | idx
            cs_len = (len(words) * 11) // 33
            ent_len = len(words) * 11 - cs_len
            ent = total >> cs_len
            cs = total & ((1 << cs_len) - 1)
            entropy = ent.to_bytes(ent_len // 8, "big")
            calc_cs = int.from_bytes(hashlib.sha256(entropy).digest(), "big") >> (256 - cs_len)
            return cs == calc_cs
        except Exception:
            return False

    @classmethod
    def generate(cls, strength: int = 128) -> str:
        cls.ensure_wordlist()
        if strength not in cls._VALID_STRENGTHS:
            raise ValueError("strength must be one of 128,160,192,224,256")
        entropy = secrets.token_bytes(strength // 8)
        ent_bits = len(entropy) * 8
        cs_bits = ent_bits // 32
        cs = int.from_bytes(hashlib.sha256(entropy).digest(), "big") >> (256 - cs_bits)
        total = (int.from_bytes(entropy, "big") << cs_bits) | cs
        nwords = (ent_bits + cs_bits) // 11
        idxs = [(total >> (11 * (nwords - 1 - i))) & 0x7FF for i in range(nwords)]
        mnemonic = " ".join(cls.WORDS[i] for i in idxs)
        if not cls.is_valid(mnemonic):  # 为稳妥保留
            raise RuntimeError("Generated mnemonic failed BIP-39 validation check")
        return mnemonic

    @classmethod
    def to_seed(cls, mnemonic: str, passphrase: str = "") -> bytes:
        cls.ensure_wordlist()
        m = cls._normalize(mnemonic)
        if not cls.is_valid(m):
            raise ValueError("Invalid BIP-39 mnemonic (checksum/words)")
        p = unicodedata.normalize("NFKD", passphrase)
        salt = ("mnemonic" + p).encode("utf-8")
        return hashlib.pbkdf2_hmac("sha512", m.encode("utf-8"), salt, 2048, dklen=64)

# ========= BIP-32 =========
class InvalidChildError(Exception): pass

class BIP32:
    @staticmethod
    def master_seed(seed: bytes) -> Tuple[bytes, bytes]:
        I = Crypto.hmac_sha512(b"Bitcoin seed", seed)
        return I[:32], I[32:]

    @staticmethod
    def ckd_priv(parent_priv: bytes, parent_chain: bytes, index: int, *, retry: bool = False) -> Tuple[bytes, bytes, int]:
        hard = (index & HARDENED) != 0
        raw  = index & 0x7FFFFFFF
        while True:
            if raw > 0x7FFFFFFF:
                raise InvalidChildError("Exhausted index space while retrying CKDpriv")
            i_try = (raw | (HARDENED if hard else 0))
            if i_try >= HARDENED:
                data = b"\x00" + parent_priv + Crypto.ser32(i_try)
            else:
                pubc, _ = Crypto.priv2pubkeys(parent_priv)
                data = pubc + Crypto.ser32(i_try)

            I = Crypto.hmac_sha512(parent_chain, data)
            Il, Ir = I[:32], I[32:]
            Il_int = int.from_bytes(Il, "big")
            if Il_int >= SECP256K1_N:
                if not retry:
                    raise InvalidChildError("Il >= curve order")
                raw += 1; continue

            kpar = int.from_bytes(parent_priv, "big")
            child_int = (Il_int + kpar) % SECP256K1_N
            if child_int == 0:
                if not retry:
                    raise InvalidChildError("Derived zero key")
                raw += 1; continue

            return child_int.to_bytes(32, "big"), Ir, i_try
        
    @staticmethod
    def ckd_pub(parent_pubc: bytes, parent_chain: bytes, index: int, *, retry: bool = False, kpar_obj: Optional[CC_PublicKey] = None) -> Tuple[bytes, bytes, int]:
        if index & HARDENED:
            raise InvalidChildError("Cannot do hardened derivation with CKDpub")
        if len(parent_pubc) != 33 or parent_pubc[0] not in (0x02, 0x03):
            raise ValueError("parent_pubc must be 33-byte compressed secp256k1 key")

        raw = index & 0x7FFFFFFF
        Kpar = kpar_obj or CC_PublicKey(parent_pubc)

        # 复用 HMAC 输入缓冲（33B pubc + 4B index）
        buf = bytearray(33 + 4)
        buf[:33] = parent_pubc

        while True:
            if raw > 0x7FFFFFFF:
                raise InvalidChildError("Exhausted index space while retrying CKDpub")
            struct.pack_into(">L", buf, 33, raw)

            I = Crypto.hmac_sha512(parent_chain, bytes(buf))
            Il, Ir = I[:32], I[32:]
            Il_int = int.from_bytes(Il, "big")

            if 0 < Il_int < SECP256K1_N:
                IlG = CC_PrivateKey(Il).public_key
                child_pub = CC_PublicKey.combine_keys([Kpar, IlG])
                return child_pub.format(compressed=True), Ir, raw

            if not retry:
                raise InvalidChildError("Il out of range in CKDpub")
            raw += 1  # 重试下一个非硬化索引

    @staticmethod
    def decode_xpub(xpub: str, index: int | None = None, *, retry: bool = False) -> Dict[str, Any]:
        """
        解析 xpub；若提供 index（非硬化），同时派生该 index 的子公钥
        警告：
          - 仅支持非硬化子键
          - 若 retry=True，遇到无效 Il 会自增 index；最终返回的 child_index 可能 != 传入 index
        """
        try:
            raw = base58.b58decode_check(xpub)
        except Exception as e:
            raise ValueError(f"Invalid xpub: {e}") from e
        if len(raw) != 78:
            raise ValueError("Invalid xpub payload length")

        info: Dict[str, Any] = {
            "version": raw[:4],
            "depth": raw[4],
            "parent": raw[5:9],
            "child":  raw[9:13],
            "chain":  raw[13:45],
            "key":    raw[45:78],
            "key_hex": raw[45:78].hex(),
        }

        if index is not None:
            if index < 0 or index >= HARDENED:
                raise ValueError("index must be in [0, 2^31-1] for CKDpub")
            parent_pubc, parent_chain = info["key"], info["chain"]
            child_pubc, child_chain, used = BIP32.ckd_pub(
                parent_pubc, parent_chain, index, retry=retry
            )
            info["child_index"] = used
            info["child_pub"] = child_pubc
            info["child_pub_hex"] = child_pubc.hex()
            info["child_chain"] = child_chain

        return info

    @staticmethod
    def derive_priv(master_priv: bytes, master_chain: bytes, path: str) -> Tuple[bytes, bytes, str, int, bytes, int]:
        if path in ("m","M",""):
            return master_priv, master_chain, "m", 0, b"\x00\x00\x00\x00", 0
        if path.startswith("m/"): path = path[2:]
        priv, cc = master_priv, master_chain
        resolved = []; depth = 0
        parent_fp = b"\x00\x00\x00\x00"; child_index = 0
        for comp in path.split("/"):
            hard = comp.endswith(("'", "h", "H"))
            if hard: comp = comp[:-1]
            try:
                i_raw = int(comp)
            except ValueError:
                raise ValueError(f"Invalid path segment: {comp!r}")
            if i_raw < 0 or i_raw > 0x7FFFFFFF:
                raise ValueError(f"Child index out of range: {i_raw}")

            pubc, _ = Crypto.priv2pubkeys(priv)
            parent_fp = Crypto._ripemd160(Crypto.sha256(pubc))[:4]

            i = i_raw + (HARDENED if hard else 0)
            priv, cc, i_resolved = BIP32.ckd_priv(priv, cc, i, retry=True)
            hard_flag = "'" if (i_resolved & HARDENED) else ""
            resolved.append(f"{i_resolved & 0x7FFFFFFF}{hard_flag}")
            child_index = i_resolved; depth += 1
        return priv, cc, "m/" + "/".join(resolved), depth, parent_fp, child_index

# ======= Extended Key (BIP-32) =======
MAINNET_VERS_XPRV = bytes.fromhex("0488ADE4")  # xprv
MAINNET_VERS_XPUB = bytes.fromhex("0488B21E")  # xpub

@dataclass(frozen=True)
class ExtendedKey:
    version_xprv: bytes = MAINNET_VERS_XPRV
    version_xpub: bytes = MAINNET_VERS_XPUB

    @staticmethod
    def _prefix(version: bytes, depth: int, parent_fingerprint: bytes, child_index: int, chain: bytes) -> bytes:
        bb = bytearray()
        bb += version
        bb += bytes([depth & 0xFF])
        bb += parent_fingerprint
        bb += Crypto.ser32(child_index)
        bb += chain
        return bytes(bb)

    def serialize_pair(self, priv: bytes, chain: bytes, depth: int, parent_fingerprint: bytes, child_index: int) -> tuple[str, str]:
        # xprv
        prefix_prv = self._prefix(self.version_xprv, depth, parent_fingerprint, child_index, chain)
        xprv_raw = prefix_prv + (b"\x00" + priv)
        xprv = base58.b58encode_check(xprv_raw).decode()
        # xpub
        pubc, _ = Crypto.priv2pubkeys(priv)
        prefix_pub = self._prefix(self.version_xpub, depth, parent_fingerprint, child_index, chain)
        xpub_raw = prefix_pub + pubc
        xpub = base58.b58encode_check(xpub_raw).decode()
        return xprv, xpub

# ========= Wallet（仅到 change 层，输出 xprv/xpub）=========
class Wallet:
    def __init__(self, mnemonic: str, passphrase: str = ""):
        # 保留 Mnemonic 校验与标准化
        if not Mnemonic.is_valid(mnemonic):
            raise ValueError("Invalid BIP-39 mnemonic (length/words/checksum).")
        self.mnemonic = Mnemonic._normalize(mnemonic)
        self.seed = Mnemonic.to_seed(self.mnemonic, passphrase)
        self.master_priv, self.master_chain = BIP32.master_seed(self.seed)

    @staticmethod
    def normalize_path(path: str) -> str:
        """将路径标准化：接受 'm/...'(推荐) 或 ''(根)；返回标准 'm/...' 字符串"""
        p = path.strip()
        if p in ("", "m", "M"):
            return "m"
        if not p.startswith(("m/", "M/")):
            # 允许传入 "44'/60'/0'/0" 这种，自动补 m/
            p = "m/" + p
        return p.replace("M/", "m/")

    def node_xkeys(self, path: str) -> Dict[str, str]:
        path = self.normalize_path(path)
        priv, cc, resolved, depth, parent_fp, child_index = BIP32.derive_priv(
            self.master_priv, self.master_chain, path
        )
        # 在该节点上序列化 xprv/xpub（无论最后是否硬化都可以）
        xprv, xpub = ExtendedKey().serialize_pair(priv, cc, depth, parent_fp, child_index)
        return {"Path": resolved, "xprv": xprv, "xpub": xpub}


# ---- Bech32 / SegWit helpers (BIP173) ----
class Bech32:
    _CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    @staticmethod
    def _polymod(values):
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = (chk >> 25) & 0xFF
            chk = ((chk & 0x1FFFFFF) << 5) ^ v
            for i in range(5):
                if (b >> i) & 1:
                    chk ^= GEN[i]
        return chk

    @staticmethod
    def _hrp_expand(hrp: str):
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    @classmethod
    def _create_checksum(cls, hrp: str, data):
        values = cls._hrp_expand(hrp) + data
        polymod = cls._polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

    @classmethod
    def encode(cls, hrp: str, data) -> str:
        combined = data + cls._create_checksum(hrp, data)
        return hrp + '1' + ''.join(cls._CHARSET[d] for d in combined)

    @staticmethod
    def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True):
        """General power-of-2 base conversion."""
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        for b in data:
            if b < 0 or (b >> frombits):
                return None
            acc = (acc << frombits) | b
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
        return ret

    # --------- 业务方法 ---------

    @classmethod
    def pub2p2wpkh(cls, pub_compressed: bytes, *, hrp: str = "bc") -> str:
        if len(pub_compressed) != 33:
            pub_compressed = CC_PublicKey(pub_compressed).format(compressed=True)
        h160 = Crypto._ripemd160(Crypto.sha256(pub_compressed))
        prog = h160
        data = [0] + cls.convertbits(h160, 8, 5, pad=True)
        return cls.encode(hrp, data)


class XpubAddress:
    """
    从 xpub 派生非硬化子公钥，并按不同链规则编码成地址/公钥表示。
    - child(xpub, index) 只做派生，不做编码
    - eth/tron/eos 分别输出该链格式
    """
    # ---------- 基础：从 xpub 派生压缩公钥 ----------
    @staticmethod
    def child(xpub: str, index: int) -> dict:
        info = BIP32.decode_xpub(xpub, index=index)  # 默认 retry=False
        pubc = info["child_pub"]  # 33B
        return {"index": info["child_index"], "pubc": pubc, "pubc_hex": pubc.hex()}
    
    @classmethod
    def _xpub2BTC(cls, xpub: str, index: int, *, testnet: bool = False) -> dict:
        info = BIP32.decode_xpub(xpub, index=index)  # decode_xpub 会返回 child_pub
        pubc = info["child_pub"]  # 33B 压缩公钥
        addr = Bech32.pub2p2wpkh(pubc, hrp="bc")
        return {"index": info["child_index"], "address": addr}

    # ---------- ETH ----------
    @classmethod
    def eth(cls, xpub: str, index: int) -> dict:
        ch = cls.child(xpub, index)
        pubc, used = ch["pubc"], ch["index"]
        # 转未压缩公钥（65B），丢掉开头 0x04 后 keccak
        pubu = CC_PublicKey(pubc).format(compressed=False)
        raw20 = Crypto._keccak256(pubu[1:])[-20:]
        lh = raw20.hex()
        hh = Crypto._keccak256(lh.encode("ascii")).hex()
        chk = "".join(c if c.isdigit() else (c.upper() if int(h, 16) >= 8 else c.lower())
                      for c, h in zip(lh, hh))
        return {"index": used, "address": "0x" + chk}

    # ---------- TRON ----------
    @classmethod
    def tron(cls, xpub: str, index: int) -> dict:
        """
        返回: {"index": i, "address": "T..."} (Base58Check，前缀 0x41)
        """
        ch = cls.child(xpub, index)
        pubc, used = ch["pubc"], ch["index"]
        pubu = CC_PublicKey(pubc).format(compressed=False)
        raw20 = Crypto._keccak256(pubu[1:])[-20:]
        addr = base58.b58encode_check(b"\x41" + raw20).decode()
        return {"index": used, "address": addr}

    # ---------- EOS ----------
    @classmethod
    def eos(cls, xpub: str, index: int) -> dict:
        ch = cls.child(xpub, index)
        pubc, used = ch["pubc"], ch["index"]
        legacy = "EOS" + base58.b58encode(pubc + Crypto._ripemd160(pubc)[:4]).decode()
        k1 = "PUB_K1_" + base58.b58encode(pubc + Crypto._ripemd160(pubc + b"K1")[:4]).decode()
        return {"index": used, "PUB_Legacy": legacy, "PUB_K1": k1}
    
