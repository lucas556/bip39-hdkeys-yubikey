# 🔐 init.py — 多链钱包初始化（YubiKey FIDO2 加密）

本工具负责**从 BIP-39 助记词生成多链钱包（BTC / ETH / TRON / EOS）**，
并利用 **YubiKey FIDO2 PRF 扩展**派生硬件密钥对主私钥进行 AES-GCM 加密。

> **特点：**
>
> * 支持 BTC / ETH / TRON / EOS 各链 xpub/zpub 及地址派生
> * 所有链共享同一 FIDO2 派生密钥（KEK），每链独立 nonce 加密
> * 自动生成并加密助记词 ZIP（AES-256 + ZIP-LZMA）
> * 输出 JSON 包含链上地址与加密私钥（无明文 xprv/zprv）
> * 兼容 macOS / Linux，Python 3.10+

---

## 🧩 环境依赖

### Python 依赖

```bash
pip install fido2 cryptography pyzipper
```

### 系统要求

* macOS / Linux（推荐）
* 已插入并配置好 **YubiKey 5 / 5C / 5NFC**
* 已设置 FIDO2 PIN 且支持 PRF 扩展（firmware ≥ 5.2）

---

## ⚙️ 核心功能

### 1. 生成助记词并创建加密钱包

执行：

```bash
python3 init.py
```

流程说明：

1. 自动生成或导入助记词；
2. 生成四链派生路径：

   * BTC → `m/84'/0'/0'/0` （Bech32 / P2WPKH）
   * ETH → `m/44'/60'/0'/0`
   * TRON → `m/44'/195'/0'/0`
   * EOS → `m/44'/194'/0'/0`
3. 调用 YubiKey FIDO2 PRF 派生 KEK：

   ```
   PRF(salt) -> HKDF(info="wallet-priv-bundle-v1") -> KEK(32B)
   ```
4. 用 AES-GCM(KEK, nonce) 加密各链私钥；
5. 输出：

   * `mnemonic.zip`（助记词加密存档）
   * `wallet_init.json`（各链 xpub/zpub + PrivEnc + KEKInfo）

---

## 📄 输出结构

`wallet_init.json` 示例如下：

```json
{
  "Chains": {
    "BTC": {
      "Path": "m/84'/0'/0'/0",
      "zpub": "zpub6...",
      "PrivEnc": {
        "alg": "AES-GCM",
        "nonce": "d2b934...",
        "ciphertext": "ab3f9e..."
      },
      "Address": { "extra": [{ "index": 0, "address": "bc1q..." }] }
    },
    "ETH": {
      "Path": "m/44'/60'/0'/0",
      "xpub": "xpub6...",
      "PrivEnc": { "alg": "AES-GCM", "nonce": "ba1e...", "ciphertext": "..." },
      "Address": { "extra": [{ "index": 0, "address": "0x..." }] }
    },
    "TRON": { ... },
    "EOS":  { ... }
  },
  "KEKInfo": {
    "salt": "8aca89b1...",
    "info": "wallet-priv-bundle-v1",
    "credential_id": "dc76a66fada74a2c58b76b314ac8544fbcdd45593951494467f4ffe3ab08af3b5df4ac89450cc19441bb618828509176"
  }
}
```

> * 每条链的 `PrivEnc` 均独立随机 nonce；
> * 顶层的 `KEKInfo` 为所有链共享的 KEK 参数；
> * 无任何明文助记词或私钥留存。

---

## 🔓 解密单链私钥

可使用同一 YubiKey 凭证和 `KEKInfo` 进行解密：

```python
from init import decrypt_priv_with_yubikey
import json

with open("wallet_init.json", "r", encoding="utf-8") as f:
    data = json.load(f)

kek_info = data["KEKInfo"]

eth_priv = decrypt_priv_with_yubikey(
    data["Chains"]["ETH"]["PrivEnc"],
    kek_info,
    rp_id="wallet.local"
)
print("ETH xprv:", eth_priv)
```

⚠️ 解密过程会再次要求：

* YubiKey 插入；
* 正确 PIN；
* 触摸确认。

---

## 🔐 文件安全策略

| 文件                 | 内容          | 加密算法               | 保护方式                 |
| ------------------ | ----------- | ------------------ | -------------------- |
| `mnemonic.zip`     | 助记词明文       | AES-256 (ZIP-LZMA) | 用户密码                 |
| `wallet_init.json` | 各链地址 + 加密私钥 | AES-GCM(KEK)       | FIDO2 PRF + PIN + 触摸 |

所有生成文件默认权限：

```bash
chmod 600 mnemonic.zip wallet_init.json
```

---

## 🧠 关键原理图

```
                ┌────────────────────┐
                │  YubiKey FIDO2 PRF │
                └─────────┬──────────┘
                          │
                          ▼
                  PRF(salt) 32B
                          │
                          ▼
                HKDF-SHA256(PRF, info)
                          │
                          ▼
                  KEK (32 bytes)
                          │
      ┌────────────┬────────────┬────────────┬────────────┐
      ▼            ▼            ▼            ▼
   AES-GCM(BTC) AES-GCM(ETH) AES-GCM(TRON) AES-GCM(EOS)
```

* 同一 KEK；
* 每链独立随机 nonce；
* 不可离线恢复 KEK，需 YubiKey 在场。

---

## 🛠️ 常见命令

| 操作                        | 命令                              |
| ------------------------- | ------------------------------- |
| 注册可发现凭证（生成 credential_id） | `python3 quick_register.py`     |
| 运行钱包初始化                   | `python3 init.py`               |
| 查看生成文件                    | `cat wallet_init.json`          |
| 验证助记词解密                   | `7z x mnemonic.zip` 或 Python 解压 |

---

## 🧩 注意事项

1. **必须使用与注册时相同的 rp_id** (`wallet.local`)；
2. 如果重置 YubiKey 或删除凭证，将无法解密旧数据；
3. 不要同时在两个链使用同一 nonce；
4. 推荐备份：

   * `wallet_init.json`
   * `mnemonic.zip`
   * `credential_id` 值（打印或离线存储）

---

## 🧰 相关脚本

| 文件                  | 功能                         |
| ------------------- | -------------------------- |
| `fido2_kek.py`      | 封装 YubiKey PRF / HKDF 派生逻辑 |
| `init.py`           | 助记词生成、地址派生、加密输出            |
| `quick_register.py` | 快速注册可发现凭证并输出 credential_id |
| `decrypt_bundle.py` | 批量解密并打印各链 xprv/zprv（可选）    |

---

## 📜 许可证

MIT License © 2025 lucas
可自由用于研究、教学与非商业安全应用。

---

## ❤️ 致谢

* [Yubico FIDO2 Python SDK](https://github.com/Yubico/python-fido2)
* [BIP-39 / BIP-32 / BIP-44 规范作者]
* [Cryptography.io](https://cryptography.io) 项目团队
* 所有开源安全工具的贡献者 🙏
