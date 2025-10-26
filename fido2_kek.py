# fido2_kek.py
# -*- coding: utf-8 -*-

import os, base64, getpass, binascii
from typing import Optional, Tuple

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, UserInteraction, DefaultClientDataCollector
from fido2.ctap2.extensions import (
    AuthenticatorExtensionsPRFInputs,
    AuthenticatorExtensionsPRFValues,
    HmacSecretExtension,
)
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

__all__ = [
    "Fido2PRFClient",
    "get_kek",            # 高层：拿 KEK（若 salt 未给则随机生成并返回）
    "register_credential" # 便捷：注册发现凭证
]

COSE_ES256 = -7


# ---------- 交互 & 宽松 CDC（仅本地使用；生产不要用） ----------
class _CLI(UserInteraction):
    def request_pin(self, *_):
        while True:
            pin = getpass.getpass("Please enter your YubiKey FIDO2 PIN (required): ").strip()
            if pin:
                return pin
            print("PIN cannot be empty, please try again.")

    def prompt_up(self):
        print("Please touch your YubiKey...")

    def request_uv(self, *_):
        print("User verification (PIN/Fingerprint) is about to begin...")
        return True

class _PermissiveCDC(DefaultClientDataCollector):
    """仅用于本地/离线实验：跳过 rpId/origin 校验。生产环境请使用默认校验。"""
    def verify_rp_id(self, rp_id: str, origin: str):
        return


# ---------- 客户端封装：只做“PRF → KEK” ----------
class Fido2PRFClient:
    """
    仅用于本地/离线环境：
    - 宽松 RP 校验（不要用于生产）
    - 注册发现凭证（带 PIN 重试）
    - 评估 PRF(salt)（带 PIN 重试）
    - PRF 经 HKDF 得到 KEK
    """
    def __init__(self, rp_id: str = "wallet.local", origin: Optional[str] = None, *, pin_retries: int = 3):
        self.rp_id = rp_id
        self.origin = origin or f"https://{rp_id}"
        self._client: Optional[Fido2Client] = None
        self.pin_retries = max(1, int(pin_retries))

    def _get_client(self) -> Fido2Client:
        if self._client is not None:
            return self._client
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            raise RuntimeError("No FIDO2 HID devices found, please insert YubiKey.")
        ext = HmacSecretExtension()  # 启用 PRF 扩展
        cdc = _PermissiveCDC(self.origin)  # 本地实验
        self._client = Fido2Client(dev, cdc, user_interaction=_CLI(), extensions=[ext])
        return self._client

    @staticmethod
    def _require_hex(s: str, name: str = "hex"):
        try:
            _ = bytes.fromhex(s)
        except (ValueError, binascii.Error):
            raise ValueError(f"{name} Not a valid hexadecimal string")

    # ---------- 注册一个发现凭证（带 PIN 重试） ----------
    def register_discoverable_credential(self, *, user_name="local-user", user_display="Local User") -> str:
        """
        返回 credential_id（hex）。
        """
        client = self._get_client()
        rp = PublicKeyCredentialRpEntity(id=self.rp_id, name="PRF RP")
        user = PublicKeyCredentialUserEntity(id=os.urandom(16), name=user_name, display_name=user_display)
        params = [PublicKeyCredentialParameters(type="public-key", alg=COSE_ES256)]

        for attempt in range(1, self.pin_retries + 1):
            prf_inputs = AuthenticatorExtensionsPRFInputs(
                eval=AuthenticatorExtensionsPRFValues(first=os.urandom(32))
            )
            opts = PublicKeyCredentialCreationOptions(
                rp=rp, user=user, challenge=os.urandom(32),
                pub_key_cred_params=params,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
                extensions={"prf": prf_inputs},
            )
            try:
                resp = client.make_credential(opts)
                cred_data = resp.response.attestation_object.auth_data.credential_data
                if not cred_data:
                    raise RuntimeError("Registration failed: No credential_data returned.")
                return cred_data.credential_id.hex()
            except Exception as e:
                em = repr(e)
                if "PIN_INVALID" in em:
                    print(f"Invalid PIN, try again ({attempt}/{self.pin_retries}) …")
                    if attempt == self.pin_retries:
                        raise RuntimeError("Multiple invalid PINs, aborted.")
                    continue
                if "PIN_AUTH_BLOCKED" in em:
                    raise RuntimeError("PIN verification is temporarily locked. Please wait until the device cools down and try again.")
                if "PIN_BLOCKED" in em:
                    raise RuntimeError("PIN is permanently locked, please reset your device.")
                raise

    # ---------- 评估 PRF(salt) → 32B 输出（带 PIN 重试） ----------
    def prf_eval(self, credential_id_hex: str, *, salt_prf: bytes) -> bytes:
        """
        返回 32 字节 PRF 输出。
        要求：
          - credential_id_hex：十六进制字符串（注册返回值）。
          - salt_prf：32 字节随机盐（调用方负责保存以便解密时复用）。
        """
        if not isinstance(salt_prf, (bytes, bytearray)) or len(salt_prf) != 32:
            raise ValueError("salt_prf must be 32 bytes.")
        self._require_hex(credential_id_hex, "credential_id_hex")

        client = self._get_client()
        for attempt in range(1, self.pin_retries + 1):
            prf_inputs = AuthenticatorExtensionsPRFInputs(
                eval=AuthenticatorExtensionsPRFValues(first=bytes(salt_prf))
            )
            req = PublicKeyCredentialRequestOptions(
                challenge=os.urandom(32),
                rp_id=self.rp_id,
                allow_credentials=[PublicKeyCredentialDescriptor(
                    type="public-key",
                    id=bytes.fromhex(credential_id_hex),
                )],
                user_verification=UserVerificationRequirement.REQUIRED,
                extensions={"prf": prf_inputs},
            )
            try:
                sel = client.get_assertion(req)
                assertion = sel.get_response(0)
                prf_out = assertion.client_extension_results.get("prf")
                if prf_out is None:
                    raise RuntimeError("The device did not return a PRF result. Please confirm that the credentials/device supports the PRF extension.")

                raw = prf_out["results"]["first"] if isinstance(prf_out, dict) else prf_out.results.first
                if isinstance(raw, (bytes, bytearray)):
                    out = bytes(raw)
                elif isinstance(raw, str):  # 某些实现用 urlsafe base64
                    try:
                        pad = "=" * ((4 - (len(raw) % 4)) % 4)
                        out = base64.urlsafe_b64decode(raw + pad)
                    except Exception as de:
                        raise RuntimeError("Failed to parse the Base64 data returned by PRF") from de
                else:
                    out = bytes(raw)

                if len(out) != 32:
                    raise RuntimeError(f"PRF output length error: {len(out)} (expected 32)")
                return out

            except Exception as e:
                em = repr(e)
                if "PIN_INVALID" in em:
                    print(f"Invalid PIN, try again ({attempt}/{self.pin_retries}) …")
                    if attempt == self.pin_retries:
                        raise RuntimeError("Multiple invalid PINs, aborted.")
                    continue
                if "PIN_AUTH_BLOCKED" in em:
                    raise RuntimeError("PIN verification is temporarily locked. Please wait until the device cools down and try again.")
                if "PIN_BLOCKED" in em:
                    raise RuntimeError("PIN is permanently locked, please reset your device.")
                raise

    # ---------- HKDF-SHA256(PRF, info) → KEK ----------
    @staticmethod
    def prf_to_kek(prf_out_32: bytes, *, info: bytes, length: int = 32) -> bytes:
        """
        建议为不同用途设定不同 info，例如：
          b"evm-priv-v1", b"btc-wif-v1", b"generic-keystore-v1"
        """
        if not isinstance(prf_out_32, (bytes, bytearray)) or len(prf_out_32) != 32:
            raise ValueError("prf_out_32 must be 32 bytes.")
        if not isinstance(info, (bytes, bytearray)) or len(info) == 0:
            raise ValueError("info must be non-empty bytes.")
        return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=bytes(info)).derive(bytes(prf_out_32))


# ---------- 统一高层：拿 KEK（加密端/解密端同用） ----------
def get_kek(
    *,
    client: Fido2PRFClient,
    credential_id_hex: str,
    info: bytes = b"privkey-v1",
    salt_prf: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """
    返回 (kek, salt_prf)：
      - 加密端：salt_prf=None → 内部随机 32B 盐并返回；请把该盐和 credential_id_hex 一并保存，解密复用。
      - 解密端：传入之前保存的 salt_prf → 能导出同一 KEK。
    注意：必须使用同一个 rpId（client.rp_id）与 credential_id_hex。
    """
    if salt_prf is None:
        salt_prf = os.urandom(32)
    elif not isinstance(salt_prf, (bytes, bytearray)) or len(salt_prf) != 32:
        raise ValueError("salt_prf must be 32 bytes or None.")

    prf_out = client.prf_eval(credential_id_hex, salt_prf=salt_prf)  # 需 PIN/触控
    kek = client.prf_to_kek(prf_out, info=info, length=32)
    return kek, bytes(salt_prf)


# ---------- 便捷包装：注册凭证 ----------
def register_credential(client: Fido2PRFClient, *, user_name="local-user", user_display="Local User") -> str:
    return client.register_discoverable_credential(user_name=user_name, user_display=user_display)
