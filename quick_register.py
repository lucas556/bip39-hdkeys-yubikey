# quick_register.py
from fido2_kek import Fido2PRFClient, register_credential
client = Fido2PRFClient(rp_id="wallet.local")
cred = register_credential(client)
print(cred)
