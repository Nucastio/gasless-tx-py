from typing import List, Optional, Union, Literal
from typing import Optional, Any, TypedDict, Union, TypeVar, Generic, Dict
from pycardano import *
from bip_utils import Bip32KeyError, Bip32Slip10Ed25519
from bech32 import bech32_decode, convertbits

class WalletCredentialsMnemonic(TypedDict):
    type: str = "mnemonic"
    words: List[str]

class WalletCredentialsRoot(TypedDict):
    type: Literal["root"]
    bech32: str
    
class WalletCredentialsCli(TypedDict):
    type: Literal["cli"]
    payment: str

WalletCredentials = Union[
    WalletCredentialsMnemonic,
    WalletCredentialsRoot,
    WalletCredentialsCli
]


class Wallet:
    sk: ExtendedSigningKey
    stakeKey: StakeExtendedSigningKey
    network: Literal[0, 1]
    
    def __init__(self, key: WalletCredentials, network: Literal[0, 1]):
        
        if key['type'] == "mnemonic":
            new_wallet = crypto.bip32.HDWallet.from_mnemonic(
                "wood bench lock genuine relief coral guard reunion follow radio jewel cereal actual erosion recall")
            payment_key = new_wallet.derive_from_path(f"m/1852'/1815'/0'/0/0")
            stake_key = new_wallet.derive_from_path(f"m/1852'/1815'/0'/2/0")

            self.sk = ExtendedSigningKey.from_hdwallet(payment_key)
            self.stakeKey = ExtendedSigningKey.from_hdwallet(stake_key)

        elif key["type"] == "root":
            hrp, data = bech32_decode(key["bech32"])
            if hrp != "xprv":
                raise ValueError("Not valid")

            key_bytes = bytes(convertbits(data, 5, 8, False))

            priv_key_32 = key_bytes[:32]
            
            self.sk = PaymentSigningKey.from_cbor(bytes.fromhex("5820" + priv_key_32.hex()))
            
            bip32_root = Bip32Slip10Ed25519.FromSeedAndPath(seed=key_bytes[:64], path="m")

            # Derive staking key at m/1852'/1815'/0'/2/0
            staking_node = bip32_root.DerivePath("m/1852'/1815'/0'/2/0")
            staking_key_bytes = staking_node.PrivateKey().Raw().ToBytes()

            # Convert to pycardano StakeSigningKey
            stake_signing_key = StakeSigningKey.from_cbor(bytes.fromhex("5820" + staking_key_bytes.hex()))

            self.stakeKey = stake_signing_key
            
        elif key["type"] == "cli":
            self.sk = PaymentSigningKey.from_cbor(bytes.fromhex(key["payment"]))
            self.stakeKey = PaymentSigningKey.from_cbor(bytes.fromhex(key["stake"]))

        else:
            raise ValueError(f"Unknown wallet credential type: {key['type']}")

        
    def get_payment_hash(self):
        return self.sk.to_verification_key().hash()
    
    def get_payment_vk(self):
        return self.sk.to_verification_key()
    
    def sign_tx(self, tx: bytes):
        return self.sk.sign(tx)

    def get_address(self):
        return Address(
            payment_part=self.sk.to_verification_key().hash(),
            staking_part=self.stakeKey.to_verification_key().hash(),
            network=Network.TESTNET,
        )