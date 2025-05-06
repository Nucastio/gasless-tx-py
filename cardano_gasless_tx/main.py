import requests
from typing import Optional, Any, TypedDict, Union, TypeVar, Generic, Dict, Protocol
from fastapi import FastAPI, Request, HTTPException
import uvicorn

from .transaction.sponsor_tx import sponsor_tx
from .transaction.validate_tx import validate_tx
from blockfrost import BlockFrostApi, ApiError, ApiUrls
from typing import List, Optional, Union, Literal
from .wallet import Wallet
from pycardano import *
from .util import parse_assets, fetch_address_assets
from fastapi.middleware.cors import CORSMiddleware

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

class WalletProp(TypedDict):
    key: WalletCredentials
    network: Literal[0, 1]


class RequestsInstance(requests.Session):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.headers.update({
            'Content-Type': 'application/json'
        })

    def request(self, method, url, *args, **kwargs):
        url = self.base_url + url
        return super().request(method, url, *args, **kwargs)


T = TypeVar('T')


class TokenRequirement(TypedDict):
    unit: str
    quantity: int
    comparison: Literal["eq", "neq", "gt", "gte", "lt", "lte"]

class PoolConditions(TypedDict, total=False):
    tokenRequirements: Optional[list[TokenRequirement]]
    whitelist: Optional[list[str]]
    corsSettings: Optional[list[str]]
    
class SponsorTxProtocol(Protocol):
    def __call__(self, tx_cbor: str, pool_id: str, utxo: Optional[UTxO] = None) -> str: ...

class ValidateTxProtocol(Protocol):
    def __call__(self, tx_cbor: str, pool_sign_server: str) -> str: ...

class Gasless:
    def __init__(self, wallet: WalletProp, conditions: PoolConditions, api_key: str):
        self.conditions = conditions

        self.in_app_wallet = Wallet(key=wallet["key"], network=Network.TESTNET if wallet["network"] == 0 else Network.MAINNET)

        self.blockchain_provider = BlockFrostChainContext(
            project_id=api_key, network=wallet["network"], base_url=ApiUrls.preprod.value if wallet["network"] == 0 else ApiUrls.mainnet.value)

        # self.instance = RequestsInstance(api_base_url)
        self.app = FastAPI()

        self.validate_tx: ValidateTxProtocol = validate_tx.__get__(self)
        self.sponsor_tx: SponsorTxProtocol = sponsor_tx.__get__(self)
        
        if "corsSettings" in self.conditions and self.conditions["corsSettings"]:
            self.app.add_middleware(
                CORSMiddleware,
                allow_origins=self.conditions.corsSettings,
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        self.app.add_api_route("/", self.process_transaction, methods=["POST"])
        self.app.add_api_route("/conditions", self.get_conditions, methods=["GET"])

    def listen(self, port: int = 8080):
        try:
            print(f"Gasless Server is running on port {port}")
            uvicorn.run(self.app, host="0.0.0.0", port=port)
        except Exception as error:
            return {
                "success": False,
                "errror": str(error)
            }
            
    async def validate_token_requirements(self, base_tx: Transaction, sponsored_pool_hash: VerificationKeyHash) -> None:
        if not self.conditions or not self.conditions.get("tokenRequirements"):
            raise ValueError("No token requirements specified in pool conditions")

        input_set = base_tx.transaction_body.inputs
        asset_match_found = False

        for input in input_set:
            try:
                utxo = vars(self.blockchain_provider.api.transaction_utxos(input.transaction_id))
                utxo_output = next(
                    (output for output in utxo["outputs"] if output.output_index == input.index), None
                )

                if not utxo_output:
                    raise ValueError(f"No UTxO found for transaction {input.transaction_id} index {input.index}")

                input_address: Address = Address.from_primitive(utxo_output.address)
                is_sponsor_wallet = (
                    input_address.payment_part == sponsored_pool_hash
                    if sponsored_pool_hash else False
                )

                if is_sponsor_wallet:
                    continue

                address_assets = fetch_address_assets(utxo_output.address)
                for requirement in self.conditions["tokenRequirements"]:
                    unit = requirement["unit"]
                    comparison = requirement["comparison"]
                    quantity = requirement["quantity"]

                    asset_value = address_assets[unit]
                    
                    if not asset_value:
                        continue

                    asset_value = float(asset_value)
                    quantity = float(quantity)

                    if comparison == "eq" and asset_value != quantity:
                        raise ValueError(f"Expected eq {quantity} of {unit}, but found {asset_value}")
                    elif comparison == "neq" and asset_value == quantity:
                        raise ValueError(f"Expected neq {quantity} of {unit}, but found {asset_value}")
                    elif comparison == "gt" and asset_value <= quantity:
                        raise ValueError(f"Expected gt {quantity} of {unit}, but found {asset_value}")
                    elif comparison == "gte" and asset_value < quantity:
                        raise ValueError(f"Expected gte {quantity} of {unit}, but found {asset_value}")
                    elif comparison == "lt" and asset_value >= quantity:
                        raise ValueError(f"Expected lt {quantity} of {unit}, but found {asset_value}")
                    elif comparison == "lte" and asset_value > quantity:
                        raise ValueError(f"Expected lte {quantity} of {unit}, but found {asset_value}")

                    asset_match_found = True
                    break

            except Exception as e:
                raise ValueError(f"Error validating token requirements: {str(e)}")

        if not asset_match_found:
            raise ValueError("No input address holds any of the required assets")

    async def validate_whitelist(self, base_tx: Transaction):
        if not self.conditions or not self.conditions.get("whitelist"):
            raise ValueError("No whitelist specified in pool conditions")

        address_match_found = False

        for input in base_tx.transaction_body.inputs:
            utxo = vars(self.blockchain_provider.api.transaction_utxos(
                input.transaction_id))
            
            utxo_output = next(
                (output for output in utxo["outputs"] 
                 if output.output_index == input.index), None)

            if not utxo_output:
                raise ValueError(
                    f"No UTxO found for transaction {input.transaction_id} index {input.index}")

            if utxo_output.address in self.conditions["whitelist"]:
                address_match_found = True

        if not address_match_found:
            raise ValueError("Address is not in the whitelist")
        
    async def process_transaction(self, request: Request) -> Dict[str, Any]:
        try:
            body = await request.json()
            tx_cbor: str = body.get("txCbor")

            if not tx_cbor:
                raise HTTPException(
                    status_code=400, detail="Missing txCbor in request body"
                )

            base_tx: Transaction = Transaction.from_cbor(tx_cbor)

            sponsor_input_map: Dict[TransactionInput, TransactionOutput] = {}

            outputs = base_tx.transaction_body.outputs

            for input in base_tx.transaction_body.inputs:
                print(input)
                utxo = vars(self.blockchain_provider.api.transaction_utxos(
                    input.transaction_id))

                utxo_output = next(
                    (output for output in utxo["outputs"] if output.output_index == input.index), None)

                if utxo_output == None:
                    raise ValueError(
                        f"UTxO not found for input {input.transaction_id}#{input.index}")

                print(utxo_output)

                utxo_output_address = Address.from_primitive(
                    utxo_output.address)

                if (
                    utxo_output_address.payment_part
                    == self.in_app_wallet.get_payment_hash()
                ):
                    cardano_tx_out = TransactionOutput(
                        address=utxo_output_address,
                        amount=parse_assets([vars(asset)
                                            for asset in utxo_output.amount]),
                    )
                    sponsor_input_map[input] = cardano_tx_out

            consumed_utxo = []
            for utxo in sponsor_input_map.values():
                consumed_utxo.append(
                    {"lovelace": utxo.amount.coin, "assets": utxo.amount.multi_asset}
                )

            produced_utxo = []
            for output in outputs:
                output_address = output.address
                if (
                    output_address.payment_part
                    == self.in_app_wallet.get_payment_hash()
                ):
                    produced_utxo.append(
                        {
                            "lovelace": output.amount.coin,
                            "assets": output.amount.multi_asset,
                        }
                    )

            fee = base_tx.transaction_body.fee

            consumed_lovelace = sum(utxo["lovelace"] for utxo in consumed_utxo)
            produced_lovelace = sum(utxo["lovelace"] for utxo in produced_utxo)
            diff = consumed_lovelace - produced_lovelace

            if diff != fee:
                raise Exception("Fee not matching")

            for utxo in consumed_utxo:
                assets: MultiAsset = utxo.get("assets")
                if assets:
                    for key, value in assets.items():
                        if not any(
                            u.get("assets") is not None
                            and u["assets"].get(key) == value
                            for u in produced_utxo
                        ):
                            raise Exception("Missing multiassets in produced")

            if "tokenRequirements" in self.conditions and self.conditions["tokenRequirements"]:
                self.validate_token_requirements(base_tx=base_tx, sponsored_pool_hash=self.in_app_wallet.get_payment_hash())

            if "whitelist" in self.conditions and self.conditions["whitelist"]:
                self.validate_whitelist(base_tx=base_tx)

            wallet_signed = self.in_app_wallet.sk.sign(
                base_tx.transaction_body.hash())

            witnesses = []

            if base_tx.transaction_witness_set.vkey_witnesses:
                for witness in base_tx.transaction_witness_set.vkey_witnesses:
                    witnesses.append(witness)

                witnesses.append(
                    VerificationKeyWitness(
                        self.in_app_wallet.get_payment_vk(), wallet_signed)
                )
            else:
                witnesses = [VerificationKeyWitness(self.in_app_wallet.get_payment_vk(), wallet_signed)
                             ]

            new_tx = Transaction(
                base_tx.transaction_body, TransactionWitnessSet(vkey_witnesses=witnesses), auxiliary_data=base_tx.auxiliary_data, valid=True
            )
            
            return {"data": new_tx.to_cbor_hex(), "error": None, "success": True}

        except HTTPException as e:
            return {"data": None, "error": e.detail, "success": False}
        except Exception as e:
            return {"data": None, "error": str(e), "success": False}

    async def get_conditions(self, request: Request) -> Dict[str, Any]:
        
        if self.conditions == None or self.in_app_wallet == None:
            raise HTTPException(status_code=400, detail="Cannot start server - required properties (app, conditions, in_app_wallet) are not initialized")
        
        return {
            "pubKey": str(self.in_app_wallet.get_payment_hash()),
            "conditions": self.conditions
        }
