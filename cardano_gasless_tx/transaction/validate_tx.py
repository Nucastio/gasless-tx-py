from typing import TypedDict
import requests
from typing import Optional, Any, TypedDict, Union, TypeVar, Generic, Dict
from fastapi import FastAPI, Request, HTTPException

from blockfrost import BlockFrostApi, ApiError, ApiUrls
from typing import List, Optional, Union, Literal
from pycardano import *
from ..util import parse_assets 


def validate_tx(self, tx_cbor: str, pool_sign_server: str) -> str:
    try:
        base_tx: Transaction = Transaction.from_cbor(tx_cbor)
        
        response = requests.get(f"{pool_sign_server}/conditions")
        response.raise_for_status()
        pool_details = response.json()
        pool_conditions = pool_details["conditions"]
        pool_pub_key = VerificationKeyHash.from_primitive(pool_details["pubKey"])

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
                == pool_pub_key
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
                == pool_pub_key
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

        if "tokenRequirements" in pool_conditions and pool_conditions["tokenRequirements"]:
            self.validate_token_requirements(base_tx=base_tx, sponsored_pool_hash=pool_pub_key)

        if "whitelist" in pool_conditions and pool_conditions["whitelist"]:
            self.validate_whitelist(base_tx=base_tx)

        response = requests.post(
            pool_sign_server,
            json={"txCbor": tx_cbor}
        )
        response_data = response.json()
        
        if not response_data.get("success") or response_data.get("error"):
            raise Exception(f"Signing server error: {response_data.get('error')}")
            
        return response_data["data"]

    except Exception as error:
        raise error