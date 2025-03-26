
from typing import Optional, Any, TypedDict, Union, TypeVar, Generic, Dict
from fastapi import FastAPI, Request, HTTPException

from blockfrost import BlockFrostApi, ApiError, ApiUrls
from typing import List, Optional, Union, Literal
from .wallet import Wallet
from pycardano import *

def parse_assets(assets) -> Value:
    multi_asset = []

    for asset in assets:
        if asset["unit"] == "lovelace":
            multi_asset.append(int(asset["quantity"]))
            continue

        policy_id = asset["unit"][:56]
        asset_name = asset["unit"][56:]

        policy_exists = False

        for i, item in enumerate(multi_asset):
            if isinstance(item, dict) and policy_id in item:
                policy_exists = True
                multi_asset[i][policy_id][asset_name] = int(
                    asset["quantity"])
                break

        if not policy_exists:
            multi_asset.append({
                policy_id: {
                    asset_name: int(asset["quantity"])
                }
            })

    return Value.from_primitive(multi_asset)


def fetch_address_assets(provider: BlockFrostApi, address: str):
    response = provider.address_utxos(address=address)
    balance: Dict[str, float] = {}
    for utxo in response:
        for asset in utxo.amount:
            if asset:
                unit = asset.unit
                quantity = float(asset.quantity)
                if unit not in balance:
                    balance[unit] = 0
                balance[unit] += quantity
                
    return balance  
    