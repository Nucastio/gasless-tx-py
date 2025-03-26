# Gasless Tx Python Library

## Installation

```python
pip install cardano-gasless-tx

```

### Prerequisites

- Python >= 3.8
- Dependencies (automatically installed via pip):
    - `requests`
    - `pycardano`
    - `blockfrost`
    - `fastapi`
    - `uvicorn`

Ensure you have a Blockfrost API key, which you can obtain from [Blockfrost](https://blockfrost.io/).

## Usage

### Importing the Library

Import the main `Gasless` class from the library:

```python
from cardano_gasless_tx import Gasless

```

### Initialization

The `Gasless` class is the core of the library. It requires three parameters for initialization:

- **`wallet`**: A dictionary specifying wallet credentials and network.
    - `key`: Wallet credentials, supporting three types:
        - `{"type": "mnemonic", "words": List[str]}`: A list of mnemonic words (e.g., 15-word phrase).
        - `{"type": "root", "bech32": str}`: A root key in Bech32 format (e.g., `xprv...`).
        - `{"type": "cli", "payment": str}`: A CLI-generated payment key in CBOR hex format.
    - `network`: An integer indicating the Cardano network (`0` for testnet, `1` for mainnet).
- **`conditions`**: A dictionary defining transaction sponsorship conditions (optional fields):
    - `tokenRequirements`: List of token requirements (e.g., `[{"unit": "lovelace", "quantity": 1000000, "comparison": "gte"}]`) with `comparison` options: `"eq"`, `"neq"`, `"gt"`, `"gte"`, `"lt"`, `"lte"`.
    - `whitelist`: List of allowed addresses (e.g., `["addr_test1..."]`).
    - `corsSettings`: List of allowed origins for CORS (e.g., `["<http://example.com>"]`).
- **`api_key`**: A string containing your Blockfrost API key.

### Example

```python
gasless = Gasless(
    wallet={
        "key": {
            "type": "mnemonic",
            "words": ["wood", "bench", "lock", "genuine", "relief", "coral", "guard", "reunion", "follow", "radio", "jewel", "cereal", "actual", "erosion", "recall"]
        },
        "network": 0  # Testnet
    },
    conditions={
        "tokenRequirements": [{"unit": "lovelace", "quantity": 1000000, "comparison": "gte"}],
        "whitelist": ["addr_test1qrs5h59fwz22rzj2fsrlcn7lvqq2wch45h7wmm77n6a5et"],
        "corsSettings": ["<http://example.com>"]
    },
    api_key="your-blockfrost-api-key"
)

```

This creates a `Gasless` instance configured for the Cardano testnet, requiring transactions to have at least 1 ADA (1,000,000 lovelace) from a whitelisted address.

## Methods

### `listen(port: int = 8080)`

Starts a FastAPI server to handle transaction signing requests and expose pool conditions.

- **Parameters**:
    - `port` (optional): The port to run the server on (default: `8080`).
- **Returns**: None. Runs the server until interrupted.
- **Behavior**:
    - Launches a server at `0.0.0.0:port`.
    - Exposes two endpoints:
        - `POST /`: Signs transactions based on conditions.
        - `GET /conditions`: Returns the pool’s public key and conditions.

### Example

```python
gasless.listen(5050)
# Gasless Server is running on port 5050

```

### `sponsor_tx(tx_cbor: str, pool_id: str, utxo: Optional[UTxO] = None) -> str`

Sponsors the transaction fee from the pool.

- **Parameters**:
    - `tx_cbor`: The CBOR-encoded transaction as a hex string.
    - `pool_id`: The sponsor pool’s address (e.g., `addr_test1...`).
    - `utxo` (optional): A specific `UTxO` object to use for sponsoring; if `None`, selects one automatically.
- **Returns**: The CBOR-encoded sponsored transaction as a hex string.


### Example

```python
sponsored_tx = gasless.sponsor_tx(
    tx_cbor="84a4008182582059d435678d1e2484ef42d0022f10e16a5ffc481b0e572fc19f8bfe1f8a862ebb0101828258390033ecacabf249c7419632e0cef2edecf79b01128cc5cbdd9df623d00c897322abe2f5dbf69b42ede7fd14c16131cbff5de2f457151c2fd22b1a000f42408258390033ecacabf249c7419632e0cef2edecf79b01128cc5cbdd9df623d00c897322abe2f5dbf69b42ede7fd14c16131cbff5de2f457151c2fd22b1a0114c8e2020007582022eef6a148c3556e81eb018f5dfc641e108750681e70fafca8fe7ad2f510156ca0f5",
    pool_id=gasless.in_app_wallet.get_address().encode()
)
print(sponsored_tx)

```

### `validate_tx(tx_cbor: str, pool_sign_server: str) -> str`

Validates a sponsored transaction and requests the pool to sign it.

- **Parameters**:
    - `tx_cbor`: The CBOR-encoded sponsored transaction as a hex string.
    - `pool_sign_server`: The URL of the pool’s signing server (e.g., `"<http://localhost:5050>"`).
- **Returns**: The CBOR-encoded signed transaction as a hex string.

### Example

```python
signed_tx = gasless.validate_tx(
    tx_cbor=sponsored_tx,
    pool_sign_server="<http://localhost:5050>"
)
print(signed_tx)

```

## Server Endpoints

When running via `listen`, the library exposes a FastAPI server with two endpoints:

### `POST /`

- **Purpose**: Processes transaction signing requests.
- **Request Body**: JSON with `txCbor` (e.g., `{"txCbor": "hex-string"}`).
- **Response**: JSON with:
    - `data`: Signed transaction CBOR hex (if successful).
    - `error`: Error message (if failed).
    - `success`: Boolean indicating success.

### Example Request

```
curl -X POST "<http://localhost:5050/>" -H "Content-Type: application/json" -d '{"txCbor": "84a400..."}'

```

### `GET /conditions`

- **Purpose**: Retrieves the pool’s public key and conditions.
- **Response**: JSON with:
    - `pubKey`: The pool’s payment verification key hash.
    - `conditions`: The pool’s conditions dictionary.

### Example Response

```json
{
  "pubKey": "ab78e8acf6a9ba6ce0d38e7d2d1cb4f9fb0597f5feacaf6dcbd96ed4",
  "conditions": {
    "tokenRequirements": [{"unit": "lovelace", "quantity": 1000000, "comparison": "gte"}]
  }
}

```

## Examples

### Complete Workflow

This example demonstrates initializing the library, sponsoring a transaction, and validating it:

```python
from gasless_lib import Gasless
import threading

# Initialize Gasless
gasless = Gasless(
    wallet={
        "key": {
            "type": "mnemonic",
            "words": ["wood", "bench", "lock", "genuine", "relief", "coral", "guard", "reunion", "follow", "radio", "jewel", "cereal", "actual", "erosion", "recall"]
        },
        "network": 0
    },
    conditions={
        "tokenRequirements": [{"unit": "lovelace", "quantity": 1000000, "comparison": "gte"}]
    },
    api_key="your-blockfrost-api-key"
)

# Start the server in a background thread
server_thread = threading.Thread(target=gasless.listen, args=(5050,))
server_thread.daemon = True
server_thread.start()

# Sample unsigned transaction CBOR (simplified for example)
unsigned_tx_cbor = "84a4008182582059d435678d1e2484ef42d0022f10e16a5ffc481b0e572fc19f8bfe1f8a862ebb0101828258390033ecacabf249c7419632e0cef2edecf79b01128cc5cbdd9df623d00c897322abe2f5dbf69b42ede7fd14c16131cbff5de2f457151c2fd22b1a000f42408258390033ecacabf249c7419632e0cef2edecf79b01128cc5cbdd9df623d00c897322abe2f5dbf69b42ede7fd14c16131cbff5de2f457151c2fd22b1a0114c8e2020007582022eef6a148c3556e81eb018f5dfc641e108750681e70fafca8fe7ad2f510156ca0f5"

# Sponsor the transaction
sponsored_tx = gasless.sponsor_tx(
    tx_cbor=unsigned_tx_cbor,
    pool_id=gasless.in_app_wallet.get_address().encode()
)

# Validate and sign the transaction
signed_tx = gasless.validate_tx(
    tx_cbor=sponsored_tx,
    pool_sign_server="<http://localhost:5050>"
)

print("Signed Transaction CBOR:", signed_tx)

```

### Running as a Pool Server

To run `gaslesspy` as a standalone pool server:

```python
from gasless_lib import Gasless

gasless = Gasless(
    wallet={"key": {"type": "cli", "payment": "5820aaca553a7b95b38b5d9b82a5daa7a27ac8e34f3cf27152a978f4576520dd"}, "network": 0},
    conditions={"whitelist": ["addr_test1qrs5h59fwz22rzj2fsrlcn7lvqq2wch45h7wmm77n6a5et"]},
    api_key="your-blockfrost-api-key"
)

gasless.listen(port=5050)

```

This starts a server that signs transactions from whitelisted addresses.

## Advanced Usage

### Internal Validation Methods

These methods are used internally but can be useful for debugging or customization:

- **`validate_token_requirements(base_tx: Transaction, sponsored_pool_hash: VerificationKeyHash)`**:
    - Validates if transaction inputs meet token requirements.
    - Raises `ValueError` if conditions are not met.
- **`validate_whitelist(base_tx: Transaction)`**:
    - Checks if transaction input addresses are in the whitelist.
    - Raises `ValueError` if no match is found.


## Notes

- **Error Handling**: Methods like `sponsor_tx` and `validate_tx` raise exceptions on invalid inputs or failed operations. Wrap calls in try-except blocks for robust applications.
- **Network**: Use `network=0` for testnet during development to avoid spending real ADA.
- **CORS**: Configure `corsSettings` if the server will be accessed from web applications.