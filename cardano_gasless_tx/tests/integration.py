from pycardano import (
    PaymentSigningKey,
    PaymentVerificationKey,
    Transaction,
    TransactionBody,
    TransactionInput,
    TransactionOutput,
    TransactionWitnessSet,
    VerificationKeyWitness,
    crypto,
    ExtendedSigningKey
)
from threading import Thread
from cardano_gasless_tx import Gasless

from time import sleep


# Assume the UTxO is sitting at index 0 of tx 732bfd67e66be8e8288349fcaaa2294973ef6271cc189a239bb431275401b8e5
tx_id = "df7f7399c3060c27c775c8f9a7573b8923d9915ba95e663618c6637e1fa7012a"
tx_in = TransactionInput.from_primitive([tx_id, 1])

address = "addr_test1wqlcn3pks3xdptxjw9pqrqtcx6ev694sstsruw3phd57ttg0lh0zq"

# Define two transaction outputs, the first one is the amount we want to send, the second one is the change.

output1 = TransactionOutput.from_primitive([address, 1000000])

output2 = TransactionOutput.from_primitive([address, 488140701])

tx_body = TransactionBody(inputs=[tx_in], outputs=[output1, output2], fee=0)

unsigned_tx = Transaction(tx_body, TransactionWitnessSet())



gasless = Gasless(wallet={"key": {"type": "mnemonic", "words": "wood bench lock genuine relief coral guard reunion follow radio jewel cereal actual erosion recall".split(
)}, "network": 0}, api_key="preprodJS4XP8SQVx5WWpsfMU7dfaOdCy9TTloQ", conditions={})

listener_thread = Thread(target=gasless.listen, args=(5000,))
# This makes the thread exit when the main program exits
listener_thread.daemon = True
listener_thread.start()


sponsored_tx = gasless.sponsor_tx(pool_id=gasless.in_app_wallet.get_address(
).encode(), tx_cbor=unsigned_tx.to_cbor_hex())

user_wallet = crypto.bip32.HDWallet.from_mnemonic(
    "sock more reward august tone polar pilot future phone moon hidden night")
payment_key = user_wallet.derive_from_path(f"m/1852'/1815'/0'/0/0")
sk = ExtendedSigningKey.from_hdwallet(payment_key)

sponsored_tx_parsed = Transaction.from_cbor(sponsored_tx)

user_signed_tx = sk.sign(sponsored_tx_parsed.transaction_body.hash())

witnesses = []

if sponsored_tx_parsed.transaction_witness_set.vkey_witnesses:
    for witness in sponsored_tx_parsed.transaction_witness_set.vkey_witnesses:
        witnesses.append(witness)

    witnesses.append(
        VerificationKeyWitness(
            sk.to_verification_key(), user_signed_tx)
    )
else:
    witnesses = [VerificationKeyWitness(
        sk.to_verification_key(), user_signed_tx)]

new_tx = Transaction(
    sponsored_tx_parsed.transaction_body, TransactionWitnessSet(vkey_witnesses=witnesses), valid=True
)
signed_tx = gasless.validate_tx(
    pool_sign_server="http://localhost:5000", tx_cbor=new_tx.to_cbor_hex())

print(signed_tx, new_tx.id ==
      Transaction.from_cbor(signed_tx).id)

sleep(4000000)
