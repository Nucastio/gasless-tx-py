from typing import TypedDict, Optional

from pycardano import *
import cbor2
from ..util import parse_assets 

def sponsor_tx(self, tx_cbor: str, pool_id: str, utxo: UTxO = None) -> str:
    try:
        if not tx_cbor or not isinstance(tx_cbor, str):
            raise ValueError('Invalid txCbor')
        if not pool_id or not isinstance(pool_id, str):
            raise ValueError('Invalid poolId')
        if utxo and not isinstance(utxo, dict) and not all(key in utxo for key in ['txHash', 'outputIndex']):
            raise ValueError('Invalid UTxO')
        
        pool_utxos = self.blockchain_provider.api.address_utxos(pool_id)

        parsed_utxos: list[UTxO] = []

        for utxo in pool_utxos:
            _utxo = vars(utxo)

            assets = [vars(asset) for asset in _utxo["amount"]]

            input = TransactionInput(TransactionId.from_primitive(
                _utxo["tx_hash"]), _utxo["tx_index"])
            utxo = UTxO(input, TransactionOutput(Address.from_primitive(
                _utxo["address"]
            ),
                parse_assets(assets)))

            parsed_utxos.append(utxo)

        sample_fee_output = TransactionOutput(Address.from_primitive(
            "addr_test1qrs5h59fwz22rzj2fsrlcn7lvqq2wch45h7wmm77n6a5etmsn92qd9m6uycped2f80k6evsmmmrfsc55jsq93daae0ustcpskv"
        ),
            Value.from_primitive(
            [
                2000000
            ]
        ))

        selected_sponsor_utxos = LargestFirstSelector().select(
            utxos=parsed_utxos, outputs=[sample_fee_output], context=self.blockchain_provider)

        sponsor_utxo = selected_sponsor_utxos[0][0]

        base_tx: Transaction = Transaction.from_cbor(tx_cbor)

        input_utxo_map: dict[TransactionInput, TransactionOutput] = {}

        included_scripts: set[str] = set()

        if base_tx.transaction_witness_set.native_scripts:
            for script in base_tx.transaction_witness_set.native_scripts:
                included_scripts.add(script.to_cbor().hex())

        for input in base_tx.transaction_body.inputs:
            utxo = vars(self.blockchain_provider.api.transaction_utxos(
                input.transaction_id))

            utxo_output = next(
                (output for output in utxo["outputs"] if output.output_index == input.index), None)

            if utxo_output == None:
                raise ValueError(
                    f"UTxO not found for input {input.transaction_id}#{input.index}")

            def _try_fix_script(scripth: str, script: PlutusScript) -> PlutusScript:
                if str(script_hash(script)) == scripth:
                    return script
                else:
                    new_script = script.__class__(cbor2.loads(script))
                    if str(script_hash(new_script)) == scripth:
                        return new_script
                    else:
                        raise ValueError("Cannot recover script from hash.")

            def _get_script(script_hash: str) -> ScriptType | None:
                script_type = self.blockchain_provider.api.script(
                    script_hash).type
                if script_type.startswith("plutusV"):
                    ps = PlutusScript.from_version(
                        int(script_type[-1]),
                        bytes.fromhex(
                            self.blockchain_provider.api.script_cbor(script_hash).cbor),
                    )
                    return _try_fix_script(script_hash, ps)
                else:
                    script_json = self.blockchain_provider.api.script_json(
                        script_hash, return_type="json"
                    )["json"]
                    return NativeScript.from_dict(script_json)

            parse_script: ScriptType | None = None

            if utxo_output.reference_script_hash:
                parse_script = _get_script(
                    utxo_output.reference_script_hash)
                if not isinstance(parse_script, PlutusScript):
                    included_scripts.append(parse_script.to_cbor().hex)

            input_utxo_map[input] = TransactionOutput(Address.from_primitive(
                utxo_output.address
            ),
                parse_assets([vars(asset) for asset in utxo_output.amount]), script=parse_script)

        if base_tx.transaction_body.reference_inputs:
            print()
            for input in base_tx.transaction_body.reference_inputs:
                print(input)
                utxo = vars(self.blockchain_provider.api.transaction_utxos(
                    input.transaction_id))

                utxo_output = next(
                    (output for output in utxo["outputs"] if output.output_index == input.index), None)

                if utxo_output == None:
                    raise ValueError(
                        f"UTxO not found for input {input.transaction_id}#{input.index}")

                # if (inputInfo.output.scriptRef) {
                # scriptsProvided.add(inputInfo.output.scriptRef.toString());
                # }

                def _try_fix_script(scripth: str, script: PlutusScript) -> PlutusScript:
                    if str(script_hash(script)) == scripth:
                        return script
                    else:
                        new_script = script.__class__(cbor2.loads(script))
                        if str(script_hash(new_script)) == scripth:
                            return new_script
                        else:
                            raise ValueError("Cannot recover script from hash.")

                def _get_script(script_hash: str) -> ScriptType | None:
                    script_type = self.blockchain_provider.api.script(
                        script_hash).type
                    if script_type.startswith("plutusV"):
                        ps = PlutusScript.from_version(
                            int(script_type[-1]),
                            bytes.fromhex(
                                self.blockchain_provider.api.script_cbor(script_hash).cbor),
                        )
                        return _try_fix_script(script_hash, ps)
                    else:
                        script_json = self.blockchain_provider.api.script_json(
                            script_hash, return_type="json"
                        )["json"]
                        return NativeScript.from_dict(script_json)

                parse_script: ScriptType | None = None

                if utxo_output.reference_script_hash:
                    parse_script = _get_script(
                        utxo_output.reference_script_hash)
                    if not isinstance(parse_script, PlutusScript):
                        included_scripts.append(parse_script.to_cbor().hex)

                input_utxo_map[input] = TransactionOutput(Address.from_primitive(
                    utxo_output.address
                ),
                    parse_assets([vars(asset) for asset in utxo_output.amount]), script=parse_script)

        base_tx.transaction_body.inputs.append(sponsor_utxo.input)
        base_tx.transaction_body.outputs.append(sponsor_utxo.output)

        input_utxo_map[sponsor_utxo.input] = sponsor_utxo.output

        pool_payment_hash = Address.decode(pool_id).payment_part

        if base_tx.transaction_body.required_signers is None:
            base_tx.transaction_body.required_signers = [pool_payment_hash]
        else:
            base_tx.transaction_body.required_signers.append(
                pool_payment_hash)

        base_tx.transaction_body.fee = 200000

        def create_dummy_tx(number_of_required_witnesses: int):
            dummy_witness_set = TransactionWitnessSet(
                vkey_witnesses=base_tx.transaction_witness_set.vkey_witnesses,
                native_scripts=base_tx.transaction_witness_set.native_scripts,
                bootstrap_witness=base_tx.transaction_witness_set.bootstrap_witness,
                plutus_v1_script=base_tx.transaction_witness_set.plutus_v1_script,
                plutus_data=base_tx.transaction_witness_set.plutus_data,
                redeemer=base_tx.transaction_witness_set.redeemer,
                plutus_v2_script=base_tx.transaction_witness_set.plutus_v2_script
            )

            dummy_vkey_witnesses: NonEmptyOrderedSet[VerificationKeyWitness] = NonEmptyOrderedSet(
            )

            for i in range(number_of_required_witnesses):
                i_bytes = i.to_bytes(32, "big")
                unique_vkey = VerificationKey.from_primitive(
                    bytes(
                        x & y
                        for x, y in zip(
                            bytes.fromhex(
                                "5797dc2cc919dfec0bb849551ebdf30d96e5cbe0f33f734a87fe826db30f7ef9"
                            ),
                            i_bytes,
                        )
                    )
                )
                unique_sig = bytes(
                    x & y
                    for x, y in zip(
                        bytes.fromhex(
                            "577ccb5b487b64e396b0976c6f71558e52e44ad254db7d06dfb79843e5441a5d"
                            "763dd42adcf5e8805d70373722ebbce62a58e3f30dd4560b9a898b8ceeab6a03"
                        ),
                        i_bytes + i_bytes,  # 64 bytes for signature
                    )
                )
                dummy_vkey_witnesses.append(
                    VerificationKeyWitness(unique_vkey, unique_sig))

            dummy_witness_set.vkey_witnesses = dummy_vkey_witnesses

            return Transaction(base_tx.transaction_body, dummy_witness_set, True, base_tx.auxiliary_data)

        def _ref_script_size():
            ref_script_size = 0
            
            if base_tx.transaction_body.reference_inputs:
                for input in base_tx.transaction_body.reference_inputs:
                    _script = input_utxo_map[input].script
                    if isinstance(_script, NativeScript):
                        ref_script_size += len(_script.to_cbor())
                    else:
                        combined_cbor = cbor2.dumps([2, _script])

                        ref_script_size += len(combined_cbor)
            return ref_script_size

        newFee = fee(self.blockchain_provider, len(
            create_dummy_tx(count_number_of_required_witnesses(
                base_tx.transaction_body, input_utxo_map, included_scripts)).to_cbor()), ref_script_size=_ref_script_size())

        base_tx.transaction_body.fee = newFee

        base_tx.transaction_body.outputs = base_tx.transaction_body.outputs[:-1]

        sponsor_utxo.output.amount.coin = sponsor_utxo.output.amount.coin - newFee

        base_tx.transaction_body.outputs.append(sponsor_utxo.output)

        return base_tx.to_cbor_hex()
    except Exception as error:
        raise error


def count_number_of_required_witnesses(tx_body: TransactionBody, utxo_context: dict[TransactionInput, TransactionOutput], scripts_provided: set[str]) -> int:

    required_witnesses: set[str] = set()

    for input in tx_body.inputs:

        print(input)
        _address = utxo_context[input].address

        if _address.address_type.value == 0:
            required_witnesses.add(_address.payment_part)

    if tx_body.collateral:
        for collateral in tx_body.collateral:
            _address = utxo_context[collateral].address

            if _address.address_type.value == 0:
                required_witnesses.add(_address.payment_part)

    if tx_body.withdraws:
        for address_bytes in tx_body.withdraws.keys():
            required_witnesses.add(address_bytes.hex())

    if tx_body.certificates:

        def _check_and_add_vkey(stake_credential: StakeCredential):
            if isinstance(stake_credential.credential, VerificationKeyHash):
                required_witnesses.add(stake_credential.credential)

        for cert in tx_body.certificates:
            if isinstance(
                cert,
                (
                    StakeRegistration,
                    StakeDeregistration,
                    StakeDelegation,
                    StakeRegistrationConway,
                    StakeDeregistrationConway,
                    VoteDelegation,
                    StakeAndVoteDelegation,
                    StakeRegistrationAndDelegation,
                    StakeRegistrationAndVoteDelegation,
                    StakeRegistrationAndDelegationAndVoteDelegation,
                ),
            ):
                _check_and_add_vkey(cert.stake_credential)
            elif isinstance(cert, RegDRepCert):
                _check_and_add_vkey(cert.drep_credential)
            elif isinstance(cert, PoolRegistration):
                required_witnesses.add(cert.pool_params.operator)
            elif isinstance(cert, PoolRetirement):
                required_witnesses.add(cert.pool_keyhash)

    for script_hex in scripts_provided:
        native_script = NativeScript.from_cbor(script_hex)

        add_key_hashes_from_native_scripts(native_script)

    if tx_body.required_signers:
        for signer in tx_body.required_signers:
            required_witnesses.add(signer)

    return len(required_witnesses)


def add_key_hashes_from_native_scripts(native_script: NativeScript, required_witnesses: set[str]):
    if isinstance(native_script, ScriptPubkey):
        required_witnesses.append(native_script.key_hash)
    elif isinstance(native_script, ScriptAll):
        for script in native_script.native_scripts:
            add_key_hashes_from_native_scripts(script, required_witnesses)
    elif isinstance(native_script, ScriptAny):
        for script in native_script.native_scripts:
            add_key_hashes_from_native_scripts(script, required_witnesses)
    elif isinstance(native_script, ScriptNofK):
        for script in native_script.native_scripts:
            add_key_hashes_from_native_scripts(script, required_witnesses)
