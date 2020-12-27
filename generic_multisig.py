import smartpy as sp

class HoneyPot(sp.Contract):
    def __init__(self):
        self.init(recorded_address=sp.address("tz1d393dnaDkbGk8GiKhhy1PX5qgF8XDKpEz"))

    @sp.entry_point
    def default(self):
        self.data.recorded_address = sp.sender


class ExecutionRequest():
    def get_signing_payload_type():
        return sp.TRecord(chain_id=sp.TChainId, nonce=sp.TNat, execution_payload=sp.TLambda(sp.TUnit, sp.TList(sp.TOperation))).layout(("chain_id",("nonce","execution_payload")))
        
    def get_type():
        return sp.TRecord(execution_payload=sp.TLambda(sp.TUnit, sp.TList(sp.TOperation)), signatures=sp.TMap(sp.TKeyHash,sp.TSignature)).layout(("execution_payload","signatures"))
    
    def get_signing_payload(chain_id, nonce, execution_payload):
        signing_payload = sp.record(chain_id=chain_id, nonce=nonce, execution_payload=execution_payload)
        layouted_execution_request = sp.set_type_expr(signing_payload, ExecutionRequest.get_signing_payload_type())
        return layouted_execution_request


class LambdaPacker(sp.Contract):
    def __init__(self, honeypot):
        def execution_payload(x):
            sp.set_type(x, sp.TUnit)
            honey_pot_contract = sp.contract(sp.TUnit, honeypot).open_some()
            sp.result([sp.transfer_operation(sp.unit, sp.mutez(0), honey_pot_contract)])
        self.init(payload=execution_payload)
    
class Executor(sp.Contract):
    def __init__(self, signers_threshold, operator_public_keys):
        self.init(nonce=sp.nat(0), signers_threshold=sp.nat(2), operator_public_keys=operator_public_keys)
        self.init_type(sp.TRecord(nonce=sp.TNat, signers_threshold=sp.TNat, operator_public_keys=sp.TList(sp.TKey)))

    @sp.entry_point
    def execute(self, execution_request):
        sp.set_type(execution_request, ExecutionRequest.get_type())
        signing_payload = ExecutionRequest.get_signing_payload(sp.chain_id, self.data.nonce+sp.nat(1), execution_request.execution_payload)
        
        valid_signatures_counter = sp.local('valid_signatures_counter', sp.nat(0))
        sp.for operator_public_key in self.data.operator_public_keys:
            sp.if sp.check_signature(operator_public_key, execution_request.signatures[sp.hash_key(operator_public_key)], sp.pack(signing_payload)):
                valid_signatures_counter.value += 1
        sp.verify(valid_signatures_counter.value >= self.data.signers_threshold)
        self.data.nonce += 1 
        sp.add_operations(execution_request.execution_payload(sp.unit).rev())

@sp.add_test(name = "Lambdas")
def test():
    
    chain_id=sp.chain_id_cst("0x9caecab9")
    scenario = sp.test_scenario()
    scenario.h1("Generic Multi Signature Executor")
    scenario.table_of_contents()
    
    admin = sp.test_account("Administrator")
    alice = sp.test_account("Alice")
    bob = sp.test_account("Robert")
    dan = sp.test_account("Dan")
    
    # Let's display the accounts:
    scenario.h2("Accounts")
    scenario.show([admin, alice, bob, dan])
    
    admin = sp.test_account("Administrator")
    
    # We have not found a way to pack for signature lambdas in smartpy directly
    # Hence we are using the tezos-client for helping out
    # The following payload assumes chain id 0x7a06a770, nonce 1, and a lambda hitting the honey pot at address tz1d393dnaDkbGk8GiKhhy1PX5qgF8XDKpEz
    # tezos-client -S -P 443 -A delphinet-tezos.giganode.io hash data 'Pair 0x7a06a770 (Pair 1 { DROP; NIL operation; PUSH address "tz1d393dnaDkbGk8GiKhhy1PX5qgF8XDKpEz"; CONTRACT unit; IF_SOME {} { UNIT; FAILWITH }; PUSH mutez 0; UNIT; TRANSFER_TOKENS; CONS })' of type 'pair (chain_id) (pair (nat) (lambda unit (list operation)))'
    # Raw packed data: 0x0507070a000000047a06a77007070001020000004a0320053d036d0743036e0a000000160000bed9025f33e3e29f09c45528114877c7628099e60555036c0200000010072f0200000004034f032702000000000743036a0000034f034d031b

    
    honey_pot = HoneyPot()
    honey_pot.address = sp.address("tz1d393dnaDkbGk8GiKhhy1PX5qgF8XDKpEz")
    executor = Executor(sp.nat(2), [alice.public_key, bob.public_key, dan.public_key])
    scenario += executor
    scenario += honey_pot
    
    
    def execution_payload(x):
        sp.set_type(x, sp.TUnit)
        honey_pot_contract = sp.contract(sp.TUnit, honey_pot.address).open_some()
        sp.result([sp.transfer_operation(sp.unit, sp.mutez(0), honey_pot_contract)])
    
    #lambda_packer = LambdaPacker(honey_pot.address)
    #scenario += lambda_packer
    #scenario += lambda_packer.pack_signing_payload()
    
    #execution_payload_pack = sp.pack(execution_payload)
    #scenario.show(execution_payload_pack)
    #signing_payload = ExecutionRequest.get_signing_payload(chain_id, sp.nat(1), execution_payload)
    alice_signature = sp.make_signature(alice.secret_key, sp.bytes("0x0507070a000000047a06a77007070001020000004a0320053d036d0743036e0a000000160000bed9025f33e3e29f09c45528114877c7628099e60555036c0200000010072f0200000004034f032702000000000743036a0000034f034d031b"))
    bob_signature = sp.make_signature(bob.secret_key, sp.bytes("0x0507070a000000047a06a77007070001020000004a0320053d036d0743036e0a000000160000bed9025f33e3e29f09c45528114877c7628099e60555036c0200000010072f0200000004034f032702000000000743036a0000034f034d031b"))
    dan_signature = sp.make_signature(dan.secret_key, sp.bytes("0x0507070a000000047a06a77007070001020000004a0320053d036d0743036e0a000000160000bed9025f33e3e29f09c45528114877c7628099e60555036c0200000010072f0200000004034f032702000000000743036a0000034f034d031b"))
    
    signatures= sp.map({sp.hash_key(bob.public_key):bob_signature, sp.hash_key(alice.public_key): alice_signature, sp.hash_key(dan.public_key):dan_signature})
    
    execution_request = sp.set_type_expr(sp.record(execution_payload=execution_payload, signatures=signatures),ExecutionRequest.get_type())
    scenario.show(signatures)
    
    #scenario += executor.execute(execution_request).run(sender=admin, chain_id=sp.chain_id_cst("0x7a06a770"))
    #scenario += executor.default(test2).run(sender=admin)
    #scenario += honey_pot
    
