import logging

from ethpwn import *
from ethpwn.ethlib.evm.plugins.base import BaseAnalysisPlugin
from ethpwn.ethlib.evm.plugins.utils import *


log = logging.getLogger(__name__)


'''
NOTE: Whenever we see a CALLER executed by the candidate_target and the value
would be the confused_contract (i.e., the confused contract is calling the target),
we change it to a random address, collect the SSTOREs in the candidate_target and terminate.
'''
class FeasibilityPlugin(BaseAnalysisPlugin):

    name = "crush_feasibility"

    def __init__(self, storage_address, code_address, expected_sloads, expected_sstores):
        super().__init__()
        self.storage_address = storage_address
        self.code_address = code_address
        self.missing_sloads = set(expected_sloads)
        self.missing_sstores = set(expected_sstores)
        self.is_feasible = False

    def check_storage_and_code_address(self, computation):
        storage_address = normalize_contract_address(computation.msg.storage_address.hex())
        code_address = normalize_contract_address(computation.msg.code_address.hex())
        return storage_address == self.storage_address and code_address == self.code_address

    def pre_opcode_hook(self, opcode, computation):
        if not self.is_feasible and opcode.mnemonic in ["SSTORE", "SLOAD"] and self.check_storage_and_code_address(computation):
            # we want to remember SSTOREs
            (slot_type, slot) = computation._stack.values[-1]
            if slot_type != int:
                slot = int.from_bytes(slot, byteorder='big')
            slot = hex(slot)

            if opcode.mnemonic == "SSTORE":
                self.missing_sstores.discard(slot)
            else:
                self.missing_sloads.discard(slot)

            if not self.missing_sloads and not self.missing_sstores:
                self.is_feasible = True
                # don't stop the computation, we want to check if this reverts
                # computation.stop()

def check_feasibility(proxy:str, logic:str, sender:str, block:int, calldata:str, expected_sloads:list, expected_sstores:list):
    try:
        proxy = normalize_contract_address(proxy)
        logic = normalize_contract_address(logic)
        sender = normalize_contract_address(sender)

        evm = get_evm_at_block(block)
        evm.register_plugin(FeasibilityPlugin(storage_address=proxy, code_address=logic, expected_sloads=expected_sloads, expected_sstores=expected_sstores))

        txn_data = {
            "sender": sender,
            "to": proxy,
            "calldata": calldata,
        }

        new_txn = evm.build_new_transaction(txn_data)
        receipt, computation = evm.apply(new_txn)

        verified = evm.plugins.crush_feasibility.is_feasible
        reverted = computation.is_error
    except:
        log.exception("Something went wrong while checking feasibility")
        verified, reverted = False, True

    return verified, reverted
