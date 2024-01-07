import logging

from collections import defaultdict

from greed import options
from greed.solver.shortcuts import Equal, BV_Extract
from greed.TAC.gigahorse_ops import TAC_Nop
# from greed.utils.exceptions import GreedException, SolverTimeout

from crush.masks import get_mask, filter_masks
from crush.target import Target
from crush.sha import ShaFlowAnalysis
from crush.utils import concretize, get_shortest_backward_slice, get_shortest_forward_slice


log = logging.getLogger(__name__)


BASETYPE_TO_TYPE_STRING = {
    "bytes/string": "ee"*32,
    "array": "dd"*32,
    "mapping": "cc"*32,
    "mapping-mapping": "bb"*32,
}

MASKING_OPS = {"ADD", "SUB", "MUL", "DIV", "SDIV", "MOD", "SMOD", "ADDMOD", "MULMOD", "EXP", "SIGNEXTEND", "AND", "OR", "XOR", "NOT", "BYTE", "SHL", "SHR", "SAR"}


class StorageAccess(object):
    """
    Represents a storage access (SLOAD/SSTORE) in the contract.

    Attributes:
        pc (int): Program counter of the storage access.
        opcode (str): Opcode of the storage access (SLOAD/SSTORE).
        path (list): List of statement ids in the path from the entry point to the storage access.
        slot (int): Slot accessed by the storage access.
        is_base_slot (bool): Whether the slot is a base slot (e.g., mapping and array elements are not stored in the base slot).
        access_masks (set): Set of possible access masks for the storage slot.
        kind (str): Kind of the storage access (e.g., value, packing, string/bytes, array, mapping).
        sha_flow (ShaFlow): ShaFlow of the storage access.
        state (State): Symbolic State at the storage access.
        resolved_slot (bool): Whether the slot is resolved.
        resolved_type (bool): Whether the type is resolved.
    """
    def __init__(self, pc, opcode, path=None, slot=None, is_base_slot=None, access_masks=None, kind=None):
        self.pc = pc
        self.opcode = opcode
        self.path = path
        self.slot = slot
        self.is_base_slot = is_base_slot
        self.access_masks = access_masks or set()
        self.kind = kind # value, packing, string/bytes, array, mapping ..

        self.sha_flow = None

        self.resolved_slot = False
        self.resolved_type = False

    def __str__(self):
        return f"StorageAccess(pc={self.pc}, opcode={self.opcode}, slot={hex(self.slot) if self.slot is not None else None}, is_base_slot={self.is_base_slot}, access_masks={self.access_masks}, kind={self.kind}, resolved_slot={self.resolved_slot}, resolved_type={self.resolved_type}, path={self.path}))"

    def __repr__(self):
        return str(self)


def run_type_analysis(self_address):
    # type analysis
    options.SOLVER_TIMEOUT = 30
    options.MAX_CALLDATA_SIZE = 512
    options.GREEDY_SHA = True
    options.MAX_SHA_SIZE = 300
    options.OPTIMISTIC_CALL_RESULTS = True
    options.DEFAULT_EXTCODESIZE = True

    # TESTCASES:
    # bool: 0x3B5BE84462cb7fFf485B5d0c2e373A8a1C14a4bB
    # address: 0x000000000000BCbB63c5f383bc510eC7Ec636bAD
    # packing (bool,bool): 0x299464101d22A98CBD53D99F3cfA6862e35CBdb5
    # packing (bool,bool,address): 0x0092c3f81BC7d630dD1f885D0be67047f54D5aF1
    # bytes/string: 0x0087EB397af9E04Ff9872199d63F841474bf2A27
    # array: 0x000F045eAB5F02E8FECb527a3b73a3eC189bB0C2
    # mapping: 0x1E0A9835b0dBE721184339f0fCD1333CD3599c2e
    # mapping-mapping: 0x11c60C661cdC828c549372C9776fAAF3Ef407079

    project = Target.project_at(self_address)

    # inject one unreachable fake statement that we can use as a NOP
    fake_statement = TAC_Nop(block_id="fake", stmt_id=f"fake")
    project.statement_at[fake_statement.id] = fake_statement

    #######################################################################
    # first find all storage accesses

    sha_flow_analysis = ShaFlowAnalysis(project)

    all_storage_accesses = []
    for stmt in {s for s in project.statement_at.values() if s.__internal_name__ in {"SLOAD", "SSTORE"}}:
        try:
            access = StorageAccess(stmt.id, stmt.__internal_name__)

            # slice on key var
            _backward_slice = get_shortest_backward_slice(project, stmt, [stmt.key_var])
            access.path = _backward_slice

            found = Target.state_at(project=project, 
                                    stmt=project.statement_at[_backward_slice[-1]], 
                                    # start_from_pc=_backward_slice[0], 
                                    path=_backward_slice,
                                    tag_statements=sha_flow_analysis.all_usable_sha_ids) # path=_backward_slice

            for id, stub in found.globals["statement_tags"].items():
                if found.solver.is_formula_true(Equal(found.curr_stmt.key_val, stub)):
                    flow = sha_flow_analysis.get_flow_by_id(id)
                    basetype = ShaFlowAnalysis.infer_basetype_from_flow(flow)
                    access.slot = ShaFlowAnalysis.get_base_slot(flow)
                    if access.slot is not None:
                        access.resolved_slot = True
                    access.is_base_slot = False
                    access.kind = basetype
                    access.sha_flow = flow

                    if basetype in BASETYPE_TO_TYPE_STRING:
                        access.access_masks.add(BASETYPE_TO_TYPE_STRING[basetype])
                        access.resolved_type = True

                    break
            # else
            if access.sha_flow is None:
                slot = concretize(found, found.curr_stmt.key_val)
                if slot is not None:
                    access.slot = slot.value
                    access.resolved_slot = True
                    access.is_base_slot = True
                    access.kind = "value"

                    if access.opcode == "SLOAD":
                        # slice again on value var (instead of key var)
                        _forward_slice = get_shortest_forward_slice(project, stmt, [stmt.value_var])
                        # cut off at last masking op
                        for s_id in _forward_slice[::-1]:
                            if project.statement_at[s_id].__internal_name__ not in MASKING_OPS:
                                _forward_slice.pop()
                                continue
                            break
                        if not _forward_slice:
                            continue
                        _forward_slice += [fake_statement.id]

                        taggable = [s_id for s_id in _forward_slice if len(project.statement_at[s_id].res_vars) == 1]
                        # run again but now fix path to forward slice and stub all taggable statements
                        state = Target.state_at(project=project, 
                                                stmt=project.statement_at[_forward_slice[-1]], 
                                                path=_forward_slice, 
                                                tag_statements=taggable
                                                )
                        unmasked_bytes = [BV_Extract(i*8, i*8+7, state.globals['statement_tags'][stmt.id]) for i in range(32)]
                        for tag in taggable:
                            masked_bytes = state.globals['statement_tags'][tag]
                            mask = get_mask(state.solver, unmasked_bytes, masked_bytes)
                            if mask is not None:
                                access.access_masks.add(mask)
                                access.resolved_type = True
                                
                    elif access.opcode == "SSTORE":
                        # slice again on value var (instead of key var)
                        _backward_slice = get_shortest_backward_slice(project, stmt, [stmt.value_var])
                        if not _backward_slice:
                            continue
                        taggable = [s_id for s_id in _backward_slice if len(project.statement_at[s_id].res_vars) == 1]
                        # run again, stub all taggable statements
                        state = Target.state_at(project=project, 
                                                stmt=stmt, 
                                                path=_backward_slice, 
                                                tag_statements=taggable
                                            )
                        unmasked_bytes = [BV_Extract(i*8, i*8+7, state.curr_stmt.value_val) for i in range(32)]
                        for tag in taggable:
                            masked_bytes = state.globals['statement_tags'][tag]
                            mask = get_mask(state.solver, unmasked_bytes, masked_bytes)
                            if mask is not None:
                                access.access_masks.add(mask)
                                access.resolved_type = True

            all_storage_accesses.append(access)
        except:# (GreedException, IndexError, SolverTimeout):
            log.exception(f"Exception during the analysis of {stmt}")
    

    # default to uint256
    for access in all_storage_accesses:
        if not access.access_masks:
            access.access_masks.add("ff"*32)

    # clean slot types
    observed_masks_by_slot = defaultdict(set)
    for access in all_storage_accesses:
        if not access.resolved_slot:
            continue
        observed_masks_by_slot[access.slot].update(access.access_masks)
    for slot, masks in list(observed_masks_by_slot.items()):
        observed_masks_by_slot[slot] = filter_masks(masks)

    # for each slot, filter access masks
    for access in all_storage_accesses:
        if access.slot in observed_masks_by_slot:
            access.access_masks = filter_masks(access.access_masks, reference_masks=observed_masks_by_slot[access.slot])

    slot_types = {hex(k): sorted(observed_masks_by_slot[k]) for k in sorted(observed_masks_by_slot)}
    storage_accesses = {access.pc: {
        "slot": hex(access.slot),
        "opcode": access.opcode,
        "is_base_slot": access.is_base_slot,
        "access_masks": sorted(access.access_masks),
    } for access in sorted(all_storage_accesses, key=lambda a: a.pc) if access.resolved_slot}# and access.resolved_type}

    report = {
        "slot_types": slot_types,
        "storage_accesses": storage_accesses,
    }
    return report
