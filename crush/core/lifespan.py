import logging
import networkx as nx

from yices.YicesException import YicesException

from greed import options
from greed.utils.exceptions import GreedException
from greed.solver.shortcuts import is_concrete, bv_unsigned_value, BV_Extract, BV_Concat, BVV

from crush import globals
from crush.globals import w3
from crush.target import Target, TargetUnknown, TargetConstant, TargetStorage, TargetCalldata, TargetExternal, NestedTargetConstant, Proxy
from crush.masks import get_mask
from crush.sql import run_query
from crush.utils import get_shortest_backward_slice


def __custom__hash__(self):
    return hash((self.__class__.__name__, self.address, self.window_start, self.window_end))
Target.__hash__ = __custom__hash__


log = logging.getLogger(__name__)


WINDOW_START = None


def _recursive_bisect_partitions(w3, address, slot, mask, start_block, end_block):
    start_value = w3.eth.get_storage_at(address, slot, start_block).hex()
    start_value = f"{int(start_value, 16):064x}"
    start_value = "0x"+"".join([start_value[i] for i, _ in enumerate(mask) if mask[i] == "f"])
    start_value = w3.to_checksum_address(start_value)

    end_value = w3.eth.get_storage_at(address, slot, end_block).hex()
    end_value = f"{int(end_value, 16):064x}"
    end_value = "0x"+"".join([end_value[i] for i, _ in enumerate(mask) if mask[i] == "f"])
    end_value = w3.to_checksum_address(end_value)

    # if same value, stop partitioning
    if start_value == end_value:
        return [(start_block, end_block, start_value)]
    # if two values but only two blocks, partition one last time
    elif end_block - start_block <= 1:
        return [(start_block, start_block, start_value), (end_block, end_block, end_value)]
    else:
        mid_block = (start_block + end_block) // 2
        return _recursive_bisect_partitions(w3, address, slot, mask, start_block, mid_block) + _recursive_bisect_partitions(w3, address, slot, mask, mid_block, end_block)


def recursive_bisect_partitions(w3, address, slot, mask, start_block, end_block):
    partitions = _recursive_bisect_partitions(w3, address, slot, mask, start_block, end_block)

    # then collapse neighboring partitions with the same value
    collapsed_partitions = list()
    _tmp_value = None
    _tmp_start = None
    _tmp_end = None
    for p in partitions:
        if p[2] == _tmp_value:
            _tmp_end = p[1]
        else:
            if _tmp_value is not None:
                collapsed_partitions.append((_tmp_start, _tmp_end, _tmp_value))
            _tmp_start = p[0]
            _tmp_end = p[1]
            _tmp_value = p[2]
    collapsed_partitions.append((_tmp_start, _tmp_end, _tmp_value))
    return collapsed_partitions


def get_target_type(found, proxy_address, only_constant_targets=False):
    #######################################################################
    # constant target
    #######################################################################
    # examples:
    # 0x4c1E01cca34f833EfeaE78EdF9F9108251438e3a
    if found.curr_stmt.arg2_val is not None and is_concrete(found.curr_stmt.arg2_val):
        address = bv_unsigned_value(found.curr_stmt.arg2_val)
        # normalize address
        address = w3.to_checksum_address(f"0x{address % 2**160:040x}")
        target = TargetConstant(pc=found.curr_stmt.id, proxy_address=proxy_address, address=address, window_start=None, window_end=None)
        return target

    if only_constant_targets:
        return TargetUnknown(pc=found.curr_stmt.id, proxy_address=proxy_address, address=None, window_start=None, window_end=None)
    #######################################################################
    # storage target
    #######################################################################
    # examples:
    # 0x30936d76c82315ebbd1E74433f282B5d6edD287C
    # 0x0E1484be68505883067473be8e51EfE1865bf6B2
    # 0xD92299927671Db31a94660BF3286687e5Ffbbb4e
    for slot, unmasked_bytes in found.globals['observed_sload_offsets'].items():
        masked_bv = found.curr_stmt.arg2_val
        masked_bytes = [BV_Extract(i * 8, i * 8 + 7, masked_bv)
                        for i in range(20)]  # only 20 bytes in target address
        try:
            mask = get_mask(found.solver, unmasked_bytes, BV_Concat(masked_bytes[::-1]), 
                            len_masked_bytes=20, tailing_00=False)
        # yices.YicesException.YicesException: The function yices_bvextract failed because: invalid indices in bv-extract
        except YicesException:
            continue

        if mask is None:
            continue

        # get storage slot
        address = w3.eth.get_storage_at(proxy_address, slot, globals.BLOCK_NUMBER)
        # mask address
        address = f"{int(address.hex(), 16):064x}"
        address = "0x"+"".join([address[i] for i, m in enumerate(mask) if mask[i] == "f"])
        # normalize address
        try:
            address = w3.toChecksumAddress(address)
        except:
            pass

        target = TargetStorage(found.curr_stmt.id, proxy_address=proxy_address, address=address, window_start=None, window_end=None, slot=hex(slot), mask=mask)
        return target
    
    #######################################################################
    # calldata target
    #######################################################################
    # examples:
    # 0x738Aa22EC2f4Ba7093E2300b3f1FF88Dc6De9A90
    calldata_unmasked_bytes = [found.calldata[BVV(i, 256)] for i in range(options.MAX_CALLDATA_SIZE)][::-1]
    calldata_masked_bv = found.curr_stmt.arg2_val
    calldata_masked_bytes = [BV_Extract(i * 8, i * 8 + 7, calldata_masked_bv)
                            for i in range(20)][::-1] # only 20 bytes in target address
    try:
        address_mask = get_mask(found.solver, calldata_unmasked_bytes, BV_Concat(calldata_masked_bytes), 
                                len_masked_bytes=20, tailing_00=False)
    # yices.YicesException.YicesException: The function yices_bvextract failed because: invalid indices in bv-extract
    except YicesException:
        address_mask = None

    if address_mask is not None:
        target = TargetCalldata(pc=found.curr_stmt.id, proxy_address=proxy_address, address=None, window_start=None, window_end=None, mask=address_mask)
        return target

    #######################################################################
    # external target
    #######################################################################
    # examples:
    # 0x3bca009e20F01F8a3F337f71DF04a3a4B9020BF1
    # 0x218B1A97b897294F07d57a31506D715d3A6Be353
    # 0x2040F2f2bB228927235Dc24C33e99E3A0a7922c1 (cannot reach callsite)
    for (_, _, source_address), unmasked_bytes in found.globals['observed_call'].items():
        masked_bv = found.curr_stmt.arg2_val
        masked_bytes = [BV_Extract(i * 8, i * 8 + 7, masked_bv)
                        for i in range(20)]  # only 20 bytes in target address
        try:
            address_mask = get_mask(found.solver, unmasked_bytes, BV_Concat(masked_bytes[::-1]), 
                                    len_masked_bytes=20, tailing_00=False)
        # yices.YicesException.YicesException: The function yices_bvextract failed because: invalid indices in bv-extract
        except YicesException:
            address_mask = None

        if address_mask is not None:
            target = TargetExternal(pc=found.curr_stmt.id, proxy_address=proxy_address, address=None, window_start=None, window_end=None, source_address=source_address)
            return target

    #######################################################################
    # unknown target
    #######################################################################
    return TargetUnknown(pc=found.curr_stmt.id, proxy_address=proxy_address, address=None, window_start=None, window_end=None)


def find_all_basic_targets(self_address, only_constant_targets=False, calltypes=None):
    calltypes = calltypes or {"DELEGATECALL",}
    
    # find delegatecall targets
    proxy_project = Target.project_at(self_address)

    all_targets = set()
    for call in {s for s in proxy_project.statement_at.values() if s.__internal_name__ in calltypes}:
        # corrupted target
        if "arg2_val" not in call.__dict__:
            log.warning(f"Skipping corrupted call target of {call.__internal_name__} at {call.id} in {self_address}")
            continue

        target = TargetUnknown(pc=call.id, proxy_address=self_address, address=None, window_start=WINDOW_START, window_end=globals.BLOCK_NUMBER)

        # try with backward slice first
        try:
            _backward_slice = get_shortest_backward_slice(proxy_project, call, [call.address_var])

            found = target.pre_callsite_state(block_number=globals.BLOCK_NUMBER,
                                              path=_backward_slice,
                                              with_monitor_sload=True,
                                              with_monitor_call=True)
            target = get_target_type(found, proxy_address=self_address, only_constant_targets=only_constant_targets)
            assert not isinstance(target, TargetUnknown)

            target.window_start = WINDOW_START
            target.window_end = globals.BLOCK_NUMBER

        except:
            # else execute whole path
            try:
                found = target.pre_callsite_state(block_number=globals.BLOCK_NUMBER,
                                                  with_monitor_sload=True,
                                                  with_monitor_call=True)
            # greed.utils.exceptions.GreedException: Could not find a state that reaches the callsite at
            except GreedException:
                log.warning(f"Skipping unreachable call target at {call.id} in {self_address}")
                continue

            target = get_target_type(found, proxy_address=self_address, only_constant_targets=only_constant_targets)

            target.window_start = WINDOW_START
            target.window_end = globals.BLOCK_NUMBER
        
        all_targets.add(target)

    return all_targets


def find_all_target_addresses(self_address, all_basic_targets, known_interactions=None):
    # at this point we have identified all possible targets
    # now we map them to all possible target addresses
    known_interactions = known_interactions or set()
    all_targets = set()

    #######################################################################
    # constant target - nothing to do
    #######################################################################
    constant_targets = {t for t in all_basic_targets if isinstance(t, TargetConstant)}
    for t in constant_targets:
        all_targets.add(t)
    
    #######################################################################
    # storage target - scan upgrade sequence
    #######################################################################
    # examples:
    # 0x260135ED4Cf9FB13D8734DCa2B4f9b583EFfbb02
    # 0x091E32ADFc3EdcbFf273Ee74aF270a062532470d
    storage_upgrade_sequences = dict()
    storage_targets = {t for t in all_basic_targets if isinstance(t, TargetStorage)}
    storage_targets_slot_and_mask = {(t.slot, t.mask) for t in storage_targets}
    for slot, mask in storage_targets_slot_and_mask:
        log.info(f"Scanning abstract target for storage slot {storage_targets_slot_and_mask}")
        partitions = recursive_bisect_partitions(w3, self_address, slot, mask, WINDOW_START, globals.BLOCK_NUMBER)
        storage_upgrade_sequence = list()
        for start_block, end_block, address in partitions:
            for t in storage_targets:
                if t.slot != slot or t.mask != mask:
                    continue
                logic_target = t.copy()
                logic_target.address = address
                logic_target.window_start = start_block
                logic_target.window_end = end_block
                all_targets.add(logic_target)
                storage_upgrade_sequence.append(logic_target)
        storage_upgrade_sequences[(slot, mask)] = storage_upgrade_sequence
        
    #######################################################################
    # calldata target - all observed on-chain interactions are possible targets
    #######################################################################
    # approximate this with any of the known interactions
    # if no known interactions this is ignored
    calldata_targets = {t for t in all_basic_targets if isinstance(t, TargetCalldata)}
    for t in calldata_targets:
        for addr in known_interactions:
            logic_target = t.copy()
            logic_target.address = addr
            all_targets.add(logic_target)

    #######################################################################
    # external target - we don't handle this for now
    # unknown target - we don't handle this for now
    #######################################################################
    # approximate this with any of the known interactions
    # if no known interactions this is ignored
    external_targets = {t for t in all_basic_targets if isinstance(t, TargetExternal)}
    unknown_targets = {t for t in all_basic_targets if isinstance(t, TargetUnknown)}
    for t in external_targets | unknown_targets:
        for addr in known_interactions:
            logic_target = t.copy()
            logic_target.address = addr
            all_targets.add(logic_target)

    #######################################################################
    # nested target - this is only done for constant-constant nested targets
    #######################################################################
    # examples:
    # 0x32b048F2F5f3CA787D591602caDB02B49341511f
    constant_target_addresses = {t.address for t in all_basic_targets if isinstance(t, TargetConstant)}
    for constant_target_address in constant_target_addresses:
        nested_constant_targets = find_all_basic_targets(constant_target_address, only_constant_targets=True)
        for nested_target in nested_constant_targets:
            if not isinstance(nested_target, TargetConstant):
                continue

            nested_target = NestedTargetConstant(pc=nested_target.pc, proxy_address=constant_target_address, address=nested_target.address, window_start=nested_target.window_start, window_end=nested_target.window_end)
            all_targets.add(nested_target)
    
    return all_targets
        

def run_dynamic_lifespan_analysis(self_address, known_interactions=None, with_unreachable=False):
    known_interactions = known_interactions or list()

    # find creation block
    global WINDOW_START
    creation_blocks = run_query(f"select block_number from contracts where address='{self_address}';", types=(int,))
    WINDOW_START = min([b[0] for b in creation_blocks]) if creation_blocks else None

    # setup lifespan analysis
    options.SOLVER_TIMEOUT = 30
    options.MAX_CALLDATA_SIZE = 512
    options.GREEDY_SHA = True
    options.MAX_SHA_SIZE = 300
    options.OPTIMISTIC_CALL_RESULTS = True
    options.DEFAULT_EXTCODESIZE = True

    # run lifespan analysis

    all_basic_targets = find_all_basic_targets(self_address)
    # print(f"Basic targets:")
    # for target in all_basic_targets:
    #     print(target)

    all_targets = find_all_target_addresses(self_address, all_basic_targets, known_interactions=known_interactions)
    proxy = Proxy(pc=None, proxy_address=None, address=self_address, window_start=WINDOW_START, window_end=globals.BLOCK_NUMBER)

    maybe_unreachable_targets = set()
    for a in known_interactions:
        if a not in {t.address for t in all_targets}:
            t = TargetUnknown(pc=None, proxy_address=None, address=a, window_start=WINDOW_START, window_end=globals.BLOCK_NUMBER)
            maybe_unreachable_targets.add(t)

    if with_unreachable:
        all_targets |= maybe_unreachable_targets
    else:
        log.warning(f"Skipping {len(maybe_unreachable_targets)} possibly unreachable targets")

    return all_targets | {proxy}
