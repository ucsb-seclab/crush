import itertools
import json
import logging
import networkx as nx
import os

from collections import defaultdict

from greed import options
from greed.analyses.slicing import forward_slice
from greed.exploration_techniques import DirectedSearch

from crush import globals
from crush.attack import AttackRequest, Shift, Collision
from crush.masks import find_colliding_masks
from crush.target import Target, TargetStorage
from crush.core.lifespan import find_all_basic_targets


log = logging.getLogger(__name__)


MAPPING_TYPE_MASKS = {"aa"*32, "bb"*32, "cc"*32}

COMP_OPS = {"EQ", "LT", "GT", "SLT", "SGT", "ISZERO"}

GETTER_CAN_CONTAIN_OPS = {"RETURN", "REVERT", "CALLVALUE", "ISZERO", "CONST", "JUMP", "JUMPI", "SLOAD", "MLOAD", "MSTORE", "SHL", "SHR", "AND", "ADD", "SUB"}
GETTER_MUST_CONTAIN_OPS = {"SLOAD", "MSTORE", "RETURN"}


def run_impact_analysis(self_address):
    """
    Find potentially impactful collisions and possible attacks that exploit them

    Summary of the analysis steps:

    TIMELINE ANALYSIS

    COLLISION ANALYSIS
    1. find shifted (slot, types)
    2. find confused (slot, types)

    SENSTIVE SLOTS ANALYSIS
    1. find sensitive (slot, types) for each target

    POSSIBLE ATTACK ANALYSIS
    (determine possible attacks / generate attack requests)
    """
    # #######################################################################
    # SETUP
    # #######################################################################
    options.SOLVER_TIMEOUT = 30
    options.MAX_CALLDATA_SIZE = 512
    options.GREEDY_SHA = True
    options.MAX_SHA_SIZE = 300
    options.OPTIMISTIC_CALL_RESULTS = True
    options.DEFAULT_EXTCODESIZE = True

    #######################################################################
    # TIMELINE ANALYSIS
    #######################################################################
    # read all_targets from lifespan analysis
    lifespan_path = f"{globals.DATA_PATH}/lifespan/{self_address}.json"
    if not os.path.exists(lifespan_path):
        # abort if the file does not exist
        raise Exception(f"File {lifespan_path} does not exist!")
    with open(lifespan_path, "r") as f:
        all_targets = json.load(f)

    # load target dicts into Target objects
    logic_targets = set()
    for t_dict in all_targets:
        target = Target.from_dict(t_dict)
        if t_dict["kind"] == "Proxy":
            proxy_target = target
        else:
            logic_targets.add(target)
    assert proxy_target is not None

    # to avoid duplicates we only consider one "upgrade sequence" per storage slot
    # (which could be duplicated with different pcs)
    one_pc_per_storage_target_slot = {target.slot: target.pc for target in logic_targets if isinstance(target, TargetStorage)}
    storage_upgrade_sequences = defaultdict(list)
    for t in sorted(logic_targets, key=lambda t: t.window_start):
        if isinstance(t, TargetStorage) and t.pc in one_pc_per_storage_target_slot.values():
            storage_upgrade_sequences[t.slot].append(t)

    # print timeline
    log.info("-"*80)
    log.info("Timeline:")
    boundaries = sorted({t.window_end for t in logic_targets} | {proxy_target.window_start})
    for a, b in zip(boundaries[:-1], boundaries[1:]):
        # contracts that are alive at this block
        alive_contracts = sorted({t.address for t in logic_targets if t.window_start <= b <= t.window_end})+[proxy_target.address]
        log.info(f"\t{[a+1, b]}: {alive_contracts}")
    log.info("-"*80)

    #######################################################################
    # COLLISION ANALYSIS
    #######################################################################

    #######################################################################
    # 1. find shifted (slot, types)
    # 
    # var1 (addr)       | var1 (addr)
    # var2 (addr)       | varX (bool)  -- new variable with corrupted value (just collided, as above)
    # var3 (bool)       | var2 (addr)  -- old variable with corrupted value (shifted)
    # -                 | var3 (bool)  -- old variable with corrupted value (shifted)

    # DEAD              | ALIVE        -- we can trigger UaW, W is the shift itself (so it comes for free)

    # two possible problems
    # 1. new variables having old values
    # technically we should check if the slot was zero to start with (i.e., if there was ANY write, regardless of the type)
    # 2. old variables having new values
    # technically we should check if old slot (slot-shift) has the exact same value as the new slot

    collisions = set()

    def adjacent_following_slots(slot, slots):
        _adjacent_following_slots = list()
        for x in range(int(slot, 16), int(slot, 16)+0xffff):
            if hex(x) in slots:
                _adjacent_following_slots.append(hex(x))
            else:
                break
        return _adjacent_following_slots

    # shift (2) < num shifted vars (3)
    # v1    |   v1
    # v2    |   x
    # v3    |   y
    # v4    |   v2
    #       |   v3
    #       |   v4

    # shift (4) > num shifted vars (3)
    # v1    |   w
    # v2    |   x
    # v3    |   y
    #       |   z
    #       |   v1
    #       |   v2
    #       |   v3
    
    for storage_upgrade_sequence in storage_upgrade_sequences.values():
        # for each consecutive pair logic_a, logic_b
        for logic_a, logic_b in itertools.combinations(storage_upgrade_sequence, 2):  # zip(storage_upgrade_sequence[:-1], storage_upgrade_sequence[1:]):
            sorted_slots_a = sorted(logic_a.type_analysis["slot_types"], key=lambda x: int(x, 16))
            sorted_slots_b = sorted(logic_b.type_analysis["slot_types"], key=lambda x: int(x, 16))
            _shifted_slots = set()
            for slot in sorted(set(sorted_slots_a) & set(sorted_slots_b), key=lambda x: int(x, 16)):     
                if slot in _shifted_slots:
                    # we skip this to avoid errors/duplicates. e.g., ['0x5', '0x6'] -> ['0x8', '0x9'] + ['0x6'] -> ['0x8']
                    continue
                if not find_colliding_masks(set(logic_a.type_analysis["slot_types"][slot]) | set(logic_b.type_analysis["slot_types"][slot])):
                    continue
                _adjacent_following_slots_a = adjacent_following_slots(slot, sorted_slots_a)
                _adjacent_following_slots_b = adjacent_following_slots(slot, sorted_slots_b)
                
                # find positive shift a -> b
                _adjacent_following_types_a = [logic_a.type_analysis["slot_types"][s] for s in _adjacent_following_slots_a]
                for shift in range(1, len(_adjacent_following_slots_b) - len(_adjacent_following_slots_a) + 1):
                    _candidate_shifted_slots = [hex(int(s, 16)+shift) for s in _adjacent_following_slots_a]
                    _candidate_shifted_types = [logic_b.type_analysis["slot_types"][s] for s in _candidate_shifted_slots]
                    if _adjacent_following_types_a == _candidate_shifted_types:
                        _shifted_slots |= set(_adjacent_following_slots_a)

                        # check if prev slot partially shifted
                        _prev_slot = hex(int(slot, 16)-1)
                        _prev_slot_shifted = hex(int(_prev_slot, 16)+shift)
                        _missing_types = list()
                        for _type in sorted(logic_a.type_analysis["slot_types"].get(_prev_slot, set()), reverse=True):
                            if _type in logic_b.type_analysis["slot_types"].get(_prev_slot, set()):
                                break
                            _missing_types.append(_type)
                        _sorted_shifted_types = sorted(logic_b.type_analysis["slot_types"].get(_prev_slot_shifted, set()))
                        if len(_sorted_shifted_types) >= len(_missing_types) and all([_type.count("ff") == _sorted_shifted_types[i].count("ff") for i, _type in enumerate(_missing_types)]):
                            collisions |= {Shift(_prev_slot, _prev_slot_shifted, logic_a, logic_b, set(_missing_types), set(_sorted_shifted_types[:len(_missing_types)]))}
                        ###################################### done checking

                        collisions |= {Collision(s, s, logic_a, logic_b, set(logic_a.type_analysis["slot_types"][s]), set(logic_b.type_analysis["slot_types"][s])) for s in _adjacent_following_slots_a[:shift]}
                        collisions |= {Shift(s, hex(int(s, 16)+shift), logic_a, logic_b, set(logic_a.type_analysis["slot_types"][s]), set(logic_b.type_analysis["slot_types"][hex(int(s, 16)+shift)])) for s in _adjacent_following_slots_a}
                        log.info(f"found shift: {shift}. {_adjacent_following_slots_a} -> {_candidate_shifted_slots}")
                        break

                # find negative shift b -> a (= positive shift a -> b but then invert targets)
                _adjacent_following_types_b = [logic_b.type_analysis["slot_types"][s] for s in _adjacent_following_slots_b]
                for shift in range(1, len(_adjacent_following_slots_a) - len(_adjacent_following_slots_b) + 1):
                    _candidate_shifted_slots = [hex(int(s, 16)+shift) for s in _adjacent_following_slots_b]
                    _candidate_shifted_types = [logic_a.type_analysis["slot_types"][s] for s in _candidate_shifted_slots]
                    if _adjacent_following_types_b == _candidate_shifted_types:
                        _shifted_slots |= set(_candidate_shifted_slots)

                        # check if prev slot partially shifted
                        _prev_slot = hex(int(slot, 16)-1)
                        _prev_slot_shifted = hex(int(_prev_slot, 16)+shift)
                        _missing_types = list()
                        for _type in sorted(logic_b.type_analysis["slot_types"].get(_prev_slot, set()), reverse=True):
                            if _type in logic_a.type_analysis["slot_types"].get(_prev_slot, set()):
                                break
                            _missing_types.append(_type)
                        _sorted_shifted_types = sorted(logic_a.type_analysis["slot_types"].get(_prev_slot_shifted, set()))
                        if len(_sorted_shifted_types) >= len(_missing_types) and all([_type.count("ff") == _sorted_shifted_types[i].count("ff") for i, _type in enumerate(_missing_types)]):
                            collisions |= {Shift(_prev_slot_shifted, _prev_slot, logic_a, logic_b, set(_sorted_shifted_types[:len(_missing_types)]), set(_missing_types))}
                        ###################################### done checking

                        collisions |= {Shift(hex(int(s, 16)+shift), s, logic_a, logic_b, set(logic_a.type_analysis["slot_types"][hex(int(s, 16)+shift)]), set(logic_b.type_analysis["slot_types"][s])) for s in _adjacent_following_slots_b}
                        log.info(f"found shift: {shift}. {_candidate_shifted_slots} -> {_adjacent_following_slots_b}")
                        break
    
    #######################################################################
    # 2. find confused (slot, types)
    # (alive or not, everything up to this block)
    # 
    # var1 (addr)       | var1 (addr)
    # var2 (addr)       | varX (bool)  -- new variable with corrupted value

    # ALIVE             | ALIVE        -- we can trigger both W (addr) + UaW (bool) and W (bool) + UaW (addr)
    # DEAD              | DEAD         -- uninteresting
    # ALIVE             | DEAD         -- we can trigger UaW (addr), but W (bool) must have happened before
    # DEAD              | ALIVE        -- we can trigger UaW (bool), but W (addr) must have happened before
    # if any of the type is a mapping type (aa, bb, cc): uninteresting

    for t1, t2 in itertools.combinations({proxy_target} | logic_targets, 2):
        # skip if the windows don't overlap
        # if not range(max(t1.window_start, t2.window_start), min(t1.window_end, t2.window_end)):
        #     continue
        # NOTE: even if the windows don't overlap, it can still affect the current logic if it's the last write that happened
        shared_slots = set(t1.type_analysis["slot_types"]) & set(t2.type_analysis["slot_types"])
        for slot in shared_slots:
            slot_masks = set(t1.type_analysis["slot_types"][slot]) | set(t2.type_analysis["slot_types"][slot])
            colliding_masks = find_colliding_masks(slot_masks)
            if colliding_masks:
                types1 = set(t1.type_analysis["slot_types"][slot]) & colliding_masks
                types2 = set(t2.type_analysis["slot_types"][slot]) & colliding_masks
                collisions.add(Collision(slot, slot, t1, t2, set(types1), set(types2)))

    # mapping -> simple collision --> ignore
    # simple -> mapping collision --> ignore
    for c in list(collisions):
        if isinstance(c, Shift):
            continue
        if c.types1-MAPPING_TYPE_MASKS == set() or c.types2-MAPPING_TYPE_MASKS == set():
            log.info(f"Ignoring collision {c.target1.address}-{c.target2.address} (slot {c.slot1}) because it involves a mapping type")
            collisions.remove(c)
        # ignore most common known address slots to reduce false positives
        KNOWN_ADDRESS_SLOTS = [
            "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",  # keccak256('eip1967.proxy.admin')
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",  # keccak256('eip1967.proxy.implementation')
            "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7",  # keccak256("PROXIABLE")
            "0xa2bd3d3cf188a41358c8b401076eb59066b09dec5775650c0de4c55187d17bd9",  # keccak256("OUSD.vault.governor.admin.impl")
            "0x7ad06df6a0af6bd602d90db766e0d5f253b45187c3717a0f9026ea8b10ff0d4b",  # keccak256("iToken_LowerAdminAddress")
        ]
        if c.slot1 in KNOWN_ADDRESS_SLOTS or c.slot2 in KNOWN_ADDRESS_SLOTS:
            log.info(f"Ignoring collision {c.target1.address}-{c.target2.address} (slot {c.slot1}) because it involves a known address slot")
            collisions.remove(c)

    for c in collisions:
        c.target1.confused_slots[c.slot1].update(c.types1)
        c.target2.confused_slots[c.slot2].update(c.types2)

    log.info("-"*80)
    log.info(f"Collisions: {len(collisions)}")
    for c in sorted(collisions, key=lambda c: int(c.slot2, 16)):
        log.info(f"\t{c}")
    log.info("-"*80)

    if len(collisions) == 0:
        log.info("NO COLLISIONS FOUND: stopping analysis...")
        exit(0)

    #######################################################################
    # SENSITIVE SLOTS ANALYSIS
    #######################################################################

    #######################################################################
    # 1. find sensitive (slot, types) for each target

    for target in {proxy_target} | logic_targets:
        #######################################################################
        # call targets
        for t in list(find_all_basic_targets(target.address, calltypes={"CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"})):
            if isinstance(t, TargetStorage):
                target.sensitive_slots[t.slot].add(t.mask)

        #######################################################################
        # guards from gigahorse
        tac_guarded_blocks = target.tac_guarded_blocks
        for g in {g for g_list in tac_guarded_blocks.values() for g in g_list if g.startswith('0x')}:
            _slot = g.split('_')[0]
            mask_start = int(g.split('_')[1]) if '_' in g else None
            mask_end = int(g.split('_')[2]) if '_' in g else None
            if mask_start or mask_end:
                _mask = ("00"*mask_start + "ff"*(mask_end-mask_start+1) + "00"*(32-mask_end-1))[::-1]
            else:
                _mask = None

            if _slot not in target.type_analysis["slot_types"]:
                log.warning(f"(target {target.address}) Guarded slot {_slot} is not in type analysis")
                continue
            elif _mask is None:
                # gigahorse considers the whole slot as a guard
                target.sensitive_slots[_slot].update(target.type_analysis["slot_types"][_slot])
                continue
            elif _mask not in target.type_analysis["slot_types"][_slot]:
                log.warning(f"(target {target.address}) Guarded mask {_mask} (slot {_slot}) is not in type analysis. Adding all possible masks")
                target.sensitive_slots[_slot].update(target.type_analysis["slot_types"][_slot])
                continue
            target.sensitive_slots[_slot].add(_mask)

        #######################################################################
        # slots guarded by guards
        all_guarded_blocks = [id for id, guards in tac_guarded_blocks.items()] #  if any(g in guarding_slots for g in guards)

        access_groups = defaultdict(dict)
        access_groups_sloads = defaultdict(dict)
        access_groups_sstores = defaultdict(dict)
        for _slot in target.type_analysis["slot_types"]:
            # separate all possible access type groups
            _access_groups_sloads = defaultdict(set)
            _access_groups_sstores = defaultdict(set)
            possible_types_for_pc = {pc: tuple(access["access_masks"]) for pc, access in target.type_analysis["storage_accesses"].items() if access["slot"] == _slot}
            for possible_types in set(possible_types_for_pc.values()):
                for pc, types in possible_types_for_pc.items():
                    if set(possible_types) - set(types) == set():
                        if target.project.statement_at[pc].__internal_name__ == "SLOAD":
                            _access_groups_sloads[possible_types].add(pc)
                        elif target.project.statement_at[pc].__internal_name__ == "SSTORE":
                            _access_groups_sstores[possible_types].add(pc)
                        else:
                            raise Exception("Unknown type")
            access_groups_sloads[_slot] = dict(_access_groups_sloads)
            access_groups_sstores[_slot] = dict(_access_groups_sstores)
            access_groups[_slot] = dict(_access_groups_sloads)
            access_groups[_slot].update(_access_groups_sstores)
        
        # figure out which access groups are guarded
        for _slot in access_groups_sstores:
            for possible_types, pcs in access_groups_sstores[_slot].items():
                if all(target.project.statement_at[pc].block_id in all_guarded_blocks for pc in pcs):
                    # log.info(f"Slot {_slot} ({possible_types}) is guarded")
                    target.sensitive_slots[_slot].update(possible_types)
        
        #######################################################################
        # slots that are never written 
        for _slot in access_groups_sloads:
            for _type in access_groups_sloads[_slot]:
                if _type not in access_groups_sstores[_slot]:
                    #log.info(f"Slot {_slot} is never written")
                    target.sensitive_slots[_slot].update(_type)

        
        #######################################################################
        # not sensitive if there is no meaningful use of the slot
        def no_meaningful_use(_slot, _type):
            # any write is a meaningful use
            for _access_group_types, _access_group_pcs in access_groups_sstores[_slot].items():
                if _type in _access_group_types and len(_access_group_pcs) > 0:
                    return False
            # any read that is NOT A GETTER is a meaningful use
            for _access_group_types, _access_group_pcs in access_groups_sloads[_slot].items():
                if _type in _access_group_types:
                    for pc in _access_group_pcs:
                        stmt = target.project.statement_at[pc]
                        stmt_cfg = target.project.block_at[stmt.block_id].function.cfg.stmt_cfg
                        subtree = nx.dfs_tree(stmt_cfg, source=stmt)
                        all_mnemonics = {s.__internal_name__ for s in subtree.nodes}
                        if GETTER_MUST_CONTAIN_OPS & all_mnemonics != GETTER_MUST_CONTAIN_OPS:
                            return False
                        if all_mnemonics - GETTER_CAN_CONTAIN_OPS != set():
                            return False
            return True
        
        for _slot in target.sensitive_slots:
            for _type in list(target.sensitive_slots[_slot]):
                if no_meaningful_use(_slot, _type):
                    # log.info(f"Slot {_slot} ({_type}) in target {target.address} does not have a meaningful use")
                    target.sensitive_slots[_slot].remove(_type)


        #######################################################################
        # guarding sensitive slots
        #######################################################################
        _sensitive_sstores = {target.project.statement_at[pc]
                              for _slot in target.sensitive_slots 
                              for _type in target.sensitive_slots[_slot] 
                              for _possible_types in access_groups_sstores[_slot] 
                              for pc in access_groups_sstores[_slot][_possible_types]
                              if _type in _possible_types}  # _type not in MAPPING_TYPE_MASKS

        # log.info(f"Sensitive sstores: {_sensitive_sstores}")
        for _slot in access_groups_sloads:
            for possible_types, pcs in access_groups_sloads[_slot].items():

                # exclude if we already know that slot+type is sensitive
                if _slot in target.sensitive_slots:
                    possible_types = set(possible_types) - target.sensitive_slots[_slot]
                if _slot in target.guarding_sensitive_slots:
                    possible_types = set(possible_types) - target.guarding_sensitive_slots[_slot]
                if not possible_types:
                    continue

                # exclude if slot+type is not colliding
                _colliding_types = set.union(*[c.types2 for c in collisions if target == c.target2 and c.slot2 == _slot], *[c.types1 for c in collisions if target == c.target1 and c.slot1 == _slot], set())
                if not _colliding_types:
                    # log.info(f"Discarding potential guarding sensitive slot {_slot} because it has no colliding types")
                    continue
                if _colliding_types - MAPPING_TYPE_MASKS == set():
                    # log.info(f"Discarding potential guarding sensitive slot {_slot} because it only has mapping types")
                    continue
                if not any([t in _colliding_types for t in possible_types]):
                    continue

                for pc in pcs:
                    stmt = target.project.statement_at[pc]
                    # check if this looks like a check of some sort
                    _forward_slice = forward_slice(target.project, stmt.id, [stmt.value_var])

                    if not any(s.__internal_name__ in COMP_OPS for s in _forward_slice):
                        # log.info(f"Discarding potential guarding sensitive slot {_slot} because it does not look like a check")
                        continue

                    # setup any possible callstack
                    # don't do the callpath game if they are in the same function, it's a waste of time
                    for _sstore in _sensitive_sstores:
                        # log.info(f"Checking if {stmt} (slot {_slot}) guards sensitive sstore {_sstore}")
                        if target.project.block_at[stmt.block_id].function == target.project.block_at[_sstore.block_id].function:
                            _callpaths = [nx.shortest_path(target.project.callgraph, target.project.function_at["0x0"], target.project.block_at[stmt.block_id].function)]
                        else:
                            _callpaths = nx.all_simple_paths(target.project.callgraph, target.project.function_at["0x0"], target.project.block_at[stmt.block_id].function)
                        for _callpath in _callpaths:
                            _dummy_state = target.project.factory.entry_state(xid=1)
                            _dummy_state.pc = pc
                            for _callprivate_block in [target.project.block_at[a.callprivate_target_sources[b.id][0]] for a, b in zip(_callpath[:-1], _callpath[1:])]:
                                if _callprivate_block.succ:
                                    saved_return_pc = _callprivate_block.succ[0].first_ins.id
                                else:
                                    fake_exit_bb = target.project.factory.block('fake_exit')
                                    saved_return_pc = fake_exit_bb.statements[0].id
                                _dummy_state.callstack.append((None, saved_return_pc, None))

                            # find a path from pc to any of the sensitive sstores
                            if DirectedSearch._is_reachable(_dummy_state, target.project.block_at[_sstore.block_id], target.project.factory, target.project.callgraph)[0]:
                                # log.info(f"{stmt} (slot {_slot}) looks like a check and might guard sensitive sstores")
                                target.guarding_sensitive_slots[_slot].update(possible_types)
                                for t in possible_types:
                                    target.guarded_sensitive_slots[(_slot, t)].add(_sstore)

        
        #######################################################################
        # array.length is sensitive (but not the whole array)
        #######################################################################
        for _slot, _type in target.type_analysis["slot_types"].items():
            if _type in [["dd"*32,], ["ee"*32,]]:
                target.sensitive_slots[_slot].update(_type)


    #######################################################################
    # POSSIBLE ATTACK ANALYSIS
    #######################################################################

    #######################################################################
    # log confused slots to make it easier to debug
    log.info("-"*80)
    log.info(f"Confused and sensitive slots:")
    for _target in {proxy_target} | logic_targets:
        log.info(f"\t{_target.address}:")
        for _slot in sorted(_target.sensitive_slots, key=lambda s: int(s, 16)):
            _confused_types = {_type for _type in _target.sensitive_slots[_slot] if _type in _target.confused_slots[_slot]}
            if not _confused_types:
                continue
            log.info(f"\t\t{_slot}: {_confused_types}")
    log.info("-"*80)

    log.info("-"*80)
    log.info(f"Confused and guarding sensitive slots:")
    for _target in {proxy_target} | logic_targets:
        log.info(f"\t{_target.address}:")
        for _slot in sorted(_target.guarding_sensitive_slots, key=lambda s: int(s, 16)):
            _confused_types = {_type for _type in _target.guarding_sensitive_slots[_slot] if _type in _target.confused_slots[_slot]}
            if not _confused_types:
                continue
            log.info(f"\t\t{_slot}: {_confused_types}")
    log.info("-"*80)

    #######################################################################
    # generate attack requests
    log.info("-"*80)
    log.info("Attack timeline:")
    attack_requests = list()

    is_alive = lambda t, b: t.window_start <= b <= t.window_end
    is_dead = lambda t, b: t.window_end < b
    
    for c in {c for c in collisions if isinstance(c, Collision)}:
        for b in {c.target1.window_start, c.target2.window_start, c.target1.window_end, c.target2.window_end}:
            ar2 = AttackRequest(AttackRequest.ATTACK_TYPE.COLLISION, c.slot2, b, proxy_target, c.target1, c.target2, c.slot1, c.types1, c.slot2, c.types2)
            ar1 = AttackRequest(AttackRequest.ATTACK_TYPE.COLLISION, c.slot1, b, proxy_target, c.target2, c.target1, c.slot2, c.types2, c.slot1, c.types1)

            for ar, t1, t2 in [(ar2, c.target1, c.target2), (ar1, c.target2, c.target1)]:
                if is_alive(t2, b) and (is_alive(t1, b) or is_dead(t1, b)) and ar.target2_sloads and (ar.is_target2_sensitive or (ar.is_target2_guarding_sensitive and ar.target2_guarded_sstores)):
                    log.info(f"Potential attack: {ar}")
                    attack_requests.append(ar)

    for c in {c for c in collisions if isinstance(c, Shift)}:
        if set(c.types2) & MAPPING_TYPE_MASKS != set():
            log.info(f"Skipping potential attack (shifted mapping): {ar} NEEDS MANUAL INSPECTION!")
            continue

        t1 = c.target1
        t2 = c.target2
        for b in {t1.window_start, t2.window_start, t1.window_end, t2.window_end}:
            ar = AttackRequest(AttackRequest.ATTACK_TYPE.SHIFT, c.slot2, b, proxy_target, t1, t2, c.slot1, c.types1, c.slot2, c.types2)
            
            if is_alive(t2, b) and is_dead(t1, b) and ar.target2_sloads and (ar.is_target2_sensitive or (ar.is_target2_guarding_sensitive and ar.target2_guarded_sstores)):
                log.info(f"Potential attack: {ar}")
                attack_requests.append(ar)

    return attack_requests