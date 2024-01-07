#!/usr/bin/env python

import json
import logging
import os

from collections import defaultdict

from greed import Project, options
from greed.exploration_techniques import DirectedSearch, Prioritizer
from greed.exploration_techniques.other import MstoreConcretizer
from greed.utils.exceptions import GreedException
from greed.utils.files import load_csv_multimap
from greed.utils.extra import gen_exec_id
from greed.solver.shortcuts import BVV, BV_Concat, Equal, BV_UGE

from crush import globals
from crush.globals import w3
from crush.exploration_techniques import SSTOREStub, Simplifier, MonitorSLOAD, MonitorCALLDATACOPY, MonitorCALL, StubUninitializedVars, PathFinder, TagStatements
from crush.utils import get_init_ctx, concretize, get_all_subclasses


log = logging.getLogger(__name__)


class Target(object):
    def __init__(self, pc, proxy_address, address, window_start, window_end):
        self.pc = pc
        self.proxy_address = proxy_address
        self.address = address

        self.window_start = window_start
        self.window_end = window_end

        self.confused_slots = defaultdict(set)
        self.sensitive_slots = defaultdict(set)
        self.guarding_sensitive_slots = defaultdict(set)
        self.guarded_sensitive_slots = defaultdict(set)

        self._type_analysis = None
        self._tac_guarded_blocks = None
        self._project = None
        self._callsite_state = dict()

    @property
    def project(self):
        if self.address is None:
            raise GreedException("Target without address has no attribute .project")
        elif self._project is None:
            self._project = Target.project_at(self.address)
        return self._project
    
    @staticmethod
    def project_at(address):
        if not os.path.exists(f"{globals.GIGAHORSE_PATH}/{address[0:5]}/{address}"):
            log.warning(f"Gigahorse analysis not found for {address}. Using default (empty) project")
            default_address = "0x0000000000000000000000000000000000000000"
            gigahorse_path = f"{globals.GIGAHORSE_PATH}/{default_address[0:5]}/{default_address}"
            return Project(gigahorse_path)
        gigahorse_path = f"{globals.GIGAHORSE_PATH}/{address[0:5]}/{address}"
        return Project(gigahorse_path)
    
    @property
    def type_analysis(self):
        if self.address is None:
            raise GreedException("Target without address has no attribute .type_analysis")
        if self.project is None:
            raise GreedException("Target without .project has no attribute .type_analysis")
        
        # _hash = hashlib.sha256(bytes.fromhex(self.project.code.decode().strip())).hexdigest()
        if self._type_analysis is None and not os.path.exists(f"{globals.DATA_PATH}/type/{self.address}.json"):
            log.warning(f"Type analysis not found for {self.address}. Using default (empty) types")
            self._type_analysis = {"slot_types": {}, "access_types": {}, "privileged_slots": [], "delegatecall_slots": [], "other_call_slots": []}
        elif self._type_analysis is None:
            with open(f"{globals.DATA_PATH}/type/{self.address}.json", "r") as f:
                self._type_analysis = json.load(f)
        return self._type_analysis
    
    @property
    def tac_guarded_blocks(self):
        if self.address is None:
            raise GreedException("Target without address has no attribute .tac_guarded_blocks")
        elif self._tac_guarded_blocks is None and not os.path.exists(f"{globals.GIGAHORSE_PATH}/{self.address[0:5]}/{self.address}/StaticallyGuardedBlock.csv"):
            log.warning(f"Guard analysis not found for {self.address}. Using default (empty) guards")
            self._tac_guarded_blocks = dict()
        elif self._tac_guarded_blocks is None:
            self._tac_guarded_blocks = load_csv_multimap(f"{globals.GIGAHORSE_PATH}/{self.address[0:5]}/{self.address}/StaticallyGuardedBlock.csv")
        return self._tac_guarded_blocks
    
    @staticmethod
    def state_at(project,
                 stmt,
                 address=None,
                 block_number=None,
                 start_from_pc=None,
                 path=None,
                 init_ctx=None,
                 tag_statements=None,
                 with_sstore_stub=False, 
                 with_partial_concrete_storage=False,
                 with_monitor_sload=False,
                 with_monitor_calldatacopy=False,
                 with_monitor_call=False):
        init_ctx = init_ctx or get_init_ctx(address=address, block_number=block_number)
        entry_state = project.factory.entry_state(xid=gen_exec_id(), init_ctx=init_ctx, partial_concrete_storage=with_partial_concrete_storage)
        
        if path is not None:
            start_from_pc = path[0]
            path = path[1:]
        if start_from_pc is not None:
            entry_state.pc = start_from_pc
            
        simgr = project.factory.simgr(entry_state=entry_state)

        if path is not None:
            pathfinder = PathFinder(path)
            simgr.use_technique(pathfinder)

        if tag_statements is not None:
            simgr.use_technique(TagStatements(tag_statements))
        simgr.use_technique(StubUninitializedVars())
        simgr.use_technique(Simplifier())
        # NOTE: it seems occasionally expensive to init the mstore concretizer (e.g., 0x0092c3f81BC7d630dD1f885D0be67047f54D5aF1)
        simgr.use_technique(MstoreConcretizer())
        if with_monitor_sload:
            simgr.use_technique(MonitorSLOAD())
        if with_monitor_calldatacopy:
            simgr.use_technique(MonitorCALLDATACOPY())
        if with_monitor_call:
            simgr.use_technique(MonitorCALL())
        if with_sstore_stub:
            assert address is not None, "Cannot use SSTOREStub without an address"
            simgr.use_technique(SSTOREStub(w3, address, block_number))

        if path is None:
            simgr.use_technique(DirectedSearch(stmt))
            simgr.use_technique(Prioritizer(scoring_function=lambda s: -s.globals['directed_search_distance']))
            
        # if we are already at the target pc, we don't need to run the simgr
        # NOTE: this is here because we still need the exploration techniques to setup the state
        if entry_state.pc == stmt.id:
            StubUninitializedVars.check_state(simgr, entry_state)
            entry_state.curr_stmt.set_arg_val(entry_state)
            return entry_state
        
        simgr.run(find=lambda s: s.curr_stmt.id == stmt.id)
        if not simgr.found:
            raise GreedException(f"Could not find a state that reaches the stmt at {stmt.id}")
        found = simgr.found.pop()
        StubUninitializedVars.check_state(simgr, found)
        found.curr_stmt.set_arg_val(found)

        return found
    
    def pre_callsite_state(self, block_number,
                           start_from_pc=None,
                           path=None,
                           init_ctx=None,
                           with_sstore_stub=False, 
                           with_partial_concrete_storage=False,
                           with_monitor_sload=False,
                           with_monitor_calldatacopy=False,
                           with_monitor_call=False):
        # get the callsite state
        proxy_project = Target.project_at(self.proxy_address)
        callsite = proxy_project.statement_at[self.pc]
        
        return Target.state_at(proxy_project, callsite, self.proxy_address, block_number, 
                               start_from_pc=start_from_pc,
                               path=path,
                               init_ctx=init_ctx,
                               with_sstore_stub=with_sstore_stub,
                               with_partial_concrete_storage=with_partial_concrete_storage,
                               with_monitor_sload=with_monitor_sload,
                               with_monitor_calldatacopy=with_monitor_calldatacopy,
                               with_monitor_call=with_monitor_call)
    
    def callsite_state(self, block_number):
        if block_number not in self._callsite_state:
            # get the callsite state
            init_ctx = get_init_ctx(address=self.proxy_address, block_number=block_number, calldatasize=options.MAX_CALLDATA_SIZE)
            found = self.pre_callsite_state(block_number=block_number, with_sstore_stub=True, init_ctx=init_ctx)

            # constrain the symbolic target value to the actual address
            symbolic_value = found.curr_stmt.address_val
            target_address = BVV(int(self.address, 16), 256)
            assert found.solver.is_formula_sat(Equal(symbolic_value, target_address))
            found.add_constraint(Equal(symbolic_value, target_address))

            self._callsite_state[block_number] = found
        return self._callsite_state[block_number]

    def _format_calldata(self, raw_calldata, block_number):
        callsite_state = self.callsite_state(block_number)
        calldata = raw_calldata
        # calldata -> bvv bytes
        offset = callsite_state.curr_stmt.argsOffset_val
        length = callsite_state.curr_stmt.argsSize_val

        calldata_length = BVV(len(calldata) // 2, 256)

        if not callsite_state.solver.is_formula_sat(BV_UGE(calldata_length, length)):
            # be dumb, skim off a few bytes and retry
            calldata = calldata[:-32]
            calldata_length = BVV(len(calldata) // 2, 256)
            while not callsite_state.solver.is_formula_sat(BV_UGE(calldata_length, length)):
                calldata = calldata[:-32]
                calldata_length = BVV(len(calldata) // 2, 256)

        if calldata_length.value == 0:
            log.error("Could not fit calldata in memory buffer")
            return raw_calldata
        
        callsite_state.solver.add_path_constraint(BV_UGE(calldata_length, length))
        offset = concretize(callsite_state, offset, force=True)
        length = concretize(callsite_state, length, force=True)

        sym_calldata = BV_Concat([BVV(int(calldata[i:i+2], 16), 8) for i in range(0, len(calldata), 2)])
        mem_calldata = callsite_state.memory.readn(offset, calldata_length)
        callsite_state.solver.add_memory_constraint(Equal(sym_calldata, mem_calldata))

        proxy_calldata = callsite_state.solver.eval_memory_at(callsite_state.memory, offset, length)
        return proxy_calldata

    def format_calldata(self, calldata, block_number):
        if self.proxy_address == self.address:
            return calldata
        elif self.pc in {"0x0",}:
            return calldata
        elif self.pc in {"-0x1",}:
            log.warning(f"Cannot format calldata for target at {self.pc=} (dummy target, previously unaccounted logic). Returning raw calldata.")
            return calldata
        
        try:
            callsite_state = self.callsite_state(block_number)
        except (GreedException, AssertionError) as e:
            raise GreedException(f"Could not find a state that reaches the callsite at {self.pc}") from e
            
        try:
            callsite_state.solver.push()
            return self._format_calldata(calldata, block_number=block_number)
        except (GreedException, AssertionError) as e:
            raise GreedException(f"Could not format calldata at {self.pc}") from e
        finally:
            callsite_state.solver.pop()

    def to_dict(self):
        return {
            "kind": self.__class__.__name__,
            "pc": self.pc,
            "proxy_address": self.proxy_address,
            "address": self.address,
            "window_start": self.window_start,
            "window_end": self.window_end
        }
    
    def from_dict(d):
        target_classname_to_class = {c.__name__: c for c in get_all_subclasses(Target)}
        target_class = target_classname_to_class[d["kind"]]
        kwargs = {k: v for k, v in d.items() if k != "kind"}
        return target_class(**kwargs)

    def __str__(self):
        return f"{self.__class__.__name__}({self.pc=}, {self.proxy_address=}, {self.address=}, {self.window_start}, {self.window_end})"
    
    def __repr__(self):
        return self.__str__()
    
    def copy(self):
        _copy = self.__class__(self.pc, self.proxy_address, self.address, self.window_start, self.window_end)
        _copy._project = self._project
        _copy._type_analysis = self._type_analysis
        return _copy
    
    def __hash__(self):
        return hash(tuple(self.to_dict().values()))
    
    def __eq__(self, other):
        return hash(self) == hash(other)
    
class Proxy(Target):
    pass
    
class TargetConstant(Target):
    pass
    
class TargetStorage(Target):
    def __init__(self, pc, proxy_address, address, window_start, window_end, slot, mask):
        super().__init__(pc, proxy_address, address, window_start, window_end)
        self.slot = slot
        self.mask = mask

    def __str__(self):
        return f"{self.__class__.__name__}({self.pc=}, {self.proxy_address=}, {self.address=}, {self.window_start}, {self.window_end}, {self.slot=})"
    
    def copy(self):
        return TargetStorage(self.pc, self.proxy_address, self.address, self.window_start, self.window_end, self.slot, self.mask)
    
    def to_dict(self):
        return {
            "kind": "TargetStorage",
            "pc": self.pc,
            "proxy_address": self.proxy_address,
            "address": self.address,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "slot": self.slot,
            "mask": self.mask
        }
    
class TargetCalldata(Target):
    def __init__(self, pc, proxy_address, address, window_start, window_end, mask):
        super().__init__(pc, proxy_address, address, window_start, window_end)
        self.mask = mask

    def __str__(self):
        return f"{self.__class__.__name__}({self.pc=}, {self.proxy_address=}, {self.address=}, {self.window_start}, {self.window_end}, {self.mask=})"
    
    def copy(self):
        return TargetCalldata(self.pc, self.proxy_address, self.address, self.window_start, self.window_end, self.mask)
    
    def to_dict(self):
        return {
            "kind": "TargetCalldata",
            "pc": self.pc,
            "proxy_address": self.proxy_address,
            "address": self.address,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "mask": self.mask
        }
    
class TargetExternal(Target):
    def __init__(self, pc, proxy_address, address, window_start, window_end, source_address):
        super().__init__(pc, proxy_address, address, window_start, window_end)
        self.source_address = source_address

    def __str__(self):
        return f"{self.__class__.__name__}({self.pc=}, {self.proxy_address=}, {self.address=}, {self.window_start}, {self.window_end}, {self.source_address=})"
    
    def copy(self):
        return TargetExternal(self.pc, self.proxy_address, self.address, self.window_start, self.window_end, self.source_address)
    
    def to_dict(self):
        return {
            "kind": "TargetExternal",
            "pc": self.pc,
            "proxy_address": self.proxy_address,
            "address": self.address,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "source_address": self.source_address
        }
    
    def copy(self):
        return TargetExternal(self.pc, self.proxy_address, self.address, self.window_start, self.window_end, self.source_address)
    
class TargetUnknown(Target):
    pass

class NestedTargetConstant(TargetConstant):
    pass