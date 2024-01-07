import logging

from collections import defaultdict

from greed import options
from greed.exploration_techniques import ExplorationTechnique
from greed.solver.shortcuts import BVV, BVS, Equal, BV_Concat, BV_Extract, is_concrete, bv_unsigned_value

from crush.utils import concretize


log = logging.getLogger(__name__)
        

class MonitorSLOAD(ExplorationTechnique):
    def setup(self, simgr):
        for state in simgr.states:
            if 'observed_sload_offsets' not in state.globals:
                state.globals['observed_sload_offsets'] = dict()

    def check_state(self, simgr, state):
        if state.curr_stmt.__internal_name__ == "SLOAD":
            state.curr_stmt.set_arg_val(state)
            storage_offset = state.curr_stmt.arg1_val

            if not is_concrete(storage_offset):
                storage_offset = int("0x" + "99"*20, 16)
            else:
                storage_offset = bv_unsigned_value(storage_offset)

            unmasked_bytes = [BVS(f"storage_{storage_offset}_{i}", 8) for i in range(1, 33)]
            # set storage to 32 known symbolic bytes
            state.storage[state.curr_stmt.key_val] = BV_Concat(unmasked_bytes[::-1])

            state.globals['observed_sload_offsets'][storage_offset] = unmasked_bytes

        return state
    

class StubUninitializedVars(ExplorationTechnique):
    @staticmethod
    def check_state(simgr, state):
        # stub anything that's undefined
        for arg_var in state.curr_stmt.arg_vars:
            if state.registers.get(arg_var) is None:
                state.registers[arg_var] = BVS(arg_var, 256)

        return state
    

class TagStatements(ExplorationTechnique):
    def __init__(self, statements) -> None:
        self.statements = statements
        self.tags = {s: BVS(f"tag_{s}", 256) for s in self.statements}
    
    def setup(self, simgr):
        for s in self.statements:
            if len(simgr.project.statement_at[s].res_vars) != 1:
                print(simgr.project.statement_at[s])
                raise NotImplementedError("TagStatements only supports statements with a single result variable")
        for state in simgr.states:
            if 'statement_tags' not in state.globals:
                state.globals['statement_tags'] = dict(self.tags)

    def check_successors(self, simgr, successors):
        for state in list(successors):
            if len(state.trace) == 0:
                continue
            prev = state.trace[-1]
            if prev.id in self.tags and prev.res1_var in state.registers and state.registers[prev.res1_var] != self.tags[prev.id]:
                log.debug(f"Tagging {prev.id} with {self.tags[prev.id]}")
                state.add_constraint(Equal(state.registers[prev.res1_var], self.tags[prev.id]))
                state.registers[prev.res1_var] = self.tags[prev.id]
        return successors


class MonitorCALLDATACOPY(ExplorationTechnique):
    def setup(self, simgr):
        for state in simgr.states:
            if 'observed_calldatacopy' not in state.globals:
                state.globals['observed_calldatacopy'] = dict()

    def check_state(self, simgr, state):
        if state.curr_stmt.__internal_name__ == "CALLDATACOPY":
            state.curr_stmt.set_arg_val(state)

            # destOffset needs to be concrete
            destOffset = concretize(state, state.curr_stmt.destOffset_val)
            if destOffset is None:
                return state

            # we'll take care of concretizing the rest later
            calldataOffset = concretize(state, state.curr_stmt.calldataOffset_val) or state.curr_stmt.calldataOffset_val
            copySize = concretize(state, state.curr_stmt.size_val) or state.curr_stmt.size_val

            state.globals['observed_calldatacopy'][destOffset] = (calldataOffset, copySize)

        return state
    

class MonitorCALL(ExplorationTechnique):
    def setup(self, simgr):
        for state in simgr.states:
            if 'observed_call' not in state.globals:
                state.globals['observed_call'] = dict()

    def check_state(self, simgr, state):
        if state.curr_stmt.__internal_name__ in {"CALL", "STATICCALL"}:
            state.curr_stmt.set_arg_val(state)

            # offset needs to be concrete
            offset_val = concretize(state, state.curr_stmt.retOffset_val)
            if offset_val is None:
                return state

            # size needs to be concrete
            size_val = concretize(state, state.curr_stmt.retSize_val)
            if size_val is None:
                return state

            address_val = concretize(state, state.curr_stmt.address_val)
            if address_val is None:
                address_val = BVV(int("0x" + "42"*20, 16), 256)
            
            # execute the call, this will copy the return data into memory
            state.curr_stmt.handle(state)

            # save the return data
            state.globals['observed_call'][(state.pc, state.instruction_count, hex(address_val.value))] = [state.memory[BVV(i, 256)] for i in range(offset_val.value, offset_val.value+size_val.value)[::-1]]

        return state
    

class SSTOREStub(ExplorationTechnique):
    def __init__(self, w3, address, block) -> None:
        super().__init__()
        self.w3 = w3
        self.address = address
        self.block = block
        
    def check_state(self, _, state):
        if state.curr_stmt.__internal_name__ != "SSTORE":
            return state
        state.curr_stmt.set_arg_val(state)
        
        # only stub if the key is concrete (simple type)
        if is_concrete(state.curr_stmt.key_val):
            key_val_sol = bv_unsigned_value(state.curr_stmt.key_val)
        else:
            return state
        slot = hex(key_val_sol)

        mask = "".join(["00" if state.solver.is_formula_true(Equal(BV_Extract(i*8, i*8+7, state.curr_stmt.value_val), BVV(0, 8))) else "ff" for i in range(32)[::-1]])
        if mask.find("ff") < 0:
            return state
        
        # value as hex padded to 32 bytes
        value_hex = self.w3.eth.get_storage_at(self.address, slot, self.block).hex()[2:].rjust(64, "0")
        masked_value_hex_padded = "".join([x if mask[i] == "f" else "0" for i, x in enumerate(value_hex)])

        # constrain the symbolic value to the on-chain value
        symbolic_value = state.curr_stmt.value_val
        on_chain_value = BVV(int(masked_value_hex_padded, 16), 256)

        if state.solver.is_formula_sat(Equal(symbolic_value, on_chain_value)):
            log.info(f"Partially stubbing SSTORE @ {state.curr_stmt.id} (slot {slot}) with {masked_value_hex_padded}")
            state.add_constraint(Equal(symbolic_value, on_chain_value))
        else:
            log.info(f"FAILED TO PARTIALLY STUB SSTORE @ {state.curr_stmt.id} (slot {slot}) with {masked_value_hex_padded}")
        return state


class Simplifier(ExplorationTechnique):
    def check_state(self, _, state):
        if state.curr_stmt.__internal_name__ in {"CODECOPY", "EXTCODESIZE", "EXP", "SIGNEXTEND", "BYTE"}:
            # skip if the state is unsat
            if not state.solver.is_sat():
                return state
            
            # skip EXTCODESIZE if DEFAULT_EXTCODESIZE is True
            if state.curr_stmt.__internal_name__ == "EXTCODESIZE" and options.DEFAULT_EXTCODESIZE is True:
                return state
            
            # emit warning
            log.warning(f"Concretizing arguments for {state.curr_stmt.__internal_name__} @ {state.curr_stmt.id}")
            
            state.solver.simplify()

            # ensure that every argument is concrete, these ops will fail otherwise
            state.curr_stmt.set_arg_val(state)
            for arg_var, arg_val in state.curr_stmt.arg_vals.items():
                if not is_concrete(arg_val):
                    arg_val_sol = state.solver.eval(arg_val, raw=True)
                    state.add_constraint(Equal(arg_val, arg_val_sol))
                    state.registers[arg_var] = arg_val_sol
            state.curr_stmt.set_arg_val(state)

        return state
    

class LoopLimiter(ExplorationTechnique):
    def __init__(self, max_counter=16) -> None:
        super().__init__()
        self.max_counter = max_counter

    def setup(self, simgr):
        for state in simgr.states:
            if 'pc_counter' not in state.globals:
                state.globals['pc_counter'] = defaultdict(int)
                state.globals['last_trace_len'] = 0

    def check_successors(self, simgr, successors):
        for state in list(successors):
            if state.globals['last_trace_len'] != len(state.trace):
                state.globals['last_trace_len'] = len(state.trace)
                state.globals['pc_counter'][state.trace[-1].id] += 1
                if max(state.globals['pc_counter'].values()) > self.max_counter:
                    log.info(f"LoopLimiter: Pruning state {state}")
                    simgr.stashes['pruned'].append(state)
                    successors.remove(state)
        return successors
    

class PathFinder(ExplorationTechnique):
    def __init__(self, path) -> None:
        super().__init__()
        self.full_path = list(path)
        self.path = list(path)

    def check_successors(self, simgr, successors):
        for state in list(successors):
            if len(self.path) > 0:
                state.pc = self.path[0]
            else:
                state.halt = True
        self.path = self.path[1:]
        return successors