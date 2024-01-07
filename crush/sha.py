import networkx as nx

from eth_utils import keccak

from greed.analyses.slicing import inline_cfg

from crush.utils import concretize, get_shortest_forward_slice, get_shortest_backward_slice
from crush.target import Target

KNOWN_HASHES = {int.from_bytes(keccak(int.to_bytes(i, 32, byteorder="big")), byteorder="big"): i for i in range(1024)}

class WrappedStmt(object):
    def __init__(self, stmt):
        self.stmt = stmt

    def __hash__(self) -> int:
        return self.stmt.__hash__()

    def __eq__(self, other) -> bool:
        return self.stmt == other.stmt if isinstance(other, WrappedStmt) else self.stmt == other

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.stmt})"

    def __repr__(self) -> str:
        return str(self)


class Wrapped_BaseConst(WrappedStmt):
    def __init__(self, stmt, slot):
        self.stmt = stmt
        self.slot = slot


class Wrapped_Sha32(WrappedStmt):
    def __init__(self, stmt, slot_offset):
        self.stmt = stmt
        self.slot_offset = slot_offset


class Wrapped_Sha32Const(WrappedStmt):
    def __init__(self, stmt, slot):
        self.stmt = stmt
        self.slot = slot


class Wrapped_Sha64(WrappedStmt):
    def __init__(self, stmt, key_offset, slot_offset):
        self.stmt = stmt
        self.key_offset = key_offset
        self.slot_offset = slot_offset


class Wrapped_ShaPlusOffset(WrappedStmt):
    def __init__(self, stmt, sha):
        self.stmt = stmt
        self.sha = sha


class ShaFlowAnalysis:
    def __init__(self, project):
        self.sha_graph = nx.DiGraph()

        # find sha statements
        for stmt in {s for s in project.statement_at.values() if s.__internal_name__ in {"SHA3"}}:
            # alright we might need symbolic execution here after all, sometime constants are
            # not propagated and mem_size is none (0x11c60C661cdC828c549372C9776fAAF3Ef407079 : 0x6c2)
            backward_slice = get_shortest_backward_slice(project, stmt, [stmt.arg1_var, stmt.arg2_var])
            found = Target.state_at(project=project, stmt=stmt, path=backward_slice)
            stmt = found.curr_stmt

            mem_offset = concretize(found, stmt.arg1_val, force=True)
            mem_size = concretize(found, stmt.arg2_val, force=True)
            if mem_offset.value is None or mem_size is None:
                continue
            if mem_size.value == 32:
                self.sha_graph.add_node(Wrapped_Sha32(stmt, mem_offset.value))
            elif mem_size.value == 64:
                self.sha_graph.add_node(Wrapped_Sha64(stmt, mem_offset.value, mem_offset.value + 0x20))
        for stmt in {s for s in project.statement_at.values() if s.__internal_name__ in {"CONST"}}:
            if stmt.res1_val.value in KNOWN_HASHES.keys():
                slot = KNOWN_HASHES[stmt.res1_val.value]
                self.sha_graph.add_node(Wrapped_Sha32Const(stmt, slot))

        # find sha + var statements
        for sha in list(self.sha_graph):
            forward_slice = get_shortest_forward_slice(project, sha.stmt, [sha.stmt.res1_var])
            for stmt_id in forward_slice:
                stmt = project.statement_at[stmt_id]
                if stmt.__internal_name__ == "ADD" and sha.stmt.res1_var in stmt.arg_vars:
                    self.sha_graph.add_node(Wrapped_ShaPlusOffset(stmt, sha))
                    self.sha_graph.add_edge(sha, Wrapped_ShaPlusOffset(stmt, sha))

        # find flows between shas
        # find mem source of each Wrapped_Sha32 and Wrapped_Sha64
        for sha in {s for s in self.sha_graph if isinstance(s, (Wrapped_Sha32, Wrapped_Sha64))}:
            # find mem source of sha
            mstore = ShaFlowAnalysis._find_mem_offset_source(project, sha.stmt, sha.slot_offset)
            # print(f"{mstore} -> {sha.stmt}")

            if mstore is None:
                continue

            # then find value source of the mstore
            backward_slice = get_shortest_backward_slice(project, mstore, [mstore.value_var])
            for s in backward_slice[::-1]:
                stmt = project.statement_at[s]
                if (mstore.value_var in stmt.res_vars and
                    stmt in self.all_Sha32|self.all_Sha64|self.all_ShaPlusOffset):
                    parent_sha = [s for s in self.all_Sha32|self.all_Sha64|self.all_ShaPlusOffset if s.stmt == stmt][0]
                    self.sha_graph.add_edge(parent_sha, sha)
                    break
                elif (mstore.value_var in stmt.res_vars and
                      stmt.__internal_name__ == "CONST" and
                      stmt.res1_val is not None):
                    parent_base = Wrapped_BaseConst(stmt, stmt.res1_val.value)
                    self.sha_graph.add_node(parent_base)
                    self.sha_graph.add_edge(parent_base, sha)
                    break

    @property
    def all_ShaPlusOffset(self):
        return {s for s in self.sha_graph if isinstance(s, Wrapped_ShaPlusOffset)}

    @property
    def all_Sha32(self):
        return {s for s in self.sha_graph if isinstance(s, Wrapped_Sha32)}

    @property
    def all_Sha64(self):
        return {s for s in self.sha_graph if isinstance(s, Wrapped_Sha64)}

    @property
    def all_leaf_ids(self):
        return {s.stmt.id for s in self.sha_graph if self.sha_graph.out_degree(s) == 0}
    
    @property
    def all_usable_sha_ids(self):
        return {s.stmt.id for s in self.sha_graph if isinstance(s, (Wrapped_Sha32, Wrapped_Sha32Const, Wrapped_Sha64, Wrapped_ShaPlusOffset))}

    @staticmethod
    def _find_mem_offset_source(project, target_stmt, mem_offset):
        target_function = project.block_at[target_stmt.block_id].function
        target_function_cfg = inline_cfg(project, target_function.cfg.stmt_cfg)

        queue = [target_stmt]
        while queue:
            stmt = queue.pop(0)
            if stmt.__internal_name__ == "MSTORE":
                backward_slice = get_shortest_backward_slice(project, stmt, [stmt.offset_var])
                if not backward_slice:
                    continue
                found = Target.state_at(project=project, stmt=stmt, path=backward_slice)
                stmt_offset_val = concretize(found, stmt.offset_val)
                if stmt_offset_val is None:
                    # if there's another mstore with symbolic offset,
                    # we cannot know with certaintly which one is the source
                    return None
                elif stmt_offset_val.value == mem_offset:
                    return stmt

            # in any case keep looking at predecessors
            for pred in target_function_cfg.predecessors(stmt):
                queue.append(pred)

    @staticmethod
    def _check_flow_shape(flow, shape):
        if len(flow) != len(shape):
            return False
        for i in range(len(flow)):
            if not isinstance(flow[i], shape[i]):
                return False
        return True
    
    @staticmethod
    def get_base_slot(flow):
        if isinstance(flow[0], (Wrapped_BaseConst, Wrapped_Sha32Const)):
            return flow[0].slot
        else:
            return None
        
    @staticmethod
    def infer_basetype_from_flow(flow):
        if ShaFlowAnalysis._check_flow_shape(flow, [Wrapped_BaseConst, Wrapped_Sha32]):
            return "bytes/string"
        if ShaFlowAnalysis._check_flow_shape(flow, [Wrapped_Sha32Const]):
            return "bytes/string"
        # arrays always add the offset (even zero) before accessing the slot
        elif ShaFlowAnalysis._check_flow_shape(flow, [Wrapped_Sha32Const, Wrapped_ShaPlusOffset]):
            return "array"
        elif ShaFlowAnalysis._check_flow_shape(flow, [Wrapped_BaseConst, Wrapped_Sha32, Wrapped_ShaPlusOffset]):
            return "array"
        elif ShaFlowAnalysis._check_flow_shape(flow, [Wrapped_BaseConst, Wrapped_Sha64]):
            return "mapping"
        elif ShaFlowAnalysis._check_flow_shape(flow, [Wrapped_BaseConst, Wrapped_Sha64, Wrapped_Sha64]):
            return "mapping-mapping"

        # NOTE: could make this recursive to spot any combination of the above

    def get_flow_by_id(self, id):
        wrapped_stmt = [s for s in self.sha_graph if s.stmt.id == id][0]
        flow = [wrapped_stmt]
        while self.sha_graph.in_degree(wrapped_stmt) > 0:
            assert self.sha_graph.in_degree(wrapped_stmt) == 1, "Unsupported multiple parents in get_flow_by_id"
            wrapped_stmt = list(self.sha_graph.predecessors(wrapped_stmt))[0]
            flow = [wrapped_stmt] + flow
        return flow