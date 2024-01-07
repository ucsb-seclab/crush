import networkx as nx
import subprocess

from greed.analyses.slicing import backward_slice, forward_slice
from greed.solver.shortcuts import is_concrete, bv_unsigned_value, BVV, NotEqual, Equal

from crush.globals import w3


def get_init_ctx(address=None, block_number=None, caller=None, origin=None, calldatasize=None):
    init_ctx = dict()

    if calldatasize is not None:
        init_ctx["CALLDATASIZE"] = calldatasize
    if address is not None:
        init_ctx["ADDRESS"] = address
    if caller is not None:
        init_ctx["CALLER"] = caller
    if origin is not None:
        init_ctx["ORIGIN"] = origin
    if block_number is not None:
        block_info = w3.eth.get_block(block_number)
        init_ctx.update({
            "NUMBER": block_number,
            "DIFFICULTY": block_info["totalDifficulty"],
            "TIMESTAMP": block_info["timestamp"]
        })

    return init_ctx


def concretize(state, val, force=False):
    if is_concrete(val):
        return BVV(bv_unsigned_value(val), 256)
        # return state.solver.eval(val, raw=True)
    else:
        try:
            val_sol = state.solver.eval(val, raw=True)
            if not state.solver.is_formula_sat(NotEqual(val, val_sol)):
                return val_sol
            elif force is True:
                state.add_constraint(Equal(val, val_sol))
                return val_sol
        except:
            return None


def get_shortest_forward_slice(project, stmt, vars):
    _forward_slice = forward_slice(project, stmt.id, vars)
    if len(_forward_slice) <= 1:
        return [s.id for s in _forward_slice]
    _dfs_tree = nx.dfs_tree(_forward_slice, stmt)
    _exits = [n for n in _dfs_tree if len(list(_dfs_tree.successors(n))) == 0]
    all_simple_paths = list(nx.all_simple_paths(_dfs_tree, stmt, _exits))
    if not all_simple_paths:
        return []
    _shortest_path = sorted(all_simple_paths, key=lambda p: len(p))[0]
    _shortest_path = [s.id for s in _shortest_path]
    return _shortest_path
        

def get_shortest_backward_slice(project, stmt, vars):
    _backward_slice = backward_slice(project, stmt.id, vars)
    if len(_backward_slice) <= 1:
        return [s.id for s in _backward_slice]
    _reversed_dfs_tree = nx.dfs_tree(_backward_slice.reverse(), stmt)
    _exits = [n for n in _reversed_dfs_tree if len(list(_reversed_dfs_tree.successors(n))) == 0]
    # filter exits to exclude loops
    # _exits = [n for n in _exits if stmt not in _backward_slice.predecessors(n)]
    all_simple_paths = list(nx.all_simple_paths(_reversed_dfs_tree, stmt, _exits))
    if not all_simple_paths:
        return []
    _shortest_path = sorted(all_simple_paths, key=lambda p: len(p))[0]
    _shortest_path = [s.id for s in _shortest_path][::-1]
    return _shortest_path
        

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    return result.stdout


def get_all_subclasses(cls):
    all_subclasses = []
    for subclass in cls.__subclasses__():
        all_subclasses.append(subclass)
        all_subclasses.extend(get_all_subclasses(subclass))

    return all_subclasses