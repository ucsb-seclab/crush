from enum import Enum


class Collision(object):
    def __init__(self, slot1, slot2, target1, target2, types1, types2):
        self.slot1 = slot1
        self.slot2 = slot2
        self.target1 = target1
        self.target2 = target2
        self.types1 = types1
        self.types2 = types2

    def __str__(self):
        return f"{self.__class__.__name__}({self.slot1=}, {self.slot2=}, {self.target1.address=}, {self.target2.address=})"
    
    def __repr__(self):
        return self.__str__()
    
    def __hash__(self):
        return hash((self.slot1, self.slot2, tuple(sorted([self.target1.address, self.target2.address]))))
    
    def __eq__(self, other):
        return hash(self) == hash(other)


class Shift(Collision):
    def __init__(self, slot1, slot2, target1, target2, types1, types2):
        super().__init__(slot1, slot2, target1, target2, types1, types2)


class AttackRequest(object):
    class ATTACK_TYPE(Enum):
        COLLISION = 1
        SHIFT = 2

    def __init__(self, attack_type=None, slot=None, target_block=None, proxy=None, target1=None, target2=None,
                 target1_slot=None, target1_types=None, target2_slot=None, target2_types=None, partial_init=False):
        if partial_init:
            return
        
        self.attack_type = attack_type
        self.slot = slot
        self.target_block = target_block

        self.proxy_address = proxy.address

        self.target1_address = target1.address
        self.target1_pc = target1.pc
        self.target1_alive = (target1.window_start <= self.target_block <= target1.window_end)
        self.target1_window = [target1.window_start, target1.window_end]
        # NOTE: only want to write if the sstore is for the base slot "slot" (i.e., no mapping/array non-base slots)
        self.target1_slot = target1_slot
        self.target1_types = sorted(target1_types)
        self.target1_sstores = {pc for pc, val in target1.type_analysis["storage_accesses"].items() 
                                if val["slot"] == slot 
                                and ((set(val["access_masks"]) & set(target1_types)) != set())
                                and target1.project.statement_at[pc].__internal_name__ == "SSTORE"
                                and val["is_base_slot"] is True}
        self.target1_sstores = sorted(self.target1_sstores)

        self.target2_address = target2.address
        self.target2_pc = target2.pc
        self.target2_alive = (target2.window_start <= self.target_block <= target2.window_end)
        self.target2_window = [target2.window_start, target2.window_end]
        self.target2_slot = target2_slot
        self.target2_types = sorted(target2_types)
        self.is_target2_sensitive = (target2_types & target2.sensitive_slots[slot] != set())
        self.is_target2_guarding_sensitive = (target2_types & target2.guarding_sensitive_slots[slot] != set())
        self.target2_sloads = set()
        self.target2_guarded_sstores = set()

        if self.is_target2_sensitive or self.is_target2_guarding_sensitive:
            self.target2_sloads = {pc for pc, storage_access in target2.type_analysis["storage_accesses"].items() 
                                   if storage_access["slot"] == slot 
                                   and ((set(storage_access["access_masks"]) & set(target2_types)) != set())
                                   and target2.project.statement_at[pc].__internal_name__ == "SLOAD"
                                   and storage_access["is_base_slot"] is True}
        if self.is_target2_guarding_sensitive:
            self.target2_guarded_sstores = {s.id for t in target2_types
                                            for s in target2.guarded_sensitive_slots[(slot, t)]
                                            if target2.project.statement_at[s.id].__internal_name__ == "SSTORE"
                                            and target2.type_analysis["storage_accesses"][s.id]["is_base_slot"] is True}
        self.target2_sloads = sorted(self.target2_sloads)
        self.target2_guarded_sstores = sorted(self.target2_guarded_sstores)

    def to_dict(self):
        j = self.__dict__.copy()
        j["attack_type"] = self.attack_type.value
        return j
    
    @staticmethod
    def from_dict(j):
        attack_request = AttackRequest(partial_init=True)
        attack_request.attack_type = AttackRequest.ATTACK_TYPE(j["attack_type"])
        attack_request.slot = j["slot"]
        attack_request.target_block = j["target_block"]
        attack_request.proxy_address = j["proxy_address"]
        attack_request.target1_address = j["target1_address"]
        attack_request.target1_pc = j["target1_pc"]
        attack_request.target1_alive = j["target1_alive"]
        attack_request.target1_window = j["target1_window"]
        attack_request.target1_slot = j["target1_slot"]
        attack_request.target1_types = j["target1_types"]
        attack_request.target1_sstores = j["target1_sstores"]
        attack_request.target2_address = j["target2_address"]
        attack_request.target2_pc = j["target2_pc"]
        attack_request.target2_alive = j["target2_alive"]
        attack_request.target2_window = j["target2_window"]
        attack_request.target2_slot = j["target2_slot"]
        attack_request.target2_types = j["target2_types"]
        attack_request.is_target2_sensitive = j["is_target2_sensitive"]
        attack_request.is_target2_guarding_sensitive = j["is_target2_guarding_sensitive"]
        attack_request.target2_sloads = j["target2_sloads"]
        attack_request.target2_guarded_sstores = j["target2_guarded_sstores"]

        return attack_request
    
    def __str__(self) -> str:
        impact = "non-sensitive"
        if self.is_target2_sensitive and self.is_target2_guarding_sensitive:
            impact = "sensitive and guarding"
        elif self.is_target2_sensitive:
            impact = "sensitive"
        elif self.is_target2_guarding_sensitive:
            impact = "guarding"

        return f"AttackRequest([{self.target_block}], {self.target1_address} -> {self.target2_address}, {impact} slot {self.slot})"