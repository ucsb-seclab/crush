from collections import defaultdict
from functools import reduce
from itertools import combinations, chain

from greed.solver.shortcuts import Equal, BV_Extract, BVV


def get_mask(solver, unmasked_bytes, masked_bytes, len_masked_bytes=32, tailing_00=True):
    def is_value(bv, byte_offset, value):
        return solver.is_formula_true(Equal(BV_Extract(byte_offset * 8, byte_offset * 8 + 7, bv), value))

    def is_00(bv, byte_offset):
        return is_value(bv, byte_offset, BVV(0x00, 8))

    ####################################################################################################################
    # SCAN LEADING BYTES
    # 3231302928272625242322212019181716151413121110090807060504030201 (sload bytes)
    # 0000000000000000000000000000000000000000000000000000000032310000 (current value)
    #                                                             ^^^^ leading bytes
    # ffff000000000000000000000000000000000000000000000000000000000000 (mask)
    ####################################################################################################################
    leading_len = 0
    while leading_len < len(unmasked_bytes) and leading_len < len_masked_bytes and is_00(masked_bytes, leading_len):
        leading_len += 1

    if leading_len == len_masked_bytes:
        # all masked
        return None
    # print(f"{leading_len=}")

    ####################################################################################################################
    # FIND SHIFT TO UNMASKED BYTES
    # 3231302928272625242322212019181716151413121110090807060504030201 (sload bytes)
    #   ^^                                                             shift (31)
    # 0000000000000000000000000000000000000000000000000000000032310000 (current value)
    # ffff000000000000000000000000000000000000000000000000000000000000 (mask)
    ####################################################################################################################
    for i, unmasked_byte in enumerate(unmasked_bytes):
        if is_value(masked_bytes, leading_len, unmasked_bytes[i]):
            shift = i
            break
    else:
        # shift not found
        return None
    # print(f"{shift=}")

    ####################################################################################################################
    # SCAN UNMASKED BYTES (what do we still control?)
    # 3231302928272625242322212019181716151413121110090807060504030201 (sload bytes)
    # ^^^^                                                             unmasked bytes
    # 0000000000000000000000000000000000000000000000000000000032310000 (current value)
    # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^         note: we also check if everything else is masked
    # ffff000000000000000000000000000000000000000000000000000000000000 (mask)
    ####################################################################################################################
    still_unmasked_bytes = set()
    unmasked_len = 0
    masked_cursor = leading_len + unmasked_len
    unmasked_cursor = shift + unmasked_len
    # start scanning from the shift.
    max_unmasked_len = len(unmasked_bytes) - max(leading_len, shift) + 1
    # print(f"{max_unmasked_len=}")
    while unmasked_len < max_unmasked_len and unmasked_len < len_masked_bytes and unmasked_cursor < len(unmasked_bytes) and masked_cursor < len_masked_bytes:
        # print(f"{masked_cursor=}, {unmasked_cursor=}")
        if is_value(masked_bytes, masked_cursor, unmasked_bytes[unmasked_cursor]):
            still_unmasked_bytes.add(unmasked_cursor)
        elif tailing_00 and not is_00(masked_bytes, masked_cursor):
            # only masking and shifting is allowed: the mask is invalid if this is not an unmasked byte and not a zero
            return None
        unmasked_len += 1
        masked_cursor = leading_len + unmasked_len
        unmasked_cursor = shift + unmasked_len
    # print(f"{unmasked_len=}")

    # translate unmasked bytes -> mask
    mask = ""
    for i in range(0, len(unmasked_bytes))[::-1]:
        if i in still_unmasked_bytes:
            mask += "ff"
        else:
            mask += "00"

    return mask


def get_collision_mask(slot_masks):
    if not slot_masks:
        return "00"*32

    collision_mask = ""
    for i in range(32):
        curr_byte = 0xff << 8 * i
        counter = 0
        for mask in slot_masks:
            if curr_byte & int(mask, 16):
                counter += 1
        if counter > 1:
            collision_mask = "ff" + collision_mask
        else:
            collision_mask = "00" + collision_mask

    return collision_mask


def get_combined_mask(masks):
    if not masks:
        return None

    combined_mask = ""
    for i in range(32):
        curr_byte = 0xff << 8 * i
        counter = 0
        for mask in masks:
            if curr_byte & int(mask, 16):
                counter += 1
        if counter > 0:
            combined_mask = "ff" + combined_mask
        else:
            combined_mask = "00" + combined_mask

    return combined_mask


def find_colliding_masks(masks):
        collision_mask = get_collision_mask(masks)
        return {m for m in masks if int(m, 16) & int(collision_mask, 16) != 0}


def find_collisions(access_masks):
    results = defaultdict(dict)

    all_slots = {slot for target in access_masks for slot in access_masks[target]}
    for slot in all_slots:
        targets_with_slot = {target for target in access_masks.keys() if slot in access_masks[target]}
        slot_masks = set.union(*[set(access_masks[target][slot]) for target in targets_with_slot])

        # get collision blacklist from self collisions
        collision_blacklist = set()
        for target in targets_with_slot:
            self_collision = find_colliding_masks(access_masks[target][slot])
            collision_blacklist.add(tuple(sorted(self_collision)))

        collision_mask = get_collision_mask(slot_masks)
        colliding_masks = find_colliding_masks(slot_masks)

        # continue if there is no collision
        if collision_mask == "0000000000000000000000000000000000000000000000000000000000000000":
            continue
        # continue if collision is in blacklist
        elif tuple(sorted(colliding_masks)) in collision_blacklist:
            continue

        for target in targets_with_slot:
            if any([m in colliding_masks for m in access_masks[target][slot]]):
                results[slot][target] = [m for m in access_masks[target][slot] if m in colliding_masks]

    return results


def filter_masks(masks, reference_masks=None):
    # if we have reference masks, return any reference mask that is (even partially) in masks
    if reference_masks:
        return {mask for mask in reference_masks if any([int(mask, 16) & int(m, 16) != 0 for m in masks])}

    # else filter
    filtered_masks = set(masks)

    # choose more specific dynamic type over less specific
    dynamic_masks = {"bb" * 32, "cc" * 32, "dd" * 32, "ee" * 32}
    for mask in sorted(dynamic_masks):
        if mask in filtered_masks:
            filtered_masks = {mask, }
            break

    # drop mask if it's just the combination of any other slot's masks
    for mask in list(filtered_masks):
        def powerset2(iterable):
            s = list(iterable)
            return chain.from_iterable(combinations(s, r) for r in range(2, len(s) + 1))

        def is_mask_combo(m, m_other):
            _m = int(m, 16)
            _m_other = [int(__m, 16) for __m in m_other]
            return reduce(lambda x, y: x | y, _m_other) == _m

        other_masks = filtered_masks - {mask, }
        if any([is_mask_combo(mask, s) for s in powerset2(other_masks)]):
            filtered_masks -= {mask, }

    # if two masks collide, keep the smaller one
    # for each pair or masks
    for mask1, mask2 in list(combinations(filtered_masks, 2)):
        # if they collide
        if int(mask1, 16) & int(mask2, 16) != 0:
            # keep the smaller one
            if mask1.count("ff") < mask2.count("ff"):
                filtered_masks -= {mask2, }
            else:
                filtered_masks -= {mask1, }

    return filtered_masks