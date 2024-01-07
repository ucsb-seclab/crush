import json
import logging
import os

from crush import globals
from crush.masks import find_collisions


log = logging.getLogger(__name__)


def run_collision_analysis(self_address):
    # read all_targets from lifespan analysis
    lifespan_path = f"{globals.DATA_PATH}/lifespan/{self_address}.json"
    if not os.path.exists(lifespan_path):
        # abort if the file does not exist
        raise Exception(f"File {lifespan_path} does not exist!")
    with open(lifespan_path, "r") as f:
        all_targets = json.load(f)

    # read all type analysis reports
    access_masks = dict()

    for addr in {target["address"] for target in all_targets} | {self_address}:
        type_path = f"{globals.DATA_PATH}/type/{addr}.json"
        if not os.path.exists(type_path):
            # abort if the file does not exist
            log.error(f"File {type_path} does not exist!")
            continue
        with open(type_path, "r") as f:
            access_masks[addr] = json.load(f)["slot_types"]
    
    report = find_collisions(access_masks)
    return report