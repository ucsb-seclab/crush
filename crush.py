#!/usr/bin/env python3

import argparse
import json
import logging

from crush import globals
from crush.core import interactions, lifespan, type, collisions, impact, exploit


LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log_greed = logging.getLogger("greed")
log = logging.getLogger('crush')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-D", "--data", type=str, action="store", help="Data path")

    subparsers = parser.add_subparsers(dest='command', required=False)

    # Proxy subparser
    proxy_parser = subparsers.add_parser('interactions', help='Run Interaction analysis')
    proxy_parser.add_argument("address", type=str, action="store", help="Target Address")
    proxy_parser.add_argument("-o", "--output", type=str, action="store", help="Output file")

    # Lifespan subparser
    lifespan_parser = subparsers.add_parser('lifespan', help='Run Lifespan analysis')
    lifespan_parser.add_argument("address", type=str, action="store", help="Target Address")
    lifespan_parser.add_argument("-o", "--output", type=str, action="store", help="Output file")
    lifespan_parser.add_argument("-i", "--known-interactions", type=str, nargs="+", action="store", help="Known interactions")
    lifespan_parser.add_argument("-u", "--unreachable", action="store_true", help="Include maybe unreachable targets")

    # Type subparser
    type_parser = subparsers.add_parser('type', help='Run Type analysis')
    type_parser.add_argument("address", type=str, action="store", help="Target Address")
    type_parser.add_argument("-o", "--output", type=str, action="store", help="Output file")

    # Collision subparser
    collision_parser = subparsers.add_parser('collision', help='Run Collision analysis')
    collision_parser.add_argument("address", type=str, action="store", help="Target Address")
    collision_parser.add_argument("-o", "--output", type=str, action="store", help="Output file")

    # Impact subparser
    impact_parser = subparsers.add_parser('impact', help='Run Impact analysis')
    impact_parser.add_argument("address", type=str, action="store", help="Target Address")
    impact_parser.add_argument("-o", "--output", type=str, action="store", help="Output file")

    # Exploit subparser
    exploit_parser = subparsers.add_parser('exploit', help='Run Exploit analysis')
    exploit_parser.add_argument("attack_request_path", type=str, action="store", help="Path to Attack Request")
    exploit_parser.add_argument("-o", "--output", type=str, action="store", help="Output file")

    args = parser.parse_args()

    #######################################################################
    # setup logging
    #######################################################################
    if args.debug:
        log.setLevel("DEBUG")
        log_greed.setLevel("DEBUG")
    else:
        log.setLevel("INFO")
        log_greed.setLevel("ERROR")

    #######################################################################
    # setup data path
    #######################################################################
    if args.data:
        globals.DATA_PATH = args.data

    #######################################################################
    if args.command == "interactions":
        known_interactions = interactions.run_interaction_analysis(args.address)
        output = json.dumps(known_interactions, indent=4)

    elif args.command == "lifespan":
        all_targets = lifespan.run_dynamic_lifespan_analysis(args.address, known_interactions=args.known_interactions, with_unreachable=args.unreachable)
        all_targets = sorted(all_targets, key=lambda t: t.window_start)
        output = json.dumps([t.to_dict() for t in all_targets], indent=4)

    elif args.command == "type":
        type_report = type.run_type_analysis(args.address)
        output = json.dumps(type_report, indent=4)

    elif args.command == "collision":
        collisions = collisions.run_collision_analysis(args.address)
        output = json.dumps(collisions, indent=4)

    elif args.command == "impact":
        attack_requests = impact.run_impact_analysis(args.address)
        output = json.dumps([r.to_dict() for r in attack_requests], indent=4)

    elif args.command == "exploit":
        attack_requests = exploit.run_exploit_analysis(args.attack_request_path)
        output = None
    
    if args.output and output is not None:
        with open(args.output, "w") as f:
            f.write(output)
    elif output is not None:
        print(output)