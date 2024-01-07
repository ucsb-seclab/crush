#!/bin/bash

# ulimit -m 20000000; ulimit -v 20000000; ulimit -t 3600

DIR=$(dirname $0)

while (( $# >= 1 )); do
    case $1 in
    --proxy) PROXY_ADDRESS=$2; shift; shift;;
    --data) DATA_PATH=$2; shift; shift;;
    *) break;
    esac;
done

# error if PROXY_ADDRESS is not set or DATA_PATH is not set
if [ -z $PROXY_ADDRESS ]; then
    echo "Please specify a proxy address with --proxy"
    exit 1
fi

# read DATA_PATH from crush.globals
if [ -z $DATA_PATH ]; then
    DATA_PATH=$(python -c "import crush.globals; print(crush.globals.DATA_PATH)")
    read -p "Using DATA_PATH=${DATA_PATH}. Press any key to continue, or Ctrl-C to cancel."
fi

mkdir -p ${DATA_PATH}/interactions ${DATA_PATH}/lifespan ${DATA_PATH}/type ${DATA_PATH}/collisions ${DATA_PATH}/impact ${DATA_PATH}/exploit

INTERACTIONS_OUTPUT_FILE=${DATA_PATH}/interactions/${PROXY_ADDRESS}.json
LIFESPAN_OUTPUT_FILE=${DATA_PATH}/lifespan/${PROXY_ADDRESS}.json
COLLISIONS_OUTPUT_FILE=${DATA_PATH}/collisions/${PROXY_ADDRESS}.json
IMPACT_OUTPUT_FILE=${DATA_PATH}/impact/${PROXY_ADDRESS}.json

# find known interactions
timeout 300 $DIR/crush.py -D $DATA_PATH interactions $PROXY_ADDRESS -o $INTERACTIONS_OUTPUT_FILE

# find possible target contracts
KNOWN_INTERACTIONS=""
if [ -s $INTERACTIONS_OUTPUT_FILE ] && [ $(jq length $INTERACTIONS_OUTPUT_FILE) -gt 0 ]; then
    KNOWN_INTERACTIONS=$(jq -r '.[] | tostring' $INTERACTIONS_OUTPUT_FILE | tr '\n' ' ')
    KNOWN_INTERACTIONS="--known-interactions $KNOWN_INTERACTIONS"
fi

# then study their lifespan
timeout 1800 $DIR/crush.py -D $DATA_PATH lifespan $PROXY_ADDRESS $KNOWN_INTERACTIONS -o $LIFESPAN_OUTPUT_FILE

if [ ! -s $LIFESPAN_OUTPUT_FILE ] || [ ! $(jq length $LIFESPAN_OUTPUT_FILE) -gt 0 ]; then
    echo "Empty lifespan analysis. Exiting."
    exit 0
fi

# run the type analysis on the proxy and all target contracts
ALL_UNIQUE_TARGET_ADDRESSES=$(jq -r '.[] | .address' $LIFESPAN_OUTPUT_FILE | sort -u | tr '\n' ' ')
# ALL_UNIQUE_TARGET_ADDRESSES (includes PROXY_ADDRESS)
for t in $ALL_UNIQUE_TARGET_ADDRESSES; do
    timeout 1800 $DIR/crush.py -D $DATA_PATH type $t -o ${DATA_PATH}/type/$t.json
done

# find collisions
timeout 1800 $DIR/crush.py -D $DATA_PATH collision $PROXY_ADDRESS -o $COLLISIONS_OUTPUT_FILE

# run impact analysis
timeout 1800 $DIR/crush.py -D $DATA_PATH impact $PROXY_ADDRESS -o $IMPACT_OUTPUT_FILE

if [ ! -s $IMPACT_OUTPUT_FILE ] || [ ! $(jq length $IMPACT_OUTPUT_FILE) -gt 0 ]; then
    echo "Empty impact analysis. Exiting."
    exit 0
fi

# separate attack requests
NUM_ATTACK_REQUESTS=$(jq length $IMPACT_OUTPUT_FILE)
NUM_DIGITS=$(echo $NUM_ATTACK_REQUESTS | wc -c)
for (( i=0; i<$NUM_ATTACK_REQUESTS; i++ )); do
    # format with leading zeros
    suffix=$(printf "%0${NUM_DIGITS}d" $((i + 1))).json
    
    # extract ith attack request
    ATTACK_REQUEST=${DATA_PATH}/impact/${PROXY_ADDRESS}_${suffix}
    jq .[$i] $IMPACT_OUTPUT_FILE > $ATTACK_REQUEST
done

# run exploit analysis
for (( i=0; i<$NUM_ATTACK_REQUESTS; i++ )); do
    # format with leading zeros
    suffix=$(printf "%0${NUM_DIGITS}d" $((i + 1))).json
    
    # extract ith attack request
    ATTACK_REQUEST=${DATA_PATH}/impact/${PROXY_ADDRESS}_${suffix}

    # run exploit analysis
    timeout 1800 $DIR/crush.py -D $DATA_PATH exploit $ATTACK_REQUEST &> ${DATA_PATH}/exploit/$(basename $ATTACK_REQUEST)
done