GIGAHORSE_PATH = "/data/blockchain/contracts"
DATA_PATH = "/tmp/crush.data"

BLOCK_NUMBER = 16976770

DB_URL = "postgresql://blockchain:127.0.0.1:5432/mainnet"

WEB3_HOST = "ws://127.0.0.1:8545"

from crush.web3 import connect_web3
w3 = connect_web3()
