import asyncio
import os
import logging
import backoff
import logging
import logging.handlers
import web3
import web3.types
import web3.contract
import websockets.exceptions

from web3.providers.base import JSONBaseProvider

from crush import globals


l = logging.getLogger(__name__)


class RetryingProvider(JSONBaseProvider):
    _internal_provider: web3.WebsocketProvider

    def __init__(self) -> None:
        super().__init__()
        self._internal_provider = None
        self._connect()

    def _connect(self):
        l.debug('connecting to web3')
        web3_host = os.getenv('WEB3_HOST', globals.WEB3_HOST)

        self._internal_provider = web3.WebsocketProvider(
            web3_host,
            websocket_timeout=60 * 5,
            websocket_kwargs={
                'max_size': 1024 * 1024 * 1024, # 1 Gb max payload
            },
        )

    @backoff.on_exception(
        backoff.expo,
        (
            websockets.exceptions.ConnectionClosedError,
            asyncio.exceptions.TimeoutError,
        ),
        max_time = 10 * 60,
        factor = 4,
        on_backoff = lambda x: x['args'][0]._connect()
    )
    def make_request(self, method, params):
        request_data = self.encode_rpc_request(method, params)
        future = asyncio.run_coroutine_threadsafe(
            self._internal_provider.coro_make_request(request_data),
            web3.WebsocketProvider._loop
        )
        ret = future.result()
        return ret


def connect_web3() -> web3.Web3:
    w3 = web3.Web3(RetryingProvider())

    if not w3.is_connected():
        l.error(f'Could not connect to web3')
        exit(1)

    l.debug(f'Connected to web3, chainId={w3.eth.chain_id}')

    return w3