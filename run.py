from colorama import Fore
import logging
from typing import Optional
from mitmproxy import proxy, options, ctx, contentviews, flow, http
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.tools.web.master import WebMaster
from mitmproxy.addons import core
import asyncio

from BAProxy import BAProxy
from tools.ViewBAApi import ViewBAApi

import socket
import random


class MitmWrapper(object):
    mitm = None

    @staticmethod
    def __check_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("localhost", port))
                return True
            except OSError:
                return False

    @classmethod
    def __get_random_port(cls):
        for _ in range(10):
            port = random.randint(8100, 8500)
            if cls.__check_port(port):
                return port
        raise Exception("No available port found after 10 attempts.")

    async def start(self, mode: str = 'dump'):
        mitm_dict = {'web': WebMaster, 'dump': DumpMaster}
        opts = options.Options(listen_host='0.0.0.0', listen_port=8516,
                               rawtcp=False)

        self.mitm = mitm_dict[mode](opts)
        self.mitm.options.update(termlog_verbosity='error')
        self.mitm.options.update(web_port=self.__get_random_port())
        self.mitm.addons.add(BAProxy(self.mitm))
        if mode == 'web':
            contentviews.add(ViewBAApi())
        try:
            await self.mitm.run()
        except KeyboardInterrupt:
            self.mitm.shutdown()


if __name__ == "__main__":
    logFormat = Fore.LIGHTCYAN_EX + \
                '┌ %(asctime)s - %(levelname)s [%(name)s] @%(filename)s:%(lineno)d \n└ ' + \
                Fore.RESET + '%(message)s'
    logging.basicConfig(format=logFormat, datefmt='%H:%M:%S', level=logging.ERROR)
    asyncio.run(MitmWrapper().start('web'))
