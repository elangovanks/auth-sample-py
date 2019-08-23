import logging
import json
import sys
import requests
import tornado
import tornado.gen

class JwksProvider(object):

    def __init__(self, jwks_uri, loop_delay_hours=12, seconds_between_attempts=10):
        self.jwks_uri = jwks_uri
        self.loop_delay_hours = loop_delay_hours
        self.seconds_between_attempts = seconds_between_attempts
        self.jwks = None

    async def update(self):
        logging.info("Updating JWKS keys from %s", self.jwks_uri)
        attempt = 1
        while True:
            try:
                self.jwks = await tornado.ioloop.IOLoop.current().run_in_executor(None, lambda : requests.get(self.jwks_uri).json())
                logging.info("Got %s JWKS keys", len(self.jwks['keys']))
                return True
            except Exception as e:
                logging.error("Failed to get JWKS keys on attempt %s with error %s", attempt, e)
                attempt += 1
                if attempt <= 3:
                    await tornado.gen.sleep(self.seconds_between_attempts)
                else:
                    logging.fatal("Failed more then three times to get JWKS keys. This is fatal, something is seriously wrong, so exiting immediately.")
                    sys.exit()
                    return False

    async def update_loop(self):
        while True:
            logging.info("JWKS updater loop sleeping for % hours", self.loop_delay_hours)
            await tornado.gen.sleep(self.loop_delay_hours * 3600)
            if not await self.update():
                return

    def get_jwks(self):
        return self.jwks
