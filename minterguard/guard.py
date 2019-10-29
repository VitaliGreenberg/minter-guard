"""
Script, which can be used as a tracking service for node.
It accepts only one argument, if it is --config argument. You should provide
path to config file to read params from.
Or you can provide all needed arguments in command line:
    --api-url=
    --pub-key=
    --set-off-tx=
    --missed-blocks= (this argument is optional and is 4 by default)
    --sleep_time_ms= (this argument is optional and is 1000 by default)
	--bot_id= (this argument is optional and is '' by default, in this case no telegram messages will be sent)
	--chat_id= (this argument is optional and is 0 by default, in this case no telegram messages will be sent)
"""

import configparser
import logging
import sys
import time
import os
import requests
import subprocess

from mintersdk.minterapi import MinterAPI
from mintersdk.sdk.transactions import MinterTx, MinterSetCandidateOffTx


logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO').upper())
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
shandler = logging.StreamHandler()
shandler.setLevel(os.environ.get('LOG_LEVEL', 'INFO').upper())
shandler.setFormatter(formatter)
logger.addHandler(shandler)


class Guard(object):
    """
    Guard class
    """

    def __init__(self, api_urls, pub_key, set_off_tx, missed_blocks=4, sleep_time_ms=1000, bot_id='', chat_id=0):
        """
        Args:
            api_urls (list): Minter API URLs
            pub_key (str): Pub key of validator under control
            set_off_tx (str): Signed tx, which will be sent to chain
            missed_blocks (int): Amount of missed blocks, when validator
                                 should be offed
            sleep_time_ms (int): Amount of milliseconds between guard eviction
            bot_id (str): Bot ID for notifications on Telegram
            chat_id (int): Chat ID for notifications on Telegram
        """
        super().__init__()

        # Set attributes
        self.minterapis = [MinterAPI(api_url) for api_url in api_urls]
        self.pub_key = pub_key
        self.set_off_tx = set_off_tx
        self.missed_blocks = int(missed_blocks)
        self.sleep_time_ms = int(sleep_time_ms)
        self.bot_id = bot_id
        self.chat_id = int(chat_id)

        # Check set off tx to be valid
        tx = MinterTx.from_raw(self.set_off_tx)
        if not isinstance(tx, MinterSetCandidateOffTx):
            raise Exception('Set off tx is not instance of MinterSetCandidateOffTx')

        # Get nonce from API
        nonce = None
        for minterapi in self.minterapis:
            try:
                nonce = minterapi.get_nonce(tx.from_mx)
                break
            except Exception as e:
                logger.error('{}: {}'.format(
                    e.__class__.__name__,
                    e.__str__()
                ))

        if tx.nonce != nonce:
            raise Exception('Set off tx has {} nonce, expected {}'.format(
                tx.nonce,
                nonce
            ))

    def track(self):
        """
        Tracking method
        """

        # Send the 'Start' message to the Telegram, if it was configured well
        if self.bot_id != '' and self.chat_id != 0:
            try:
                requests.get("https://api.telegram.org/bot{}/sendMessage?chat_id={}&text=Minter-Guard has started monitoring {} for {} missed blocks."
				    .format(self.bot_id, self.chat_id, self.pub_key, self.missed_blocks))
            except Exception as ex:
                logger.error('Failed sending message to Telegram! Please fix and restart the service. No more attempts to send will be made.')
                logger.error('{}: {}'.format(e.__class__.__name__, e.__str__()))
                self.bot_id = ''
                self.chat_id = ''

        while True:
            try:
                # Get missed blocks
                response = None
                for i, minterapi in enumerate(self.minterapis):
                    if i > 0:
                        logger.info('{} attempt with {} API'.format(i, minterapi.api_url))
                    try:
                        response = minterapi.get_missed_blocks(self.pub_key)
                        break
                    except Exception as e:
                        logger.error('{}: {}'.format(
                            e.__class__.__name__,
                            e.__str__()
                        ))
                if response is None:
                    raise

                # Raise exception on non 404 error (Validator not found)
                if response.get('error'):
                    if response['error']['code'] != 404:
                        raise Exception(response['error'])
                    else:
                        logger.debug("Going for a sleep for {}ms.".format(self.sleep_time_ms))
                        time.sleep(self.sleep_time_ms/1000)
                        continue

                # If response is ok, get missed blocks count
                mb = int(response['result']['missed_blocks_count'])
                logger.debug("Missed block count: {}".format(mb))

                # If missed blocks is greater than limit, set candidate off
                if mb >= self.missed_blocks:
                    # Send set candidate off transaction

                    response = None
                    for minterapi in self.minterapis:
                        try:
                            response = minterapi.send_transaction(self.set_off_tx)
                            break
                        except Exception as e:
                            logger.error('{}: {}'.format(
                                e.__class__.__name__,
                                e.__str__()
                            ))
                    if response is None:
                        raise

                    if response.get('error'):
                        raise Exception(response['error'])

                    # Write log info message about setting candidate off
                    logger.warning('Set candidate off. Blocks missed: {}'.format(mb))

                    # Send the 'EMERGENCY' message to the Telegram, if it was configured well
                    if self.bot_id != '' and self.chat_id != 0:
						try:
							requests.get("https://api.telegram.org/bot{}/sendMessage?chat_id={}&text=EMERGENCY!!! Your Validator ({}) has been turned OFF !!! {} blocks missed.".format(self.bot_id, self.chat_id, self.pub_key, mb))
                        except Exception as ex:
                            logger.error('Failed sending message to Telegram! Please fix and restart the service. No more attempts to send will be made.')
                            logger.error('{}: {}'.format(e.__class__.__name__, e.__str__()))
                            self.bot_id = ''
                            self.chat_id = ''

            except Exception as e:
                logger.error('{}: {}'.format(
                    e.__class__.__name__,
                    e.__str__()
                ))

            # Wait specific time between each loop
            logger.debug("Going for a sleep for {}ms.".format(self.sleep_time_ms))
            time.sleep(self.sleep_time_ms/1000)


if __name__ == '__main__':
    try:
        # Future kwargs for Guard(**kwargs)
        kwargs = {}

        # Process sys argv and generate kwargs for Guard(**kwargs)
        if len(sys.argv) == 2 and '--config=' in sys.argv[1]:
            config = configparser.ConfigParser()
            config.read(sys.argv[1].split('=')[1])

            # If log file path is provided in config file, create file handler
            # and remove stream handler
            if 'SERVICE' in config.sections() and config['SERVICE'].get('LOG') and \
               config['SERVICE']['LOG'] != '':
                logger.removeHandler(shandler)
                fhandler = logging.FileHandler(config['SERVICE']['LOG'])
                fhandler.setLevel(os.environ.get('LOG_LEVEL', 'INFO').upper())
                fhandler.setFormatter(formatter)
                logger.addHandler(fhandler)

            # Check sections
            for section in ['API', 'NODE']:
                if section not in config.sections():
                    raise Exception('Section {} not found'.format(section))

            # Check sections attributes
            if config['API'].get('API_URL') is None or \
               config['API']['API_URL'] == '':
                raise Exception('API_URL should be provided')

            if config['NODE'].get('PUB_KEY') is None or \
               config['NODE']['PUB_KEY'] == '':
                raise Exception('PUB_KEY should be provided')

            if config['NODE'].get('SET_OFF_TX') is None or \
               config['NODE']['SET_OFF_TX'] == '':
                raise Exception('SET_OFF_TX should be provided')

            if 'TELEGRAM' in config.sections() and config['TELEGRAM'].get('BOT_ID') is not None and config['TELEGRAM'].get('BOT_ID') != '':
                kwargs['bot_id'] = config['TELEGRAM'].get('BOT_ID')

            if 'TELEGRAM' in config.sections() and config['TELEGRAM'].get('CHAT_ID') is not None and config['TELEGRAM'].get('CHAT_ID') != '':
                kwargs['chat_id'] = config['TELEGRAM'].get('CHAT_ID')

            # Set kwargs
            kwargs.update({
                'api_urls': config['API']['API_URL'].split(),
                'pub_key': config['NODE']['PUB_KEY'],
                'set_off_tx': config['NODE']['SET_OFF_TX']
            })

            if config['NODE'].get('MISSED_BLOCKS'):
                kwargs['missed_blocks'] = int(config['NODE']['MISSED_BLOCKS'])

            if config['SERVICE'].get('SLEEP_TIME_MS'):
                kwargs['sleep_time_ms'] = int(config['SERVICE']['SLEEP_TIME_MS'])

        else:
            for argv in sys.argv:
                kv = argv.split('=')
                if kv[0][:2] == '--':
                    k = kv[0].replace('--', '').replace('-', '_')
                    v = kv[1]
                    kwargs[k] = v

        # Create guard object and start tracking
        guard = Guard(**kwargs)
        guard.track()
    except Exception as e:
        logger.error('{}: {}'.format(e.__class__.__name__, e.__str__()))
        sys.exit(1)
