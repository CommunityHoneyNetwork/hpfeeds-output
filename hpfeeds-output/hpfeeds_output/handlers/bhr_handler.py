import json
import logging
from logging import StreamHandler
from IPy import IP

logger = logging.getLogger('hpfeeds-output')

class BHRHandler(StreamHandler):

    def __init__(self, bhr, source, duration, rcache, ignore_cidr):
        StreamHandler.__init__(self)
        self.source = source
        self.duration = duration
        self.cache = rcache
        self.ignore_cidr_list = ignore_cidr
        self.bhr = bhr

    def is_ignore_addr(self,ip):
        try:
            checkip = IP(ip)
            for c in self.ignore_cidr_list:
                if checkip in c:
                    return True
            return False
        except ValueError as e:
            logger.warning('Received invalid IP via hpfeeds: {}'.format(e))
            return True

    def emit(self, record):

        msg = json.loads(record.msg)

        indicator = msg['src_ip']
        signature = msg['signature']
        honeypot = msg['app']

        if signature != 'Connection to Honeypot':
            logger.debug('Non-initial connection signature: {} ; skipping!'.format(signature))
            return
        elif self.cache.iscached(indicator):
            logger.debug('Indicator {} is cached; skipping'.format(indicator))
            return
        elif self.is_ignore_addr(indicator):
            logger.debug('Indicator {} is on ignore list; skipping'.format(indicator))
            return

        logger.debug('Submitting BHR block: {}'.format(indicator))
        try:
            r = self.bhr.block(cidr=indicator, source=self.source, why=honeypot, duration=self.duration)
            logger.info('BHR block submitted for indicator: {}'.format(indicator))
            logger.debug('BHR submission result: {}'.format(r))
            self.cache.setcache(indicator)
        except Exception as e:
            logger.error('Error submitting BHR block: {0}'.format(repr(e)))
