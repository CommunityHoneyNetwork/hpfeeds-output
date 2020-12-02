import json
import requests
import logging
from logging import StreamHandler
from IPy import IP

logger = logging.getLogger('__main__')

class BHRHandler(StreamHandler):

    def __init__(self, host, token, source, reason, duration, rcache, ignore_cidr, ssl):
        StreamHandler.__init__(self)
        self.url = host + "/api/block"
        self.reason = reason
        self.source = source
        self.duration = duration
        self.cache = rcache
        self.ignore_cidr_list = ignore_cidr
        self.ssl = ssl
        self.session = requests.Session()
        self.session.headers.update({'Authorization': 'Token ' + token})

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
        logging.debug(record)
        logging.debug(type(record.msg))

        msg = json.loads(record.msg)

        indicator = msg['src_ip']
        signature = msg['signature']

        if signature != 'Connection to Honeypot':
            logger.debug('Non-initial connection signature: {} ; skipping!'.format(signature))
            return
        elif self.cache.iscached(indicator):
            logger.debug('Indicator {} is cached; skipping'.format(indicator))
            return
        elif self.is_ignore_addr(indicator):
            logger.debug('Indicator {} is on ignore list; skipping'.format(indicator))

        data = {"cidr": indicator,
                "source": self.source,
                "why": self.reason,
                "duration": self.duration}
        logging.debug('Submitting BHR block: {0}'.format(data))
        try:
            self.session.post(self.url, data=json.dumps(data), verify=self.ssl)
            logging.info('BHR block submitted for indicator: {}'.format(indicator))
        except Exception as e:
            logging.error('Error submitting BHR block: {0}'.format(repr(e)))
