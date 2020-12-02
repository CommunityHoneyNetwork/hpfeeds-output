import json
import logging
import requests
from datetime import datetime
from logging import StreamHandler
from IPy import IP

logger = logging.getLogger('__main__')

class CIFv3Handler(StreamHandler):

    def __init__(self, host, token, tlp, confidence, tags, provider, group, ssl, rcache, ignore_cidr, include_hp_tags=False):
        StreamHandler.__init__(self)
        self.tlp = tlp
        self.confidence = confidence
        self.tags = tags
        self.provider = provider
        self.group = group
        self.include_hp_tags = include_hp_tags
        self.cache = rcache
        self.ignore_cidr_list = ignore_cidr
        self.url = host + "/indicators"

        logging.debug('Initializing Client instance with: {0}, {1}, {2}'.format(token, host, ssl))
        self.session = requests.Session()
        self.session.headers.update({'Authorization': 'Token token=' + token})

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
        logger.debug(record)
        logger.debug(type(record.msg))

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

        app = msg['app']
        msg_tags = []
        if self.include_hp_tags and msg['tags']:
            msg_tags = msg['tags']

        data = {"indicator": indicator,
                "tlp": self.tlp,
                "confidence": self.confidence,
                "tags": self.tags + [app] + msg_tags,
                "provider": self.provider,
                "group": self.group,
                "lasttime": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')}
        logger.debug('Submitting indicator: {0}'.format(data))

        try:
            self.session.post(self.url, data=json.dumps(data))
            logger.info('Indicator submitted: {}'.format(indicator))
        except Exception as e:
            logger.error('Error submitting indicator: {0}'.format(repr(e)))

        return
