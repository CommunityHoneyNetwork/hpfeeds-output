import json
import logging
import requests
from datetime import datetime
from logging import StreamHandler


#TODO: Add support for IGNORE_CIDR
#TODO: Add support for Redis caching

class CIFv3Handler(StreamHandler):

    def __init__(self, host, token, tlp, confidence, tags, provider, group, ssl, include_hp_tags=False):
        StreamHandler.__init__(self)
        self.tlp = tlp
        self.confidence = confidence
        self.tags = tags
        self.provider = provider
        self.group = group
        self.include_hp_tags = include_hp_tags
        self.url = host + "/indicators"

        logging.debug('Initializing Client instance with: {0}, {1}, {2}'.format(token, host, ssl))
        self.session = requests.Session()
        self.session.headers.update({'Authorization': 'Token token=' + token})

    def emit(self, record):
        logging.debug(record)
        logging.debug(type(record.msg))

        msg = json.loads(record.msg)

        indicator = msg['src_ip']
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
        logging.debug('Submitting indicator: {0}'.format(data))
        try:
            self.session.post(self.url, data=json.dumps(data))
            logging.debug('Indicator submitted')
        except Exception as e:
            logging.error('Error submitting indicator: {0}'.format(repr(e)))

        return
