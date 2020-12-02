import json
import requests
import logging
from logging import StreamHandler

#TODO: Add support for IGNORE_CIDR
#TODO: Add support for Redis caching

class BHRHandler(StreamHandler):

    def __init__(self, host, token, source, reason, duration, ssl):
        StreamHandler.__init__(self)
        self.url = host + "/api/block"
        self.reason = reason
        self.source = source
        self.duration = duration

        self.session = requests.Session()
        self.session.headers.update({'Authorization': 'Token ' + token})

    def emit(self, record):
        logging.debug(record)
        logging.debug(type(record.msg))

        msg = json.loads(record.msg)

        indicator = msg['src_ip']

        data = {"cidr": indicator,
                "source": self.source,
                "why": self.reason,
                "duration": self.duration}
        logging.debug('Submitting BHR block: {0}'.format(data))
        try:
            self.session.post(self.url, data=json.dumps(data))
            logging.debug('BHR block submitted')
        except Exception as e:
            logging.error('Error submitting BHR block: {0}'.format(repr(e)))
