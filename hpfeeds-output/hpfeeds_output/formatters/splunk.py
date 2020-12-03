#!/usr/bin/python

import datetime
import logging
import json
import time

logger = logging.getLogger('__main__')

class SplunkFormatter(logging.Formatter):

    def format(self, record):

        msg = json.loads(record.msg)
        outmsg = {}
        logger.debug('Formatting message for Splunk: {}'.format(msg))

        timestamp = datetime.datetime.isoformat(datetime.datetime.utcnow())
        if time.tzname[0] == 'UTC':
            timestamp += 'Z'
        outmsg['timestamp'] = timestamp

        for k, v in dict(msg).items():
            if isinstance(v, bytes):
                outmsg[k] = v.decode('utf8')
            else:
                outmsg[k] = v

        if 'src_ip' in outmsg:
            outmsg['src'] = outmsg['src_ip']
            del outmsg['src_ip']

        if 'dest_ip' in outmsg:
            outmsg['dest'] = outmsg['dest_ip']
            del outmsg['dest_ip']

        d = [u'{}="{}"'.format(name, str(value).replace('"', '\\"')) for name, value in outmsg.items() if value]
        msg = ', '.join(d)

        return msg
