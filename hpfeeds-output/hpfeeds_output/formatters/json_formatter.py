import datetime
import logging
import json
import time

logger = logging.getLogger('hpfeeds-output')

class JSONFormatter(logging.Formatter):
    def format(self, record):

        msg = json.loads(record.msg)
        outmsg = {}
        logger.debug('Formatting message for JSON: {}'.format(msg))

        t = datetime.datetime.isoformat(datetime.datetime.utcnow())
        if time.tzname[0] == 'UTC':
            t += 'Z'
        msg['timestamp'] = t
        # create a new object with timestamp first so it's output first
        # This works on Python 3.6 and later as dictionaries keys are ordered by creation
        outmsg['timestamp'] = msg.pop('timestamp')
        for item in msg:
            if isinstance(msg[item], bytes):
                outmsg[item] = msg[item].decode('utf8')
            else:
                outmsg[item] = msg[item]

        return json.dumps(outmsg)
