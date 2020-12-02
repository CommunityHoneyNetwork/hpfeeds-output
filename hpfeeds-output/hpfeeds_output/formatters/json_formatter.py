import json
import datetime
import time

#TODO: Convert to a logging.Formatter subclass

def format(message):
    msg = dict(message)
    log = dict()
    t = datetime.datetime.isoformat(datetime.datetime.utcnow())
    if time.tzname[0] == 'UTC':
        t += 'Z'
    msg['timestamp'] = t
    # create a new object with timestamp first so it's output first
    # This works on Python 3.6 and later as dictionaries keys are ordered by creation
    log['timestamp'] = msg.pop('timestamp')
    for item in msg:
        if isinstance(msg[item], bytes):
            log[item] = msg[item].decode('utf8')
        else:
            log[item] = msg[item]

    return json.dumps(log)
