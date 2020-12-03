import logging

logger = logging.getLogger('hpfeeds-output')

class RawJsonFormatter(logging.Formatter):

    def format(self, record):
        return record.msg

