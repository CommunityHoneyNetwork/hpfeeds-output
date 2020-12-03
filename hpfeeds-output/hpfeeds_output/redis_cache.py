import redis
import logging

logger = logging.getLogger('hpfeeds-output')

class RedisCache(object):
    """
    Implement a simple cache using Redis.
    """

    def __init__(self, host='redis', port=6379, db=2, expire=300):
        # This code will have implication of no more than one instance of BHR
        # In case of multiples, false cache hits will result due to db selected
        self.r = redis.Redis(host=host, port=port, db=db)
        self.expire_t = expire

    def iscached(self,ip):
        a = self.r.get(ip)
        logger.debug('Checked for {} in cache and received: {}'.format(ip,a))
        if a:
            return True
        else:
            return False

    def setcache(self,ip):
        a = self.r.set(name=ip, value=0, ex=self.expire_t)
        logger.debug('Sent {} to cache and received: {}'.format(ip,a))
