'''
Created on 8 Dec 2011

@author: rwilkinson
'''
from beaker.cache import CacheManager
from beaker.util import parse_cache_config_options

class RegisterBase(object):
    def __init__(self, name, config):
        cacheMgr = CacheManager(**parse_cache_config_options(config))
        self.cache = cacheMgr.get_cache(name)

    def set_value(self, key, value):
        self.cache.put(key, value)

    def get_value(self, key):
        return self.cache.get(key)

    def has_key(self, key):
        return self.cache.has_key(key)

    def parse_config(self, prefix, name, config):
        base = ("%s.%s." % (prefix, name))
        cache_opts = {
            'cache.expire': config.get(base + 'expire', None),
            'cache.type': config.get(base + 'type', 'file'),
            'cache.data_dir': config.get(base + 'data_dir', '/tmp/ndgoauth/cache/' + name),
            'cache.lock_dir': config.get(base + 'lock_dir', None)
            }
        return cache_opts

class TestRegister(RegisterBase):
    def add(self, k, v):
        self.set_value(k, v)

    def get(self, k):
        return self.get_value(k)

if __name__ == '__main__':
    t = TestRegister(
        'testcache',
        {
            'cache.type': 'dbm',
            'cache.data_dir': '/tmp/cache/data',
            'cache.lock_dir': '/tmp/cache/lock'
        })
    t.add('a', 'AAA')
    t.add('b', 'BBB')
    print t.get('a')
    print t.cache.has_key('a')
    print t.cache.has_key('c')
    t.add('a', 'ABC')
    print t.get('a')
    t.cache.put('a', 'ABC')
    print t.get('a')
    t.cache.put('d', 'DDD')
    print t.get('d')
#    print t.get('e')
    print t.has_key('a')
    print t.has_key('f')
