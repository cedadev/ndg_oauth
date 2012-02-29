"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from beaker.cache import CacheManager
from beaker.util import parse_cache_config_options

class RegisterBase(object):
    """
    Base class for persistent registers. Entries are stored in a Beaker cache.
    """
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
