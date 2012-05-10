"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from datetime import datetime, timedelta
import logging

from ndg.oauth.server.lib.register.register_base import RegisterBase

log = logging.getLogger(__name__)

class AuthorizationGrant(object):
    """
    Authorization grant as stored in the reqister
    """
    def __init__(self, code, request, lifetime, scope=None, additional_data=None):
        self.code = code
        self.client_id = request.client_id
        self.redirect_uri = request.redirect_uri
        # Allow for authorized scope to be different from requested scope.
        self.scope_str = (scope if scope is not None else request.scope)
        self.additional_data = additional_data
        self.timestamp = datetime.utcnow()
        self.expires = self.timestamp + timedelta(days=0, seconds=lifetime)
        self.granted = False

class AuthorizationGrantRegister(RegisterBase):
    """
    Authorization grant reqister that holds access tokens as determined by the
    cache options
    """
    CACHE_NAME = 'authorizationgrantregister'

    def __init__(self, config, prefix='cache'):
        cache_opts = self.parse_config(prefix, self.CACHE_NAME, config)
        super(AuthorizationGrantRegister, self).__init__('AuthorizationGrantRegister', cache_opts)

    def add_grant(self, grant):
        if self.has_key(grant.code):
            # Internal error
            log.error("Repeated attempt to add grant of code: %s", grant.code)
            return False

        self.set_value(grant.code, grant)
        return True
