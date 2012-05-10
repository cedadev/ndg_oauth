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
import ndg.oauth.server.lib.register.scopeutil as scopeutil

log = logging.getLogger(__name__)

class AccessToken(object):
    """
    Access token as stored in the reqister
    """
    def __init__(self, token_id, request, grant, token_type, lifetime):
        self.token_id = token_id
        self.token_type = token_type
        self.grant = grant
        self.scope = scopeutil.scopeStringToList(grant.scope_str)
        self.timestamp = datetime.now()
        self.lifetime = lifetime
        self.expires = self.timestamp + timedelta(days=0, seconds=lifetime)
        self.valid = True

class AccessTokenRegister(RegisterBase):
    """
    Access token reqister that holds access tokens as determined by the cache
    options
    """
    CACHE_NAME = 'accesstokenregister'

    def __init__(self, config, prefix='cache'):
        cache_opts = self.parse_config(prefix, self.CACHE_NAME, config)
        super(AccessTokenRegister, self).__init__('AccessTokenRegister', cache_opts)

    def add_token(self, token):
        """Adds a token to the register.
        @type token: AccessToken
        @param token: access token
        """
        if self.has_key(token.token_id):
            # Internal error
            log.error("Repeated attempt to add token of ID: %s", token.token_id)
            return False

        self.set_value(token.token_id, token)
        log.debug("Added token of ID: %s", token.token_id)
        return True

    def get_token(self, token_id, scope):
        """Retrieves a registered token by token ID and required scope.
        @type token_id: basestring
        @param token_id: token ID
        @type scope: basestring
        @param scope: required scopes as space separated string
        """
        try:
            token = self.get_value(token_id)
        except KeyError:
            log.debug("Request for token of ID that is not registered: %s",
                      token_id)
            return (None, 'invalid_token')

        if not token.valid:
            log.debug("Request for invalid token of ID: %s", token_id)
            return (None, 'invalid_token')
        if token.expires <= datetime.utcnow():
            log.debug("Request for expired token of ID: %s", token_id)
            return (None, 'invalid_token')
        # Check scope
        if not scopeutil.isScopeGranted(token.scope,
                                        scopeutil.scopeStringToList(scope)):
            log.debug("Request for token of ID: %s - token was not granted scope %s",
                      token_id, scope)
            return (None, 'insufficient_scope')
        return (token, None)
