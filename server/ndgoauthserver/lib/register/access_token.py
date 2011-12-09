'''
Created on 17 Nov 2011

@author: rwilkinson
'''
from datetime import datetime, timedelta
import logging

from ndgoauthserver.lib.register.register_base import RegisterBase

log = logging.getLogger(__name__)

class AccessToken(object):
    def __init__(self, token_id, request, grant, token_type, lifetime):
        self.token_id = token_id
        self.token_type = token_type
        self.grant = grant
        self.scope = grant.scope.split() if grant.scope else []
        self.timestamp = datetime.now()
        self.lifetime = lifetime
        self.expires = self.timestamp + timedelta(days=0, seconds=lifetime)
        self.valid = True

class AccessTokenRegister(RegisterBase):
    CACHE_NAME = 'accesstokenregister'

    def __init__(self, config, prefix='cache'):
        cache_opts = self.parse_config(prefix, self.CACHE_NAME, config)
        super(AccessTokenRegister, self).__init__('AccessTokenRegister', cache_opts)

    def add_token(self, token):
        if self.has_key(token.token_id):
            # Internal error
            log.error("Repeated attempt to add token of ID: %s", token.token_id)
            return False

        self.set_value(token.token_id, token)
        return True

    def get_token(self, token_id, scope):
        try:
            token = self.get_value(token_id)
        except KeyError:
            return (None, 'invalid_token')

        if not token.valid:
            log.debug("Request for invalid token of ID: %s", token_id)
            return (None, 'invalid_token')
        if token.expires <= datetime.utcnow():
            log.debug("Request for expired token of ID: %s", token_id)
            return (None, 'invalid_token')
        # Check scope
        if scope and (scope not in token.scope):
            log.debug("Request for token of ID: %s - token was not granted scope %s",
                      token_id, scope)
            return (None, 'invalid_token')
        return (token, None)
