'''
Created on 17 Nov 2011

@author: rwilkinson
'''
import uuid

from ndgoauthserver.lib.register.access_token import AccessToken

class BearerTokenGenerator(object):
    def __init__(self, lifetime, token_type, **kw):
        self.lifetime = lifetime
        self.token_type = token_type

    def get_access_token(self, token_request, grant, request):
        token_id = uuid.uuid4().hex
        return AccessToken(token_id, token_request, grant, self.token_type, self.lifetime)
