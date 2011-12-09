'''
Created on 17 Nov 2011

@author: rwilkinson
'''
import logging
import uuid

from ndgoauthserver.lib.authorize.authorizer_interface import AuthorizerInterface
from ndgoauthserver.lib.oauth.authorize import AuthorizeResponse
from ndgoauthserver.lib.oauth.oauth_exception import OauthException
from ndgoauthserver.lib.register.authorization_grant import AuthorizationGrant, AuthorizationGrantRegister

log = logging.getLogger(__name__)

class Authorizer(AuthorizerInterface):
    def __init__(self, lifetime):
        self.lifetime = lifetime

    def generate_authorization_grant(self, auth_request, request):
        code = uuid.uuid4().hex
        grant = AuthorizationGrant(code, auth_request, self.lifetime)
        return (grant, code)
