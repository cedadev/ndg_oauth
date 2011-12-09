'''
Created on 2 Dec 2011

@author: rwilkinson
'''
import logging
import uuid

from ndgoauthserver.lib.authorize.authorizer_interface import AuthorizerInterface
from ndgoauthserver.lib.oauth.authorize import AuthorizeResponse
from ndgoauthserver.lib.oauth.oauth_exception import OauthException
from ndgoauthserver.lib.register.authorization_grant import AuthorizationGrant, AuthorizationGrantRegister

log = logging.getLogger(__name__)

class AuthorizerStoringIdentifier(AuthorizerInterface):
    def __init__(self, lifetime, **kw):
        self.lifetime = lifetime
        self.user_identifier_env_key = kw.get('user_identifier_env_key')
        self.user_identifier_grant_data_key = kw.get('user_identifier_grant_data_key')

    def generate_authorization_grant(self, auth_request, request):
        user_identifier = request.environ.get(self.user_identifier_env_key)
        if not user_identifier:
            log.error('Could not find user identifier key "%s" in environ', self.user_identifier_env_key)
            raise OauthException('server_error', 'Authorization grant could not be created')

        code = uuid.uuid4().hex
        grant = AuthorizationGrant(code, auth_request, self.lifetime,
                                   additional_data={'user_identifier': user_identifier})
        return (grant, code)
