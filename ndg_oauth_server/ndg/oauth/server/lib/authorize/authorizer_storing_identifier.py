"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging
import uuid

from ndg.oauth.server.lib.authorize.authorizer_interface import \
                                                            AuthorizerInterface
from ndg.oauth.server.lib.register.authorization_grant import AuthorizationGrant

log = logging.getLogger(__name__)

class AuthorizerStoringIdentifier(AuthorizerInterface):
    """
    Authorizer interface that stores the user identifier as additional grant
    data so that it can be used in access token generation.
    """
    def __init__(self, lifetime, **kw):
        """
        @type lifetime: int
        @param lifetime: lifetimes of generated tokens in seconds

        @type kw:dict
        @param kw: additional keywords
            user_identifier_env_key: key for user identifier value in environ
            user_identifier_grant_data_key: key in additional grant data for
                user identifier value
        """
        self.lifetime = lifetime
        self.user_identifier_grant_data_key = kw.get(
                                            'user_identifier_grant_data_key')

    def generate_authorization_grant(self, auth_request, user_identifier):
        """Generates an authorization grant.
        @type auth_request: ndg.oauth.server.lib.oauth.authorize.AuthorizeRequest
        @param auth_request: authorization request

        @type user_identifier: string
        @param user_identifier: identifier for user granting the request

        @rtype: tuple (
            ndg.oauth.server.lib.register.authorization_grant.AuthorizationGrant
            str
        )
        @return: tuple (
            authorization grant
            authorization code
        )
        """
        code = uuid.uuid4().hex
        additional_data = {self.user_identifier_grant_data_key: user_identifier}
        grant = AuthorizationGrant(code, auth_request, self.lifetime,
                                   additional_data=additional_data)
        
        return grant, code
