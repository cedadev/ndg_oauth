"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import uuid

from ndg.oauth.server.lib.access_token.access_token_interface import AccessTokenInterface
from ndg.oauth.server.lib.register.access_token import AccessToken

class BearerTokenGenerator(AccessTokenInterface):
    def __init__(self, lifetime, token_type, **kw):
        """
        @type lifetime: int
        @param lifetime: lifetimes of generated tokens in seconds

        @type token_type: str
        @param token_type: token type name

        @type kw:dict
        @param kw: additional keywords
        """
        self.lifetime = lifetime
        self.token_type = token_type

    def get_access_token(self, token_request, grant, request):
        """
        Gets an access token with an ID that is a random UUID used as a bearer
        token.
        @type token_request: ndg.oauth.server.lib.access_token.AccessTokenRequest
        @param token_request: access token request

        @type grant: ndg.oauth.server.lib.register.authorization_grant.AuthorizationGrant
        @param grant: authorization grant

        @type request: webob.Request
        @param request: HTTP request object

        @rtype: ndg.oauth.server.lib.register.access_token.AccessToken
        @return: access token or None if an error occurs
        """
        token_id = uuid.uuid4().hex
        return AccessToken(token_id, token_request, grant, self.token_type, self.lifetime)
