"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from ndg.oauth.server.lib.access_token.access_token_interface import \
                                                        AccessTokenInterface
from ndg.oauth.server.lib.register.access_token import AccessToken


class BearerTokenGenerator(AccessTokenInterface):
    '''Class to generate bearer token'''
    
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

    def get_access_token(self, _arg):
        """
        Gets an access token with an ID that is a random UUID used as a bearer
        token.
        @type request: ndg.oauth.server.lib.access_token.AccessTokenRequest /
        ndg.oauth.server.lib.oauth.authorize.AuthorizeRequest
        @param request: access token request

        @type _arg: 
        ndg.oauth.server.lib.register.authorization_grant.AuthorizationGrant /
        ndg.oauth.server.lib.oauth.authorize.AuthorizeRequest
        @param _arg: authorization grant (authorisation code flow) or 
        authorisation request (implicit flow)

        @rtype: ndg.oauth.server.lib.register.access_token.AccessToken
        @return: access token or None if an error occurs
        """
        return AccessToken.create(self.token_type, _arg, self.lifetime)

