"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from abc import ABCMeta, abstractmethod

class AccessTokenInterface(object):
    """
    Interface for access token generators. Implementations will create a
    specific type of token.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, lifetime, token_type, **kw):
        """
        @type lifetime: int
        @param lifetime: lifetimes of generated tokens in seconds

        @type token_type: str
        @param token_type: token type name

        @type kw:dict
        @param kw: additional keywords
        """
        pass

    @abstractmethod
    def get_access_token(self, token_request, grant, request):
        """
        @type token_request: ndgoauthserver.lib.access_token.AccessTokenRequest
        @param token_request: access token request

        @type grant: ndgoauthserver.lib.register.authorization_grant.AuthorizationGrant
        @param grant: authorization grant

        @type request: webob.Request
        @param request: HTTP request object

        @rtype: ndgoauthserver.lib.register.access_token.AccessToken
        @return: access token
        """
        return None
