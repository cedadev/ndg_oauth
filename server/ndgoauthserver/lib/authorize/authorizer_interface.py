"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from abc import ABCMeta, abstractmethod
class AuthorizerInterface(object):
    """
    Interface for generation of authorization grants.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, lifetime, **kw):
        """
        @type lifetime: int
        @param lifetime: lifetimes of generated tokens in seconds

        @type kw:dict
        @param kw: additional keywords
        """
        pass

    @abstractmethod
    def generate_authorization_grant(self, auth_request, request):
        """Generates an authorization grant.
        @type auth_request: ndgoauthserver.lib.oauth.authorize.AuthorizeRequest
        @param auth_request: authorization request

        @type request: webob.Request
        @param request: HTTP request object

        @rtype: tuple (
            ndgoauthserver.lib.register.authorization_grant.AuthorizationGrant
            str
        )
        @return: tuple (
            authorization grant
            authorization code
        )
        """
        return None
