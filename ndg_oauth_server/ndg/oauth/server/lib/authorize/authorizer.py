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

from ndg.oauth.server.lib.authorize.authorizer_interface import AuthorizerInterface
from ndg.oauth.server.lib.register.authorization_grant import AuthorizationGrant

log = logging.getLogger(__name__)

class Authorizer(AuthorizerInterface):
    """
    Authorizer implementation that uses random UUIDs as authorization grant
    codes.
    """
    def __init__(self, lifetime):
        self.lifetime = lifetime

    def generate_authorization_grant(self, auth_request, request):
        """Generates an authorization grant.
        @type auth_request: ndg.oauth.server.lib.oauth.authorize.AuthorizeRequest
        @param auth_request: authorization request

        @type request: webob.Request
        @param request: HTTP request object

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
        grant = AuthorizationGrant(code, auth_request, self.lifetime)
        return (grant, code)
