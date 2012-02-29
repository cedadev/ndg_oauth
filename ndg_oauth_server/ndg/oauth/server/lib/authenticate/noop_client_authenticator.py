"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from ndg.oauth.server.lib.authenticate.client_authenticator_interface import ClientAuthenticatorInterface

class NoopClientAuthenticator(ClientAuthenticatorInterface):
    """
    Client authenticator implementation that returns None implying that the
    client should not be authenticated.
    """
    def authenticate(self, request):
        """
        Authenticator that always returns None
        Returning None implies client id is not to be checked against grant.

        @type request: webob.Request
        @param request: HTTP request object

        @rtype: str
        @return: None
        """
        return None
