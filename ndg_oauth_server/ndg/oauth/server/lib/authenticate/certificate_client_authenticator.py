"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from ndg.oauth.server.lib.authenticate.client_authenticator_interface import ClientAuthenticatorInterface
from ndg.oauth.server.lib.oauth.oauth_exception import OauthException
from ndg.oauth.server.lib.register.client import ClientRegister

class CertificateClientAuthenticator(ClientAuthenticatorInterface):
    CERT_DN_ENVIRON_KEY = 'SSL_CLIENT_S_DN'
    """
    Client authenticator implementation that checks for a SSL certificate DN
    in the environ and compares this with that registered for the client.
    SSL certificate authentication must be configured, e.g., in an Apache server
    hosting the application.
    """
    def authenticate(self, request):
        """
        Checks for an SSL certificate distinguished name in the environ and if
        found, returns it.
        @type request: webob.Request
        @param request: HTTP request object

        @rtype: str
        @return: ID of authenticated client, or None if authentication is not to
        be performed.
        
        Raise OauthException if authentication fails.
        """
        dn = request.environ.get(self.CERT_DN_ENVIRON_KEY)
        if not dn:
            raise OauthException('invalid_client', 'No certificate DN found.')

        for client_authorization in ClientRegister.register.itervalues():
            if client_authorization.authentication_data == dn:
                return client_authorization.client_id
        raise OauthException('invalid_client', ('Certificate DN does not match that for any registered client: %s' % dn))
