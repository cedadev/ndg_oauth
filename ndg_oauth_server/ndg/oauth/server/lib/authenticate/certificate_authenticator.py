"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from ndg.oauth.server.lib.authenticate.authenticator_interface import AuthenticatorInterface
from ndg.oauth.server.lib.oauth.oauth_exception import OauthException


class CertificateAuthenticator(AuthenticatorInterface):
    CERT_DN_ENVIRON_KEY = 'SSL_CLIENT_S_DN'
    """
    Client authenticator implementation that checks for a SSL certificate DN
    in the environ and compares this with that registered for the client/resource/....
    SSL certificate authentication must be configured, e.g., in an Apache server
    hosting the application.
    """

    def __init__(self, typ, register):
        AuthenticatorInterface.__init__(self, typ)
        self._register = register

    def authenticate(self, request):
        """
        Checks for an SSL certificate distinguished name in the environ and if
        found, returns it.
        @type request: webob.Request
        @param request: HTTP request object

        @rtype: str
        @return: ID of authenticated client/resource, or None if authentication
        is not to be performed.
        
        Raise OauthException if authentication fails.
        """
        dn = request.environ.get(self.CERT_DN_ENVIRON_KEY)
        if not dn:
            raise OauthException('invalid_%s' % self.typ, 'No certificate DN found.')

        for authorization in self._register.register.itervalues():
            if authorization.authentication_data == dn:
                return authorization.id

        raise OauthException('invalid_%s' % self.typ,
			     'Certificate DN does not match that for any registered %s: %s' % (self.typ, dn))

