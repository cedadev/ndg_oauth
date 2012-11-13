"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "W van Engen"
__date__ = "01/11/12"
__copyright__ = "(C) 2011 FOM / Nikhef"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "wvengen+oauth2@nikhef.nl"
__revision__ = "$Id$"

from base64 import b64decode

from ndg.oauth.server.lib.authenticate.client_authenticator_interface import ClientAuthenticatorInterface
from ndg.oauth.server.lib.oauth.oauth_exception import OauthException
from ndg.oauth.server.lib.register.client import ClientRegister

class PasswordClientAuthenticator(ClientAuthenticatorInterface):
    """
    Client authenticator implementation that checks for a client id/secret
    combination, either in the HTTP Authorization header, or in the request
    parameters, according to the OAuth 2 RFC, section 2.3.1

    @todo implement protection against brute force attacks (MUST)
    """
    def authenticate(self, request):
        """
        Checks for client_id/client_secret pair in Authorization header, or else
        POSTed request parameters.
        @type request: webob.Request
        @param request: HTTP request object

        @rtype: str
        @return: id of authenticated client
        
        Raise OauthException if authentication fails.
        """
        cid = secret = None
        if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Basic'):
            cid, secret = b64decode(request.headers['Authorization'][6:]).split(':',1)
        elif 'client_id' in request.POST and 'client_secret' in request.POST:
            cid = request.POST['client_id']
            secret = request.POST['client_secret']

        if not cid or not secret:
            raise OauthException('invalid_client', 'No client password authentication supplied')

        for client_authorization in ClientRegister.register.itervalues():
            if client_authorization.client_id == cid and client_authorization.client_secret == secret:
                return client_authorization.client_id
        raise OauthException('invalid_client', ('Client access denied: %s' % cid))
