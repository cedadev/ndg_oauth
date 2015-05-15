"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "W van Engen"
__date__ = "01/11/12"
__copyright__ = "(C) 2011 FOM / Nikhef"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "wvengen+oauth2@nikhef.nl"
__revision__ = "$Id$"

from base64 import b64decode

from ndg.oauth.server.lib.authenticate.authenticator_interface import \
                                                        AuthenticatorInterface
from ndg.oauth.server.lib.oauth.oauth_exception import OauthException


class PasswordAuthenticator(AuthenticatorInterface):
    """
    Authenticator implementation that checks for a client/resource id+secret
    combination, either in the HTTP Authorization header, or in the request
    parameters, according to the OAuth 2 RFC, section 2.3.1

    @todo implement protection against brute force attacks (MUST)
    """

    def __init__(self, typ, register):
        super(PasswordAuthenticator, self).__init__(typ)
        self._register = register

    def authenticate(self, params, headers):
        """
        Checks for id/secret pair in Authorization header, or else
        POSTed request parameters.
        :type client_id: string
        :param client_id: client identifier

        :rtype: str
        :return: id of authenticated client/resource
        
        :raise OauthException: if authentication fails.
        """
        # Normalise headers input ready for matching
        headers_ = [(key.lower(), val) for key, val in headers]
        
        authz_header = headers_.get('authorization', '')
        if authz_header.startswith('Basic'):
            client_id, client_secret = b64decode(authz_header[6:]).split(':', 1)

        elif 'client_id' in params and 'client_secret' in params:
            client_id = params['client_id']
            client_secret = params['client_secret']
            
        if not client_id or not client_secret:
            raise OauthException('invalid_%s' % self.typ,
                 'No %s password authentication supplied' % self.typ)
            
        for authorization in self._register.register.itervalues():
            if (authorization.id == client_id and 
                authorization.secret == client_secret):
                return authorization.id

        raise OauthException('invalid_%s' % self.typ,
			                 '%s access denied: %s' % (client_id, self.typ))

