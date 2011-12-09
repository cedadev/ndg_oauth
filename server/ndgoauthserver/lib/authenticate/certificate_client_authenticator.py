'''
Created on 8 Dec 2011

@author: rwilkinson
'''
from ndgoauthserver.lib.authenticate.client_authenticator_interface import ClientAuthenticatorInterface
from ndgoauthserver.lib.oauth.oauth_exception import OauthException
from ndgoauthserver.lib.register.client import ClientRegister

class CertificateClientAuthenticator(ClientAuthenticatorInterface):
    CERT_DN_ENVIRON_KEY = 'SSL_CLIENT_S_DN'
    """
    Client authenticator implementation that checks for a SSL certificate DN
    in the environ and compares this with that registered for the client.
    SSL certificate authentication must be configured, e.g., in an Apache server
    hosting the application.
    """
    def authenticate(self, request):
        dn = request.environ.get(self.CERT_DN_ENVIRON_KEY)
        if not dn:
            raise OauthException('invalid_client', 'No certificate DN found.')

        for client_authorization in ClientRegister.register.itervalues():
            if client_authorization.authentication_data == dn:
                return client_authorization.client_id
        raise OauthException('invalid_client', ('Certificate DN does not match that for any registered client: %s' % dn))
