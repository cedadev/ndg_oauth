'''
Created on 8 Dec 2011

@author: rwilkinson
'''
from ndgoauthserver.lib.authenticate.client_authenticator_interface import ClientAuthenticatorInterface

class NoopClientAuthenticator(ClientAuthenticatorInterface):
    """
    Client authenticator implementation that 
    """
    def authenticate(self, request):
        return None
