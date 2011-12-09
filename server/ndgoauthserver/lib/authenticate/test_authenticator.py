'''
Created on 16 Nov 2011

@author: rwilkinson
'''
from ndgoauthserver.lib.authenticate.authenticator_interface import AuthenticatorInterface

class TestAuthenticator(AuthenticatorInterface):
    def authenticate(self, params):
        if params.get('identifier', None) and params.get('password', '') == 'test':
            return True
        return None
