'''
Created on 8 Dec 2011

@author: rwilkinson
'''
from abc import ABCMeta, abstractmethod
class ClientAuthenticatorInterface(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def authenticate(self, request):
        """
        Returning None implies client id is not to be checked against grant.
        Implementations should raise OauthException if authentication fails.
        """
        return None
