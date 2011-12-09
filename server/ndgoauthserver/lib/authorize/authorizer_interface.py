'''
Created on 17 Nov 2011

@author: rwilkinson
'''
from abc import ABCMeta, abstractmethod
class AuthorizerInterface(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, lifetime, **kw):
        pass

    @abstractmethod
    def generate_authorization_grant(self, auth_request, request):
        return None
