'''
Created on 17 Nov 2011

@author: rwilkinson
'''
from abc import ABCMeta, abstractmethod
class AccessTokenInterface(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, lifetime, token_type, **kw):
        pass

    @abstractmethod
    def get_access_token(self, token_request, grant, request):
        return None
