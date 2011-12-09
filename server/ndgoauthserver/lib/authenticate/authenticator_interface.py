'''
Created on 16 Nov 2011

@author: rwilkinson
'''
from abc import ABCMeta, abstractmethod
class AuthenticatorInterface(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def authenticate(self, params):
        return None
