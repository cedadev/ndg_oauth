'''
Created on 17 Nov 2011

@author: rwilkinson
'''

class OauthException(Exception):
    def __init__(self, error, error_description):
        self.error = error
        self.error_description = error_description

    def __str__(self):
        return("%s: %s" % (self.error, self.error_description))
