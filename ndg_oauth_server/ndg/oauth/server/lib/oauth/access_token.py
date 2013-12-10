"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from abc import ABCMeta, abstractmethod


class AccessTokenRequest(object):
    """
    OAuth 2.0 access token request object.
    """
    def __init__(self, grant_type, code, redirect_uri):
        """
        grant_type
              REQUIRED.  Value MUST be set to "authorization_code".
        code
              REQUIRED.  The authorization code received from the
              authorization server.
        redirect_uri
              REQUIRED, if the "redirect_uri" parameter was included in the
              authorization request as described in Section 4.1.1, and their
              values MUST be identical.
        """
        self.grant_type = grant_type
        self.code = code
        self.redirect_uri = redirect_uri



class AccessTokenResponseBase:
    """OAuth 2.0 access token response base class.
    """
    __metaclass__ = ABCMeta
    
    def __init__(self, access_token, token_type, expires_in):
        """Set access token, type, expiry.
        """
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in

    @abstractmethod
    def get_as_dict(self):
        content_dict = {'access_token': self.access_token,
                        'token_type': self.token_type,
                        'expires_in': self.expires_in}

        return content_dict
    
    
class AuthzCodeGrantAccessTokenResponse(AccessTokenResponseBase):
    """OAuth 2.0 access token response for Authorisation Grant code flow.
    """
    def __init__(self, *arg, **kwarg):
        """Set access token, type, expiry and optionally, a refresh token.
        Refresh token should not be set for the Implicit Grant flow
        """
        self.refresh_token = kwarg.pop('refresh_token', None)
        
        super(AuthzCodeGrantAccessTokenResponse, self).__init__(*arg, **kwarg)

    def get_as_dict(self):
        content_dict = super(AuthzCodeGrantAccessTokenResponse, 
                             self).get_as_dict()
        
        if self.refresh_token:
            content_dict['refresh_token'] = self.refresh_token
            
        return content_dict


class ImplicitGrantAccessTokenResponse(AccessTokenResponseBase):
    """OAuth 2.0 access token response for Implicit Grant code flow.
    """
    def __init__(self, access_token, token_type, expires_in, state, scope=None):
        """Set access token, type, expiry, state and optionally, scope.
        """
        super(ImplicitGrantAccessTokenResponse, self).__init__(access_token, 
                                                               token_type, 
                                                               expires_in)
        self.state = state
        self.scope = scope
        
    def get_as_dict(self):
        content_dict = super(ImplicitGrantAccessTokenResponse, 
                             self).get_as_dict()
                  
        content_dict['state'] = self.state
        if self.scope:
            content_dict['scope'] = self.scope
            
        return content_dict