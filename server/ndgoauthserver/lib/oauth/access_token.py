'''
Created on 17 Nov 2011

@author: rwilkinson
'''
class AccessTokenRequest(object):
    """
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

class AccessTokenResponse(object):
    """
    """
    def __init__(self, access_token, token_type, expires_in, refresh_token=None):
        """
        """
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in
        self.refresh_token = refresh_token

    def get_as_dict(self):
        content_dict = {'access_token': self.access_token,
                        'token_type': self.token_type,
                        'expires_in': self.expires_in}
        if self.refresh_token:
            content_dict['refresh_token'] = self.refresh_token
        return content_dict
