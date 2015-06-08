"""OAuth 2.0 WSGI server middleware - utility for creating access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from datetime import datetime

from ndg.oauth.server.lib.oauth.oauth_exception import OauthException
from ndg.oauth.server.lib.oauth.access_token import (AccessTokenRequest, 
                                            AuthzCodeGrantAccessTokenResponse,
                                            ImplicitGrantAccessTokenResponse) 
from ndg.oauth.server.lib.oauth.authorize import AuthorizeRequest
                                                  
AUTHORIZATION_CODE_GRANT_TYPE = 'authorization_code'
MIN_N_ARGS = 3
        
    
def _make_access_token_from_authz_code_grant(token_request, client_id, 
                                             access_token_register, 
                                             access_token_generator,
                                             authorization_grant_register):
    """Makes an access token based on a token request and using a given access
    token generator.
    Returns
      access token response or None if an error occurs that is not one of those
          that can be reported in an error response, i.e., internal server error
    """
    # Check token_request valid and matches a registered authorization grant.
    if token_request.grant_type != AUTHORIZATION_CODE_GRANT_TYPE:
        raise OauthException('invalid_request', 'Invalid grant_type')

    try:
        grant = authorization_grant_register.get_value(token_request.code)
        
    except KeyError:
        raise OauthException('invalid_grant', 'Invalid authorization code')

    if (grant.redirect_uri is not None and 
        token_request.redirect_uri != grant.redirect_uri):
        raise OauthException('invalid_grant', 'Invalid redirect URI')

    if grant.granted:
        # Invalidate the associated token.
        if grant.token:
            grant.token.valid = False
        raise OauthException('invalid_grant', 
                             'Token already granted for authorization grant')

    # Check whether expired.
    if grant.expires <= datetime.utcnow():
        raise OauthException('invalid_grant', 'Authorization grant expired')

    # Check that the grant is issued to the requesting client.
    # This requires that the client has authenticated itself so that the
    # client identity is known.
    # client_id is None if client authentication is not configured - this
    # signals that authentication is disabled for testing.
    if client_id and (grant.client_id != client_id):
        raise OauthException('invalid_grant', 
                             'Token granted for different client')

    token = access_token_generator.get_access_token(grant)
    if not token:
        return None

    grant.granted = True
    grant.token = token

    response = AuthzCodeGrantAccessTokenResponse(token.token_id, 
                                                 token.token_type,
                                                 token.lifetime, 
                                                 refresh_token=None)
    if access_token_register.add_token(token):
        return response
    else:
        return None
    

def _make_access_token_from_implicit_grant(authz_request, access_token_register, 
                                           access_token_generator):
    """
    Makes an access token based on a token request and using a given access
    token generator.
    Returns
      access token response or None if an error occurs that is not one of those
          that can be reported in an error response, i.e., internal server error
    """
    token = access_token_generator.get_access_token(authz_request)
    if not token:
        return None

    response = ImplicitGrantAccessTokenResponse(token.token_id, 
                                                token.token_type,
                                                token.lifetime,
                                                authz_request.state,
                                                scope=token.scope)
    if access_token_register.add_token(token):
        return response
    else:
        return None


def make_access_token(*args):
    '''Make an access token based on an access token request (Authorisation
    Code flow) or an authorisation request (Implicit Grant flow)
    '''
    if len(args) < MIN_N_ARGS:
        raise TypeError('make_access_token takes at least %d, (%d given)' %
                        (MIN_N_ARGS, len(args)))
        
    if isinstance(args[0], AccessTokenRequest):
        return _make_access_token_from_authz_code_grant(*args)
        
    elif isinstance(args[0], AuthorizeRequest):
        return _make_access_token_from_implicit_grant(*args)
        
    else:
        raise TypeError('Expecting %r or %r type for make_access_token first ' 
                        'argument.' % (AccessTokenRequest, AuthorizeRequest))
