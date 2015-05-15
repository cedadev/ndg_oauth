"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"


class AuthorizeRequest(object):
    """
    OAuth 2.0 authorization request object
    """
    def __init__(self, response_type, client_id, redirect_uri, scope, state):
        """
        :param response_type: REQUIRED.  Value MUST be set to "code".
        :param client_id: REQUIRED.  The client identifier as described in 
        Section 2.2.
        :param redirect_uri: OPTIONAL, as described in Section 3.1.2.
        :param scope: OPTIONAL.  The scope of the access request as described by
        Section 3.3.
        :param state: RECOMMENDED.  An opaque value used by the client to 
        maintain state between the request and callback.  The authorization
        server includes this value when redirecting the user-agent back
        to the client.  The parameter SHOULD be used for preventing
        cross-site request forgery as described in Section 10.12.
        """
        self.response_type = response_type
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.state = state


class AuthorizeResponse(object):
    """
    OAuth 2.0 authorization response object
    """
    def __init__(self, code, state):
        """
        :param code: REQUIRED.  The authorization code generated by the
              authorization server.  The authorization code MUST expire
              shortly after it is issued to mitigate the risk of leaks.  A
              maximum authorization code lifetime of 10 minutes is
              RECOMMENDED.  The client MUST NOT use the authorization code
              more than once.  If an authorization code is used more than
              once, the authorization server MUST deny the request and SHOULD
              attempt to revoke all tokens previously issued based on that
              authorization code.  The authorization code is bound to the
              client identifier and redirection URI.
        :param state: REQUIRED if the "state" parameter was present in the 
        client authorization request.  The exact value received from the client.
        """
        self.code = code
        self.state = state
