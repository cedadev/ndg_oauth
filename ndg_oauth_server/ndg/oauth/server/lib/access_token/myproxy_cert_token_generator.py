"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import base64
import logging

from ndg.oauth.server.lib.access_token.access_token_interface import AccessTokenInterface
from ndg.oauth.server.lib.register.access_token import AccessToken

log = logging.getLogger(__name__)

class MyProxyCertTokenGenerator(AccessTokenInterface):
    """Access token generator that returns MyProxy certificates as tokens.
    """
    def __init__(self, lifetime, token_type, **kw):
        """
        @type lifetime: int
        @param lifetime: lifetimes of generated tokens in seconds

        @type token_type: str
        @param token_type: token type name

        @type kw:dict
        @param kw: additional keywords
        """
        self.lifetime = lifetime
        self.token_type = token_type
        self.certificate_request_parameter = kw.get('certificate_request_parameter')
        self.myproxy_client_env_key = kw.get('myproxy_client_env_key',
            'myproxy.server.wsgi.middleware.MyProxyClientMiddleware.myProxyClient')
        self.myproxy_global_password = kw.get('myproxy_global_password')
        self.user_identifier_grant_data_key = kw.get('user_identifier_grant_data_key')

    def get_access_token(self, token_request, grant, request):
        """
        Gets an access token using MyProxyClient.
        @type token_request: ndg.oauth.server.lib.access_token.AccessTokenRequest
        @param token_request: access token request

        @type grant: ndg.oauth.server.lib.register.authorization_grant.AuthorizationGrant
        @param grant: authorization grant

        @type request: webob.Request
        @param request: HTTP request object

        @rtype: ndg.oauth.server.lib.register.access_token.AccessToken
        @return: access token or None if an error occurs
        """
        myproxyclient = request.environ.get(self.myproxy_client_env_key)
        if myproxyclient is None:
            log.error('MyProxy client not found in environ')
            return None

        cert_req_enc = request.POST.get(self.certificate_request_parameter)
        if cert_req_enc is None:
            log.error('Certificate request not found in POST parameters')
            return None
        cert_req = base64.b64decode(cert_req_enc)

        # Get the user identification as set by an authentication filter.
        myproxy_id = grant.additional_data.get(
                                            self.user_identifier_grant_data_key)
        if not myproxy_id:
            log.error('User identifier not stored with grant')
            return None

        # Attempt to obtain a certificate from MyProxy.
        try:
            creds = myproxyclient.logon(myproxy_id, 
                                        self.myproxy_global_password, 
                                        certReq=cert_req)
        except Exception, exc:
            log.error('MyProxy logon failed: %s', exc.__str__())
            return None

        token_id = creds[0]
        return AccessToken(token_id, token_request, grant, self.token_type, 
                           self.lifetime)
