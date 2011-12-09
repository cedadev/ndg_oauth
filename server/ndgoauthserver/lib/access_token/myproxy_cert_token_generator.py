'''
Created on 30 Nov 2011

@author: rwilkinson
'''
import base64
import logging
import uuid

from ndgoauthserver.lib.oauth.oauth_exception import OauthException
from ndgoauthserver.lib.register.access_token import AccessToken

log = logging.getLogger(__name__)

class MyProxyCertTokenGenerator(object):
    def __init__(self, lifetime, token_type, **kw):
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
        Returns
          access token or None if an error occurs that is not one of those that
          can be reported in an error response
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
        myproxy_id = grant.additional_data.get(self.user_identifier_grant_data_key)
        if not myproxy_id:
            log.error('User identifier not stored with grant')
            return None

        # TODO password should be configurable.
        myproxy_global_password = self.myproxy_global_password
        try:
            creds = myproxyclient.logon(myproxy_id, myproxy_global_password, certReq=cert_req)
        except Exception, exc:
            log.error('MyProxy logon failed: %s', exc.__str__())
            return None

#        token_id = uuid.uuid4().hex
        token_id = creds[0]
        return AccessToken(token_id, token_request, grant, self.token_type, self.lifetime)
