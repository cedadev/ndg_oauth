"""OAuth 2.0 WSGI server middleware providing MyProxy certificates in response
to resource requests
"""
__author__ = "R B Wilkinson"
__date__ = "13/03/12"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import base64
import logging

log = logging.getLogger(__name__)


class MyproxyCertRequest(object):
    def __init__(self, **kw):
        """
        @type kw: dict
        @param kw: additional keywords
        """
        self.certificate_request_parameter = kw.get(
                                                'certificate_request_parameter')
        self.myproxy_client_env_key = kw.get('myproxy_client_env_key',
            'myproxy.server.wsgi.middleware.MyProxyClientMiddleware.myProxyClient')
        self.myproxy_global_password = kw.get('myproxy_global_password')
        self.user_identifier_grant_data_key = kw.get(
                                            'user_identifier_grant_data_key')

    def get_resource(self, token, request):
        """ Creates response to a resource request - takes a certificate request
        from the request parameters and obtains a certificate from a MyProxy
        server.
        @type token: basestring
        @param token: access token
        @type request: webob.Request
        @param request: request object
        @rtype: basestring
        @returns: certificate
        """
        grant = token.grant

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

        return creds[0]
