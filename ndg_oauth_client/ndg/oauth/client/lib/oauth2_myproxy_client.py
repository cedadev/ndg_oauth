"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "09/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import base64

from ndg.oauth.client.lib.oauth2client import Oauth2Client
import ndg.oauth.client.lib.openssl_cert as openssl_cert

class Oauth2MyProxyClient(Oauth2Client):
    """Extentsion of OAuth client to handle additional certificate request
    parameter for MyProxy request.
    """
    def additional_access_token_request_parameters(self, parameters, request):
        """
        Creates a certificate request and sets it as an additional parameter.
        Also, saves the private key in environ.

        @type parameters: dict of str
        @param parameters: parameters sent in access token request

        @type request: webob.Request
        @param request: request object
        """
        key_pair = openssl_cert.createKeyPair()
        cert_req = openssl_cert.createCertReq('ignored-username', key_pair)
        parameters[self.certificate_request_parameter] = base64.b64encode(cert_req)

        # Store the private key.
        private_key = openssl_cert.getKeyPairPrivateKey(key_pair)
        self.private_key = private_key
