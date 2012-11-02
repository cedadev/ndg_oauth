"""Function to make a request for an X.509 certificate from an Online 
Certificate authority protected with OAuth
"""
__author__ = "R B Wilkinson"
__date__ = "20/03/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import base64
import json
import logging
import urllib

from ndg.oauth.client.lib import openssl_cert
from ndg.oauth.client.lib.oauth2client import Oauth2Client

log = logging.getLogger(__name__)

DEFAULT_CERTIFICATE_REQUEST_PARAMETER = 'certificate_request'


def request_certificate(token, 
                        resource_server_url, 
                        ssl_config,
                        certificate_request_parameter=None):
    """Requests a certificate using an OAuth authorized resource request.
    @param token: access token to use in request
    @type token: basestring
    @param resource_server_url: URL of resource server to which the request
    should be made
    @type resource_server_url: basestring
    @param ssl_config: SSL configuration including the OAuth client certificate
    and private key
    @type ssl_config: ndg.httpsclient.ssl_context_util:SSlContextConfig
    @param certificate_request_parameter: name of parameter for the certificate
    request in the resource server request
    @type certificate_request_parameter: basestring
    """
    oauth_client = Oauth2Client(access_token=token)
    
    parameters = {}
    key_pair = openssl_cert.create_keypair()
    cert_req = openssl_cert.create_certreq('ignored-username', key_pair)
    
    cert_req_param = (DEFAULT_CERTIFICATE_REQUEST_PARAMETER
                      if certificate_request_parameter is None
                      else certificate_request_parameter)
    
    parameters[cert_req_param] = base64.b64encode(cert_req)

    # Make POST request to obtain an access token.
    log.debug("Resource request - parameters: %s", parameters)
    data = urllib.urlencode(parameters)
    
    response = oauth_client.request_resource(resource_server_url, 
                                             ssl_config=ssl_config, 
                                             data=data)

    # TODO: Refactor so that does or doesn't support JSON response - currently
    # works so that it will accept either
    if 'application/json' in response.headers.get('Content-type', ''):
        response_json = json.load(response)
        certificate = response_json.get('certificate', None)
    else:       
        certificate = response.read() 

    # Get the private key.
    private_key = openssl_cert.getKeyPairPrivateKey(key_pair)
    return private_key, certificate
