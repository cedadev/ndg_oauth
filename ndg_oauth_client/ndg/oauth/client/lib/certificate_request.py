"""Function to make a certificate request using a resource server secured
using OAuth
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

import ndg.httpsclient.utils as httpsclient_utils
import ndg.httpsclient.ssl_context_util as ssl_context_util
import ndg.oauth.client.lib.openssl_cert as openssl_cert

log = logging.getLogger(__name__)

DEFAULT_CERTIFICATE_REQUEST_PARAMETER = 'certificate_request'

def request_certificate(token, resource_server_url, ssl_config,
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
    parameters = {'access_token': token}
    key_pair = openssl_cert.createKeyPair()
    cert_req = openssl_cert.createCertReq('ignored-username', key_pair)
    cert_req_param = (DEFAULT_CERTIFICATE_REQUEST_PARAMETER
                      if certificate_request_parameter is None
                      else certificate_request_parameter)
    parameters[cert_req_param] = base64.b64encode(cert_req)

    # Make POST request to obtain an access token.
    log.debug("Resource request - parameters: %s", parameters)
    data = urllib.urlencode(parameters)
    response_json = httpsclient_utils.fetch_stream_from_url(
            resource_server_url,
            httpsclient_utils.Configuration(
                    ssl_context_util.make_ssl_context_from_config(ssl_config)),
            data)
    response = json.load(response_json)
    certificate = response.get('certificate', None)

    # Get the private key.
    private_key = openssl_cert.getKeyPairPrivateKey(key_pair)
    return (private_key, certificate)
