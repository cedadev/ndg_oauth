"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "13/03/12"
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
from ndg.httpsclient.ssl_context_util import SSlContextConfig
import ndg.oauth.client.lib.openssl_cert as openssl_cert

log = logging.getLogger(__name__)

class WsgiTestApp(object):
    """
    Simple WSGI application that displays a token set in the WSGI environ by
    Oauth2ClientMiddleware.
    """
    method = {
        "/": 'default',
        "/cert": 'cert'
    }
    CERTIFICATE_REQUEST_PARAMETER = 'certificate_request'
    TOKEN_ENV_KEYNAME = 'oauth2client.token'
    def __init__(self, app, globalConfig, **localConfig):
        self.beakerSessionKeyName = globalConfig['beakerSessionKeyName']
        self.app = app

        self.resource_url = localConfig.get('resource_url')

        # SSL configuration
        client_cert = localConfig.get('client_cert')
        client_key = localConfig.get('client_key')
        ca_cert_file = localConfig.get('ca_cert_file')
        ca_dir = localConfig.get('ca_dir')
        self.ssl_config = SSlContextConfig(client_key, client_cert,
                                           ca_cert_file, ca_dir, True)

    def __call__(self, environ, start_response):
        methodName = self.method.get(environ['PATH_INFO'], '').rstrip()
        if methodName:
            action = getattr(self, methodName)
            return action(environ, start_response)
        elif self.app is not None:
            return self.app(environ, start_response)
        else:
            start_response('404 Not Found', [('Content-type', 'text/plain')])
            return "WSGI Test Application: invalid URI"

    def default(self, environ, start_response):
        response = "<h2>WSGI Test Application</h2>"
        start_response('200 OK', 
                       [('Content-type', 'text/html'),
                        ('Content-length', str(len(response)))])
        return [response]

    def cert(self, environ, start_response):
        response = ["<h2>WSGI Test Application - Request new certificate</h2>"]
        token_value = environ.get(self.TOKEN_ENV_KEYNAME)
        token = None

        if not token_value:
            response.append("<p>Token not found</p>")
        elif isinstance(token_value, basestring):
            token = token_value
        elif isinstance(token_value, tuple) and len(token) == 2:
            token = token_value[1]

        if token:
            cert = self.request_certificate(token)
            if cert:
                for c in cert:
                    response.append("<pre>%s</pre>" % c)
            else:
                response.append("<p>New certificate not obtained</p>")

        start_response('200 OK', 
                       [('Content-type', 'text/html'),
                        ('Content-length', str(sum([len(r) for r in response])))])
        return response

    def request_certificate(self, token):
        parameters = {'access_token': token}
        key_pair = openssl_cert.createKeyPair()
        cert_req = openssl_cert.createCertReq('ignored-username', key_pair)
        parameters[self.CERTIFICATE_REQUEST_PARAMETER] = base64.b64encode(cert_req)

        # Make POST request to obtain an access token.
        log.debug("Resource request - parameters: %s", parameters)
        data = urllib.urlencode(parameters)
        response_json = httpsclient_utils.fetch_stream_from_url(
            self.resource_url,
            httpsclient_utils.Configuration(
                ssl_context_util.make_ssl_context_from_config(self.ssl_config)),
            data)
        response = json.load(response_json)
        certificate = response.get('certificate', None)

        # Get the private key.
        private_key = openssl_cert.getKeyPairPrivateKey(key_pair)
        return (private_key, certificate)

    @classmethod
    def app_factory(cls, globalConfig, **localConfig):
        return cls(None, globalConfig, **localConfig)

    @classmethod
    def filter_app_factory(cls, app, globalConfig, **localConfig):
        return cls(app, globalConfig, **localConfig)
