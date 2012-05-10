"""Test ESGI application that returns the response from a URL
"""
__author__ = "R B Wilkinson"
__date__ = "20/03/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging

from OpenSSL import crypto

import ndg.httpsclient.utils as httpsclientutils
import ndg.httpsclient.ssl_context_util as ssl_context_util
import ndg.oauth.client.lib.certificate_request as certificate_request

log = logging.getLogger(__name__)

class GetUrlApp(object):
    """WSGI application to exercise the NDG security proxy with OAuth.
    """
    method = {
        "/": 'default',
        "/get": 'get'
    }
    DEFAULT_TOKEN_ENV_KEYNAME = 'oauth2client.token'
    DEFAULT_CERTIFICATE_REQUEST_PARAMETER = 'certificate_request'
    def __init__(self, app, globalConfig, **localConfig):
#        self.beakerSessionKeyName = globalConfig['beakerSessionKeyName']
        self.app = app

        self.url = localConfig['url']

        self.resource_server_url = localConfig.get('resource_server_url')
        self.token_env_key = localConfig.get('oauth2_token_key',
                                             self.DEFAULT_TOKEN_ENV_KEYNAME)

        # SSL configuration
        client_cert = localConfig.get('client_cert')
        client_key = localConfig.get('client_key')
        self.ca_cert_file = localConfig.get('ca_cert_file')
        self.ca_dir = localConfig.get('ca_dir')
        self.ssl_config = ssl_context_util.SSlContextConfig(client_key,
            client_cert, self.ca_cert_file, self.ca_dir, True)

        # OAuth client configuration
        self.certificate_request_parameter = localConfig.get(
                                    'certificate_request_parameter',
                                    self.DEFAULT_CERTIFICATE_REQUEST_PARAMETER)

    def __call__(self, environ, start_response):
        log.debug('GetUrlApp.__call__ ...')
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

    def get(self, environ, start_response):
        log.debug('GetUrlApp.get ...')
        response = ["<h2>WSGI Test Application - Get URL</h2>"]

        token = environ.get(self.token_env_key)
        if not token:
            response.append('<p>No OAuth token found.</p>')
        else:
            log.debug("Token found; %s" % token)
            try:
                (private_key,
                 certificate) = certificate_request.request_certificate(
                    token, self.resource_server_url, self.ssl_config,
                    self.certificate_request_parameter)
            except Exception, exc:
                response.append('<p>Exception obtaining certificate from OAuth '
                                'server: %s</p>' % exc.__str__())
            else:
                ssl_context = ssl_context_util.make_ssl_context(None,
                                                            None,
                                                            self.ca_cert_file,
                                                            self.ca_dir,
                                                            True)

                clientKey = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                                   private_key)
                clientCert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                                     certificate)
   
                ssl_context.use_privatekey(clientKey)
                ssl_context.use_certificate(clientCert)


                config = httpsclientutils.Configuration(ssl_context, True)
                log.debug("Making request to URL: %s", self.url)
                resp = httpsclientutils.fetch_from_url(self.url, config)
                response.append(resp)

        start_response('200 OK', 
                       [('Content-type', 'text/html'),
                        ('Content-length', str(sum([len(r) for r in response])))])
        return response

    @classmethod
    def app_factory(cls, globalConfig, **localConfig):
        return cls(None, globalConfig, **localConfig)

    @classmethod
    def filter_app_factory(cls, app, globalConfig, **localConfig):
        return cls(app, globalConfig, **localConfig)
