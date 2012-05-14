"""Retriever of data from a URL using credentials obtained using an OAuth
    access token.
"""
__author__ = "R B Wilkinson"
__date__ = "29/03/12"
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

class HttpGetWithCredential(object):
    """Retrieves data from a URL using credentials obtained using an OAuth
    access token. 
    """
    DEFAULT_TOKEN_ENV_KEYNAME = 'oauth2client.token'

    def __init__(self, resource_server_url, client_cert, client_key,
                 ca_cert_file, ca_dir,
                 token_env_key=None,
                 certificate_request_parameter=None):
        """
        @type resource_server_url: basestring
        @param resource_server_url: URL of resource server from which to request
        certificates
        @type client_cert: basestring
        @param client_cert: location of certificate file for OAuth client
        @type client_key: basestring
        @param client_key: location of private key file for OAuth client
        @type ca_cert_file: basestring
        @param ca_cert_file: location of file containing trusted certificate
        authority certificates
        @type ca_dir: basestring
        @param ca_dir: location of directory containing trusted certificate
        authority certificate files
        @type token_env_key: basestring
        @param token_env_key: key of entry in environ holding the OAuth token
        @type certificate_request_parameter: basestring
        @param certificate_request_parameter: name of the parameter to be used
        in the resource request to hold the certificate request
        """
        self.resource_server_url = resource_server_url
        self.token_env_key = (self.DEFAULT_TOKEN_ENV_KEYNAME
                              if token_env_key is None
                              else token_env_key)

        # SSL configuration
        self.client_cert = client_cert
        self.client_key = client_key
        self.ca_cert_file = ca_cert_file
        self.ca_dir = ca_dir
        self.client_ssl_config = ssl_context_util.SSlContextConfig(client_key,
            client_cert, self.ca_cert_file, self.ca_dir, True)

        # OAuth client configuration
        self.certificate_request_parameter = certificate_request_parameter

        self.token = None
        self.user_ssl_context = None

    def get(self, environ, url):
        """Makes a HTTP request to the specified URL using the certificate
        obtained from the WSGI environ.
        @type environ: dict
        @param environ: WSGI environ
        @type url: basestring
        @param url: URL of resource to request
        @rtype: basestring
        @return: response from HTTP request
        """
        current_token = environ.get(self.token_env_key)
        if current_token:
            log.debug("Token ID: %s", current_token)
        else:
            log.debug("No token found with environ key: %s",
                      self.token_env_key)
        if ((self.token != current_token) or not self.user_ssl_context):
            log.debug("Certificate request needed")
            if current_token:
                self.token = current_token
                # Get credential.
                log.debug("Making certificate request")
                (private_key,
                 certificate) = certificate_request.request_certificate(
                    self.token, self.resource_server_url,
                    self.client_ssl_config, self.certificate_request_parameter)
    
                # Create SSL context using the resource owner's delegated
                # credential.
                self.user_ssl_context = ssl_context_util.make_ssl_context(
                                                            None,
                                                            None,
                                                            self.ca_cert_file,
                                                            self.ca_dir,
                                                            True)

                clientKey = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                                   private_key)
                clientCert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                                     certificate)
   
                self.user_ssl_context.use_privatekey(clientKey)
                self.user_ssl_context.use_certificate(clientCert)
                log.debug("Created new SLL context")
            else:
                log.warn("Certificate needed but no token available")

        config = httpsclientutils.Configuration(self.user_ssl_context, True)
        log.debug("Making request to URL: %s", url)
        response = httpsclientutils.fetch_from_url(url, config)

        return response
