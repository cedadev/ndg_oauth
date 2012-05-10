"""OAuth 2.0 WSGI server middleware to request a MyProxy certificates using a
resource server request
"""
__author__ = "R B Wilkinson"
__date__ = "19/03/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import httplib
import logging

from webob import Request

import ndg.oauth.client.lib.certificate_request as certificate_request
from ndg.oauth.client.lib.oauth2client import Oauth2Client
from ndg.httpsclient.ssl_context_util import SSlContextConfig

log = logging.getLogger(__name__)

class CertificateRequestMiddleware(object):
    """
    OAuth 2.0 client middleware that requests a certificate using a resource
    server request
    """
    PARAM_PREFIX = 'certreq.'
    CERTIFICATE_ENVIRON_KEY_OPTION = 'oauth2_certificate_environ_key'
    CERTIFICATE_SESSION_KEY_OPTION = 'oauth2_certificate_session_key'
    CERTIFICATE_REQUEST_PARAMETER_OPTION = 'certificate_request_parameter'
    RESOURCE_SERVER_URL_OPTION = 'resource_server_url'
    SESSION_KEY_OPTION = 'session_key'
    TOKEN_KEY_OPTION = 'oauth2_token_key'
    propertyDefaults = {
        CERTIFICATE_ENVIRON_KEY_OPTION: 'oauth2client.certificate',
        CERTIFICATE_SESSION_KEY_OPTION: 'oauth2client.certificate',
        CERTIFICATE_REQUEST_PARAMETER_OPTION: 'certificate_request',
        RESOURCE_SERVER_URL_OPTION: '',
        SESSION_KEY_OPTION: 'beaker.session.oauth2client',
        TOKEN_KEY_OPTION: 'oauth2client.token',
    }

    def __init__(self, app, app_conf, prefix=PARAM_PREFIX, **local_conf):
        """
        @param app: wrapped application/middleware
        @type app: WSGI application
        @param app_conf: application configuration settings - ignored - this
        method includes this arg to fit Paste middleware / app function 
        signature
        @type app_conf: dict
        @param prefix: optional prefix for parameter names included in the 
        local_conf dict - enables these parameters to be filtered from others
        which don't apply to this middleware
        @param local_conf: attribute settings to apply
        @type local_conf: dict
        """
        self._app = app
        self._set_configuration(prefix, local_conf)

    def __call__(self, environ, start_response):
        """
        @param environ: WSGI environment
        @type environ: dict
        @param start_response: WSGI start response function
        @type start_response: 
        @return: WSGI response
        @rtype: iterable
        """
        log.debug("CertificateRequestMiddleware.__call__ ...")

        req = Request(environ)
        log.debug("Request url: %s", req.url)
        log.debug("Request host_url: %s", req.host_url)
        log.debug("Request application_url: %s", req.application_url)

        # Get session.
        session = environ.get(self.session_env_key)
        if session is None:
            raise Exception(
                'CertificateRequestMiddleware.__call__: No beaker session key '
                '"%s" found in environ' % self.session_env_key)

        # Determine whether a certificate is stored in the session already.
        key_cert = None
        if self.__class__.CERTIFICATE_SESSION_KEY_OPTION in session:
            key_cert = session[self.__class__.CERTIFICATE_SESSION_KEY_OPTION]
        else:
            # If not, and an access token has been obtained, request a
            # certificate.
            client = Oauth2Client.get_client_instance(session, None,
                                                      create=False)
            if client and client.access_token:
                key_cert = certificate_request.request_certificate(
                                            client.access_token,
                                            self.resource_server_url,
                                            self.ssl_config,
                                            self.certificate_request_parameter)
                session[self.__class__.CERTIFICATE_SESSION_KEY_OPTION
                                                                    ] = key_cert
                # Make certificate available in the session immediately.
                session.save()
                session.persist()

        if key_cert:
            environ[self.certificate_env_key] = key_cert

        app_iter = self._app(environ, start_response)
        return app_iter

    def _set_configuration(self, prefix, local_conf):
        """Sets the configuration values.

        @param prefix: optional prefix for parameter names included in the
        local_conf dict - enables these parameters to be filtered from others
        which don't apply to this middleware
        @type prefix: str
        @param local_conf: attribute settings to apply
        @type local_conf: dict
        """
        cls = self.__class__
        self.resource_server_url = cls._get_config_option(prefix, local_conf,
                                                cls.RESOURCE_SERVER_URL_OPTION)
        self.session_env_key = cls._get_config_option(prefix, local_conf,
                                                      cls.SESSION_KEY_OPTION)
        self.token_env_key = self._get_config_option(prefix, local_conf,
                                                     cls.TOKEN_KEY_OPTION)
        self.certificate_env_key = self._get_config_option(prefix, local_conf,
                                            cls.CERTIFICATE_SESSION_KEY_OPTION)
        self.certificate_session_key = self._get_config_option(prefix,
                                local_conf, cls.CERTIFICATE_ENVIRON_KEY_OPTION)

        # SSL configuration
        client_cert = cls._get_config_option(prefix, local_conf, 'client_cert')
        client_key = cls._get_config_option(prefix, local_conf, 'client_key')
        ca_cert_file = cls._get_config_option(prefix, local_conf,
                                              'ca_cert_file')
        ca_dir = cls._get_config_option(prefix, local_conf, 'ca_dir')
        self.ssl_config = SSlContextConfig(client_key, client_cert,
                                           ca_cert_file, ca_dir, True)

        # OAuth client configuration
        self.certificate_request_parameter = cls._get_config_option(prefix,
                        local_conf, cls.CERTIFICATE_REQUEST_PARAMETER_OPTION)

    @classmethod
    def _get_config_option(cls, prefix, local_conf, key):
        value = local_conf.get(prefix + key, cls.propertyDefaults.get(key,
                                                                      None))
        log.debug("CertificateRequestMiddleware configuration %s=%s", key,
                  value)
        return value

    @staticmethod
    def _get_http_status_string(status):
        return ("%d %s" % (status, httplib.responses[status]))

    @classmethod
    def filter_app_factory(cls, app, app_conf, **local_conf):
        return cls(app, app_conf, **local_conf)
