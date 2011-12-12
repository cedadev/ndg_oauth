"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "09/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import httplib
import logging

from webob import Request

from ndgoauthclient.lib.oauth2client import Oauth2ClientConfig
from ndgoauthclient.lib.oauth2_myproxy_client import Oauth2MyProxyClient
from urllib2pyopenssl.ssl_context_util import SSlContextConfig

log = logging.getLogger(__name__)

class Oauth2ClientMiddleware(object):
    """
    OAuth 2.0 client middleware that sets an access token in the WSGI environ.
    """
    PARAM_PREFIX = 'oauth2.'
    BASE_URL_PATH_OPTION = 'base_url_path'
    CERTIFICATE_REQUEST_PARAMETER_OPTION = 'certificate_request_parameter'
    SESSION_KEY_OPTION = 'session_key'
    SESSION_CALL_CONTEXT_KEY = 'oauth2_call_context'
    TOKEN_KEY_OPTION = 'oauth2_token_key'
    propertyDefaults = {
        BASE_URL_PATH_OPTION: '',
        CERTIFICATE_REQUEST_PARAMETER_OPTION: 'certificate_request',
        SESSION_KEY_OPTION: 'beaker.session.oauth2client',
        TOKEN_KEY_OPTION: 'oauth2client.token',
    }
    client_instances = {}

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
        self._oauth_client_class = Oauth2MyProxyClient

    def __call__(self, environ, start_response):
        """
        @param environ: WSGI environment
        @type environ: dict
        @param start_response: WSGI start response function
        @type start_response: 
        @return: WSGI response
        @rtype: iterable
        """
        log.debug("Oauth2ClientMiddleware.__call__ ...")

        req = Request(environ)
        original_environ = {'PATH_INFO': environ['PATH_INFO'], 'QUERY_STRING': environ['QUERY_STRING']}

        # Get session.
        session = environ.get(self.session_env_key)
        if session is None:
            raise Exception(
                'Oauth2ClientMiddleware.__call__: No beaker session key '
                '"%s" found in environ' % self.session_env_key)

        # Check whether redirecting back after requesting authorization.
        if self.client_config.is_redirect_uri(req.host_url, req.url):
            log.debug("Redirected back after requesting authorization.")
            token = self._get_token_after_redirect(session, req)
            original_environ = session[self.__class__.SESSION_CALL_CONTEXT_KEY]
        else:
            # Start the OAuth2 transaction to get a certificate.
            (token, redirect_url) = self._get_token(session, req.host_url)
            if redirect_url:
                session[self.__class__.SESSION_CALL_CONTEXT_KEY] = original_environ
                session.save()
                start_response(self._get_http_status_string(httplib.FOUND),
                               [('Location', redirect_url)])
                return []

        if token:
            environ[self.token_env_key] = token

        # Ensure that the URL is that prior to authentication redirection.
        environ['PATH_INFO'] = original_environ['PATH_INFO']
        environ['QUERY_STRING'] = original_environ['QUERY_STRING']

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
        self.session_env_key = cls._get_config_option(prefix, local_conf, cls.SESSION_KEY_OPTION)
        self.token_env_key = self._get_config_option(prefix, local_conf, cls.TOKEN_KEY_OPTION)

        # SSL configuration
        client_cert = cls._get_config_option(prefix, local_conf, 'client_cert')
        client_key = cls._get_config_option(prefix, local_conf, 'client_key')
        ca_cert_file = cls._get_config_option(prefix, local_conf, 'ca_cert_file')
        ca_dir = cls._get_config_option(prefix, local_conf, 'ca_dir')
        ssl_config = SSlContextConfig(client_key, client_cert, ca_cert_file, ca_dir, True)

        # OAuth client configuration
        certificate_request_parameter = cls._get_config_option(prefix, local_conf, cls.CERTIFICATE_REQUEST_PARAMETER_OPTION)
        client_id = cls._get_config_option(prefix, local_conf, 'client_id')
        authorization_endpoint = cls._get_config_option(prefix, local_conf, 'authorization_endpoint')
        access_token_endpoint = cls._get_config_option(prefix, local_conf, 'access_token_endpoint')
        base_url_path = cls._get_config_option(prefix, local_conf, cls.BASE_URL_PATH_OPTION)
        redirect_uri = 'oauth_redirect'
        self.client_config = Oauth2ClientConfig(
            client_id, authorization_endpoint, access_token_endpoint,
            base_url_path, redirect_uri, ssl_config,
            certificate_request_parameter=certificate_request_parameter)

    @classmethod
    def _get_config_option(cls, prefix, local_conf, key):
        return local_conf.get(prefix + key, cls.propertyDefaults.get(key, None))

    @staticmethod
    def _get_http_status_string(status):
        return ("%d %s" % (status, httplib.responses[status]))

    @classmethod
    def filter_app_factory(cls, app, app_conf, **local_conf):
        return cls(app, app_conf, **local_conf)

    def _get_token(self, session, host_url):
        """Gets a token using the OAuth2 client.
        @type session: Beaker SessionObject
        @param session: session
        @type host_url: str
        @param host_url: host part of request URL
        @rtype: tuple (
            result type of callback or None
            str or None
        )
        @return: (
            result of callback or None if a redirect is needed
            redirect URI if redirect needed or None
        """
        client = self._oauth_client_class.get_client_instance(session, self.client_config, create=True)

        callback = TokenRetriever(client)

        (result, redirect_url) = client.call_with_access_token(
            scope='', host_url=host_url, callback=callback)

        return (result, redirect_url)

    def _get_token_after_redirect(self, session, req):
        """Gets a token using the OAuth2 client - to be called after a redirect
        has occurred from the OAuth authorization server.
        @type session: Beaker SessionObject
        @param session: session
        @rtype: result type of callback
        @return: result of callback
        """
        client = self._oauth_client_class.get_client_instance(session, self.client_config)
        if client:
            # Return callback result.
            return client.call_with_access_token_redirected_back(req)
        else:
            raise Exception("No OAuth client created for session.")


class TokenRetriever(object):
    def __init__(self, client):
        self.client = client

    def __call__(self, access_token, error, error_description):
        """
        Returns the private key and certificate.
        This depends on Oauth2MyProxyClient which sets the private key in the
        client.
        @type access_token: type of access token
        @param access_token: access token
        @type error: str
        @param error: OAuth error string
        @type error_description: str
        @param error_description: error description
        @rtype: tuple (str, str)
        @return: tuple (
            private key
            access token
        )
        """
        if error:
            return ("", ("Token not available because of error: %s - %s" % (error, error_description)))
        return (self.client.private_key, self.client.access_token)
