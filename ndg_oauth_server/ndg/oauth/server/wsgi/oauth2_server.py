"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import httplib
import logging
import urllib
import urlparse

from webob import Request

from ndg.oauth.server.lib.access_token.bearer_token_generator import BearerTokenGenerator
from ndg.oauth.server.lib.access_token.myproxy_cert_token_generator import MyProxyCertTokenGenerator
from ndg.oauth.server.lib.authenticate.certificate_client_authenticator import CertificateClientAuthenticator
from ndg.oauth.server.lib.authenticate.noop_client_authenticator import NoopClientAuthenticator
from ndg.oauth.server.lib.authorization_server import AuthorizationServer
from ndg.oauth.server.lib.authorize.authorizer import Authorizer
from ndg.oauth.server.lib.authorize.authorizer_storing_identifier import AuthorizerStoringIdentifier

log = logging.getLogger(__name__)

class Oauth2ServerMiddleware(object):
    """
    WSGI OAuth 2.0 server.
    Requires:
    o Beaker session
    o An authentication provider that sets the user's ID in the environ, e.g.,
      repose.who
    o MyProxyClientMiddleware
    o Middleware to set user's decisions for authorization of OAuth clients in
      the environ, e.g., ndg.oauth.server.wsgi.authorization_filter.
    """
    PARAM_PREFIX = 'oauth2server.'
    # Configuration options
    ACCESS_TOKEN_LIFETIME_OPTION = 'access_token_lifetime'
    ACCESS_TOKEN_TYPE_OPTION = 'access_token_type'
    AUTHORIZATION_GRANT_LIFETIME_OPTION = 'authorization_grant_lifetime'
    BASE_URL_PATH_OPTION = 'base_url_path'
    CERTIFICATE_REQUEST_PARAMETER_OPTION = 'certificate_request_parameter'
    CLIENT_AUTHENTICATION_METHOD_OPTION = 'client_authentication_method'
    CLIENT_AUTHORIZATION_URL_OPTION = 'client_authorization_url'
    CLIENT_AUTHORIZATIONS_KEY_OPTION = 'client_authorizations_key'
    CLIENT_REGISTER_OPTION = 'client_register'
    MYPROXY_CLIENT_KEY_OPTION = 'myproxy_client_key'
    MYPROXY_GLOBAL_PASSWORD_OPTION = 'myproxy_global_password'
    USER_IDENTIFIER_KEY_OPTION = 'user_identifier_key'
    USER_IDENTIFIER_GRANT_DATA_KEY = 'user_identifier'

    # Configuration option defaults
    propertyDefaults = {
        ACCESS_TOKEN_LIFETIME_OPTION: 86400,
        ACCESS_TOKEN_TYPE_OPTION: 'myproxy',
        AUTHORIZATION_GRANT_LIFETIME_OPTION: 600,
        BASE_URL_PATH_OPTION: '',
        CERTIFICATE_REQUEST_PARAMETER_OPTION: 'certificate_request',
        CLIENT_AUTHENTICATION_METHOD_OPTION: 'certificate',
        CLIENT_AUTHORIZATION_URL_OPTION: '/client_authorization/authorize',
        CLIENT_AUTHORIZATIONS_KEY_OPTION: 'client_authorizations',
        MYPROXY_CLIENT_KEY_OPTION: 'myproxy.server.wsgi.middleware.MyProxyClientMiddleware.myProxyClient',
        USER_IDENTIFIER_KEY_OPTION: 'REMOTE_USER'
    }
    method = {
        '/access_token': 'access_token',
        '/authorize': 'authorize',
        '/check_token': 'check_token'
    }

    def __init__(self, app, app_conf, prefix=PARAM_PREFIX, **local_conf):
        """
        Sets up the server depending on the configuration.

        @type app: WSGI application
        @param app: wrapped application/middleware

        @type app_conf: dict
        @param app_conf: application configuration settings - ignored - this
        method includes this arg to fit Paste middleware / app function 
        signature

        @@type prefix: str
        @param prefix: optional prefix for parameter names included in the 
        local_conf dict - enables these parameters to be filtered from others
        which don't apply to this middleware

        @type local_conf: dict
        @param local_conf: attribute settings to apply
        """
        self._app = app
        conf = self._set_configuration(prefix, local_conf)

        if self.access_token_type == 'bearer':
            # Simple bearer token configuration.
            authorizer = Authorizer(self.authorization_grant_lifetime_seconds)
            access_token_generator = BearerTokenGenerator(self.access_token_lifetime_seconds, self.access_token_type)
        elif self.access_token_type == 'myproxy':
            # Configure authorization server to use MyProxy certificates as access tokens.
            authorizer = AuthorizerStoringIdentifier(
                self.authorization_grant_lifetime_seconds,
                user_identifier_env_key=self.user_identifier_env_key,
                user_identifier_grant_data_key=self.USER_IDENTIFIER_GRANT_DATA_KEY)

            access_token_generator = MyProxyCertTokenGenerator(
                self.access_token_lifetime_seconds, self.access_token_type,
                certificate_request_parameter=self.certificate_request_parameter,
                myproxy_client_env_key=self.myproxy_client_env_key,
                myproxy_global_password=self.myproxy_global_password,
                user_identifier_grant_data_key=self.USER_IDENTIFIER_GRANT_DATA_KEY)
        else:
            raise ValueError("Invalid configuration value %s for %s" %
                             (self.access_token_type,
                              self.ACCESS_TOKEN_TYPE_OPTION))

        # Determine client authentication type. A 'none' options is allowed so
        # that development/testing can be performed without running on Apache.
        if self.client_authentication_method == 'certificate':
            client_authenticator = CertificateClientAuthenticator()
        elif self.client_authentication_method == 'none':
            client_authenticator = NoopClientAuthenticator()
        else:
            raise ValueError("Invalid configuration value %s for %s" %
                             (self.client_authentication_method,
                              self.CLIENT_AUTHENTICATION_METHOD_OPTION))

        self._authorizationServer = AuthorizationServer(
            self.client_register_file, authorizer, client_authenticator,
            access_token_generator, conf)

    def __call__(self, environ, start_response):
        """
        @type environ: dict
        @param environ: WSGI environment

        @type start_response: WSGI start response function
        @param start_response: start response function

        @rtype: iterable
        @return: WSGI response
        """
        log.debug("Oauth2ServerMiddleware.__call__ ...")
        req = Request(environ)
        log.debug("Request path_info: %s", req.path_info)

        # Determine what operation the URL specifies.
        actionPath = None
        if req.path_info.startswith(self.base_path):
            actionPath = req.path_info[len(self.base_path):]
        methodName = self.__class__.method.get(actionPath, '')
        if methodName:
            log.debug("Method: %s" % methodName)
            action = getattr(self, methodName)
            return action(req, start_response)
        elif self._app is not None:
            log.debug("Delegating to lower filter/application.")
            return self._app(environ, start_response)
        else:
            response = "OAuth 2.0 Server - Invalid URL"
            start_response(self._get_http_status_string(httplib.NOT_FOUND),
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))
                            ])
            return [response]

    def authorize(self, req, start_response):
        """Handles OAuth 2 authorize request.
        @type req: webob.Request
        @param req: HTTP request object

        @type start_response: WSGI start response function
        @param start_response: start response function

        @rtype: iterable
        @return: WSGI response
        """
        # User authentication is required before authorization can proceed.
        user = req.environ.get(self.user_identifier_env_key)
        if not user:
            log.debug("%s not in environ - authentication required" % self.user_identifier_env_key)
            start_response(self._get_http_status_string(httplib.UNAUTHORIZED), [])
            return []


        # User authorization for the client is also required.
        (client_authorized, authz_uri) = self._check_client_authorization(user, req)
        if authz_uri:
            log.debug("Redirecting to %s", authz_uri)
            return self._redirect(authz_uri, start_response)

        if not client_authorized:
            log.debug("User has declined authorization for client.")

        # Request authorization grant.
        (redirect_uri, error, error_description) = self._authorizationServer.authorize(req, client_authorized)
        if error:
            response = ("%s: %s" %(error, error_description))
            log.error("Returning error: %s - %s", error, error_description)
            start_response(self._get_http_status_string(httplib.BAD_REQUEST),
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))
                            ])
            return[response]
        else:
            return self._redirect(redirect_uri, start_response)

    def _check_client_authorization(self, user, req):
        """
        Gets the URL to which to redirect for the user to authorize the client.
        Returns: URL or None if already authorized
        @type user: str
        @param user: identifier of user/resource owner

        @type req: webob.Request
        @param req: HTTP request object
        """
        client_authorizations = req.environ.get(self.client_authorizations_env_key)
        client_id = req.params.get('client_id')
        scope = req.params.get('scope')
        if not client_authorizations:
            client_authorized = None
            log.debug("Client authorization register not found in environ (key %s).", self.client_authorizations_env_key)
        else:
            client_authorized = client_authorizations.is_client_authorized_by_user(user, client_id, scope)
        if client_authorized is None:
            log.debug("Client not authorized by user (client_id: %s  scope: %s  user: %s).", client_id, scope, user)
            url_params = {'client_id': client_id,
                          'scope': scope,
                          'user': user,
                          'original_url': req.url}
            url = ("%s?%s" % (self._make_client_authorization_url(req),
                              urllib.urlencode(url_params)))
            return (None, url)
        return (client_authorized, None)

    def _make_client_authorization_url(self, req):
        parts = urlparse.urlparse(self.client_authorization_url)
        if (parts.scheme and parts.netloc):
            # Absolute URL:
            return self.client_authorization_url
        else:
            # Relative - append to application URL:
            return '/'.join([req.application_url.rstrip('/'),
                             self.client_authorization_url.lstrip('/')])


    def access_token(self, req, start_response):
        """Handles OAuth 2 access token request.
        @type req: webob.Request
        @param req: HTTP request object

        @type start_response: 
        @param start_response: WSGI start response function

        @rtype: iterable
        @return: WSGI response
        """
        (response, error_status, error_description) = self._authorizationServer.access_token(req)
        log.debug("Access token response is of type %s", type(response))
        if response is None:
            response = ''
        headers = [
            ('Content-Type', 'application/json; charset=UTF-8'),
            ('Cache-Control', 'no-store'),
            ('Content-length', str(len(response))),
            ('Pragma', 'no-store')
        ]
        status_str = self._get_http_status_string(error_status if error_status else httplib.OK)
            
        start_response(status_str, headers)
        return [response]

    def check_token(self, req, start_response):
        """
        Service to validate bearer tokens. It would be called from a resource
        service that trusts this authorization service.
        @type req: webob.Request
        @param req: HTTP request object

        @type start_response: 
        @param start_response: WSGI start response function

        @rtype: iterable
        @return: WSGI response
        """
        (response, error_status, error_description) = self._authorizationServer.check_token(req)
        if response is None:
            response = ''
        headers = [
            ('Content-Type', 'application/json; charset=UTF-8'),
            ('Cache-Control', 'no-store'),
            ('Content-length', str(len(response)))
            ('Pragma', 'no-store')
        ]
        status_str = self._get_http_status_string(error_status if error_status else httplib.OK)
            
        start_response(status_str, headers)
        return [response]

    @staticmethod
    def _get_http_status_string(status):
        return ("%d %s" % (status, httplib.responses[status]))

    def _redirect(self, url, start_response):
        """Initiates a redirect to a specified URL.
        @type param: str
        @param url: URL

        @type start_response: 
        @param start_response: WSGI start response function

        @rtype: iterable
        @return: WSGI response
        """
        log.debug("Redirecting to %s", url)
        start_response(self._get_http_status_string(httplib.FOUND),
               [('Location', url.encode('ascii', 'ignore'))])
        return []

    def _set_configuration(self, prefix, local_conf):
        """Sets the configuration values.

        @type prefix: str
        @param prefix: optional prefix for parameter names included in the
        local_conf dict - enables these parameters to be filtered from others
        which don't apply to this middleware

        @type local_conf: dict
        @param local_conf: attribute settings to apply
        """
        conf = {}
        plen = len(prefix)
        for k, v in local_conf.iteritems():
            if k.startswith(prefix):
                conf[k[plen:]] = v
        cls = self.__class__
        self.base_path = cls._get_config_option(conf, cls.BASE_URL_PATH_OPTION)
        self.authorization_grant_lifetime_seconds = cls._get_config_option(conf, cls.AUTHORIZATION_GRANT_LIFETIME_OPTION)
        self.access_token_lifetime_seconds = cls._get_config_option(conf, cls.ACCESS_TOKEN_LIFETIME_OPTION)
        self.access_token_type = cls._get_config_option(conf, cls.ACCESS_TOKEN_TYPE_OPTION)
        self.certificate_request_parameter = cls._get_config_option(conf, cls.CERTIFICATE_REQUEST_PARAMETER_OPTION)
        self.client_authorization_url  = cls._get_config_option(conf, cls.CLIENT_AUTHORIZATION_URL_OPTION)
        self.client_authentication_method  = cls._get_config_option(conf, cls.CLIENT_AUTHENTICATION_METHOD_OPTION)
        self.client_authorizations_env_key = cls._get_config_option(conf, cls.CLIENT_AUTHORIZATIONS_KEY_OPTION)
        self.client_register_file = cls._get_config_option(conf, cls.CLIENT_REGISTER_OPTION)
        self.myproxy_client_env_key = cls._get_config_option(conf, cls.MYPROXY_CLIENT_KEY_OPTION)
        self.myproxy_global_password = cls._get_config_option(conf, cls.MYPROXY_GLOBAL_PASSWORD_OPTION)
        self.user_identifier_env_key = cls._get_config_option(conf, cls.USER_IDENTIFIER_KEY_OPTION)
        # Return any options that start with the prefix but haven't been read
        # above.
        return conf

    @classmethod
    def _get_config_option(cls, conf, key):
        value = conf.pop(key, cls.propertyDefaults.get(key, None))
        log.debug("Oauth2ServerMiddleware configuration %s=%s", key, value)
        return value

    @classmethod
    def filter_app_factory(cls, app, app_conf, **local_conf):
        return cls(app, app_conf, **local_conf)

    @classmethod
    def app_factory(cls, app_conf, **local_conf):
        return cls(None, app_conf, **local_conf)
