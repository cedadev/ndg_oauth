"""OAuth 2.0 WSGI server middleware implements Authorisation and Resource 
server functionality.  It includes support for basic bearer tokens and also 
a customisation - X.509 certificates as access tokens - for use with an SLCS
(Short-lived Credential Service)
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

from ndg.oauth.server.lib.access_token.bearer_token_generator import \
    BearerTokenGenerator
from ndg.oauth.server.lib.authenticate.certificate_authenticator \
    import CertificateAuthenticator
from ndg.oauth.server.lib.authenticate.noop_authenticator import \
    NoopAuthenticator
from ndg.oauth.server.lib.authenticate.password_authenticator \
    import PasswordAuthenticator
from ndg.oauth.server.lib.authorization_server import AuthorizationServer
from ndg.oauth.server.lib.authorize.authorizer_storing_identifier import \
    AuthorizerStoringIdentifier
from ndg.oauth.server.lib.register.client import ClientRegister
from ndg.oauth.server.lib.register.resource import ResourceRegister

log = logging.getLogger(__name__)


class Oauth2ServerMiddleware(object):
    """
    WSGI OAuth 2.0 server implements Authorisation and Resource server functions
    
    Requires:
    o Beaker session
    o An authentication provider that sets the user's ID in the environ, e.g.,
      repose.who
    o MyProxyClientMiddleware (ONLY required for X.509 cert based token
      generation used with SLCS config)
    o Middleware to set user's decisions for authorization of OAuth clients in
      the environ, e.g., ndg.oauth.server.wsgi.authorization_filter.
    """
    PARAM_PREFIX = 'oauth2server.'
    CERT_DN_ENVIRON_KEY = 'SSL_CLIENT_S_DN'
    
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
    RESOURCE_AUTHENTICATION_METHOD_OPTION = 'resource_authentication_method'
    RESOURCE_REGISTER_OPTION = 'resource_register'
    USER_IDENTIFIER_KEY_OPTION = 'user_identifier_key'
    USER_IDENTIFIER_GRANT_DATA_KEY = 'user_identifier'

    AUTHORISATION_SERVER_ENVIRON_KEYNAME = \
                                        'ndg.oauth.server.authorisation.server'
    
    # Configuration option defaults
    PROPERTY_DEFAULTS = {
        ACCESS_TOKEN_LIFETIME_OPTION: 86400,
        ACCESS_TOKEN_TYPE_OPTION: 'bearer',
        AUTHORIZATION_GRANT_LIFETIME_OPTION: 600,
        BASE_URL_PATH_OPTION: '',
        CERTIFICATE_REQUEST_PARAMETER_OPTION: 'certificate_request',
        CLIENT_AUTHENTICATION_METHOD_OPTION: 'certificate',
        CLIENT_AUTHORIZATION_URL_OPTION: '/client_authorization/authorize',
        CLIENT_AUTHORIZATIONS_KEY_OPTION: 'client_authorizations',
        RESOURCE_AUTHENTICATION_METHOD_OPTION: 'none',
        USER_IDENTIFIER_KEY_OPTION: 'REMOTE_USER'
    }
    method = {
        '/access_token': 'access_token',
        '/authorize': 'authorize',
        '/check_token': 'check_token',
        '/request_certificate': 'request_certificate'
    }

    def __init__(self, app, app_conf, prefix=PARAM_PREFIX, **local_conf):
        """
        Sets up the server depending on the configuration.

        :type app: WSGI application
        :param app: wrapped application/middleware

        :type app_conf: dict
        :param app_conf: application configuration settings - ignored - this
        method includes this arg to fit Paste middleware / app function 
        signature

        @:type prefix: str
        :param prefix: optional prefix for parameter names included in the 
        local_conf dict - enables these parameters to be filtered from others
        which don't apply to this middleware

        :type local_conf: dict
        :param local_conf: attribute settings to apply
        """
        self._app = app
        conf = self._set_configuration(prefix, local_conf)

        if self.access_token_type == 'bearer':
            # Simple bearer token configuration.
            access_token_generator = BearerTokenGenerator(
                                        self.access_token_lifetime_seconds, 
                                        self.access_token_type)
        else:
            raise ValueError("Invalid configuration value %s for %s" %
                             (self.access_token_type,
                              self.ACCESS_TOKEN_TYPE_OPTION))
            
        # Store user identifier with grant - this isn't needed for the OAuth
        # protocol but is needed to return certificates using MyProxy.
        authorizer = AuthorizerStoringIdentifier(
            self.authorization_grant_lifetime_seconds,
            user_identifier_env_key=self.user_identifier_env_key,
            user_identifier_grant_data_key=self.USER_IDENTIFIER_GRANT_DATA_KEY)

        # Determine client authentication type. A 'none' options is allowed so
        # that development/testing can be performed without running on Apache.
        client_register = ClientRegister(self.client_register_file)
        client_authenticator = self._get_authenticator(
            self.client_authentication_method, client_register,
            'client', self.CLIENT_AUTHENTICATION_METHOD_OPTION)

        # same for resource authentication type.
        resource_register = ResourceRegister(self.resource_register_file)
        resource_authenticator = self._get_authenticator(
            self.resource_authentication_method, resource_register,
            'resource', self.RESOURCE_AUTHENTICATION_METHOD_OPTION)

        self._authorization_server = AuthorizationServer(
            client_register, authorizer, client_authenticator,
            resource_register, resource_authenticator,
            access_token_generator, conf)

    def _get_authenticator(self, name, register, typ, option_name):
        """Returns new authenticator by name"""
        if name == 'certificate':
            return CertificateAuthenticator(typ, register)
            
        elif name == 'password':
            return PasswordAuthenticator(typ, register)
            
        elif name == 'none':
            return NoopAuthenticator(typ)
            
        else:
            raise ValueError("Invalid configuration value %s for %s" %
                             (name, option_name))

    def __call__(self, environ, start_response):
        """
        :type environ: dict
        :param environ: WSGI environment

        :type start_response: WSGI start response function
        :param start_response: start response function

        :rtype: iterable
        :return: WSGI response
        """
        log.debug("Oauth2ServerMiddleware.__call__ ...")
        req = Request(environ)
        log.debug("Request path_info: %s", req.path_info)

        # Set Authorisation Server as key in environ for access by downstream
        # middleware or app.  For example, a resource server can use it to 
        # check access tokens presented to it from clients against ones issued
        # by the authorisation server
        environ[self.__class__.AUTHORISATION_SERVER_ENVIRON_KEYNAME
                ] = self._authorization_server
                
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
                           [('Content-type', 'text/plain; charset=utf-8'),
                            ('Content-length', str(len(response)))
                            ])
            return [response]

    def authorize(self, req, start_response):
        """Handles OAuth 2 authorize request.
        :type req: webob.Request
        :param req: HTTP request object

        :type start_response: WSGI start response function
        :param start_response: start response function

        :rtype: iterable
        :return: WSGI response
        """
        # Stop immediately if the client is not registered.
        (error, error_description
                        ) = self._authorization_server.is_registered_client(req)
        if error:
            log.debug("Error checking if client registered: %s - %s", error,
                      error_description)
            return self._error_response(error, error_description,
                                        start_response)

        # User authentication is required before authorization can proceed.
        user = req.environ.get(self.user_identifier_env_key)
        if not user:
            log.debug("%s not in environ - authentication required",
                      self.user_identifier_env_key)
            start_response(self._get_http_status_string(httplib.UNAUTHORIZED), 
                           [])
            return []

        # User authorization for the client is also required.
        client_authorized, authz_uri = self._check_client_authorization(user, 
                                                                        req)
        if authz_uri:
            log.debug("Redirecting to %s", authz_uri)
            return self._redirect(authz_uri, start_response)

        if not client_authorized:
            log.debug("User has declined authorization for client.")

        # Parameters should only be taken from the query string.
        params = req.GET

        # Check for consistency
        (error, 
         error_description) = self.__class__.check_authorization_request(req, 
                                                                         params)
        if error:
            return self._error_response(error, 
                                        error_description, 
                                        start_response)

        # Request authorization grant or for Implicit Grant flow
        (redirect_uri, 
         error, 
         error_description) = self._authorization_server.authorize(
                                params.get('response_type', None),
                                params.get('client_id', None),
                                client_authorized,
                                user,
                                redirect_uri=params.get('redirect_uri', None),
                                scope=params.get('scope', None),
                                state=params.get('state', None))
        if error:
            return self._error_response(error, 
                                        error_description, 
                                        start_response)

        return self._redirect(redirect_uri, start_response)
        
    @staticmethod
    def check_request(request, params, post_only=False):
        """
        Checks that the request is valid in the following respects:
        o Must be over HTTPS.
        o Optionally, must use the POST method.
        o Parameters must not be repeated.
        If the request is directly from the client, the user must be
        authenticated - it is assumed that the caller has checked this.

        :type request: webob.Request
        :param request: HTTP request object

        :type params: dict
        :param params: request parameters

        :type post_only: bool
        :param post_only: True if the HTTP method must be POST, otherwise False

        :rtype tuple:
        :return: tuple containing error code and error message.  Both are set to
        None if no error occurred.
        """
        if request.scheme != 'https':
            return ('invalid_request', 
                    'Transport layer security must be used for this request.')

        if post_only and request.method != 'POST':
            return ('invalid_request', 
                    'HTTP POST method must be used for this request.')

        # Check for duplicate parameters.
        param_counts = {}
        for key in params.iterkeys():
            count = param_counts.get(key, 0)
            param_counts[key] = count + 1

        for key, count in param_counts.iteritems():
            if count > 1:
                return ('invalid_request', 'Parameter "%s" is repeated.' % key)
            
        return None, None

    @classmethod
    def check_access_token_request(cls, request, params, post_only=False):
        '''Check validity of access token request syntax and transport scheme
        
        :type request: webob.Request
        :param request: HTTP request object

        :type params: dict
        :param params: request parameters

        :type post_only: bool
        :param post_only: True if the HTTP method must be POST, otherwise False

        :rtype tuple:
        :return: tuple containing error code and error message.  Both are set to
        None if no error occurred.
        '''
        error_code, error_description = cls.check_request(request, params, 
                                                          post_only=False)
        if error_code:
            return error_code, error_description
        else:            
            # redirect_uri is only required if it was included in the 
            # authorization request.
            required_parameters = ['grant_type', 'code']
            missing_parameters = []
            for param in required_parameters:
                if param not in params:
                    log.error("Missing request parameter %s from inputs: %s",
                              param, params)
                    missing_parameters.append(param)
            
            if len(missing_parameters):
                return ('invalid_request', "Missing request parameter(s): %s" % 
                        missing_parameters)
            else:
                return None, None
            
    @classmethod
    def check_authorization_request(cls, request, params, post_only=False):
        '''Check validity of authorization request syntax and transport scheme
        
        :type request: webob.Request
        :param request: HTTP request object

        :type params: dict
        :param params: request parameters

        :type post_only: bool
        :param post_only: True if the HTTP method must be POST, otherwise False

        :rtype tuple:
        :return: tuple containing error code and error message.  Both are set to
        None if no error occurred.
        '''
        error_code, error_description = cls.check_request(request, params, 
                                                          post_only=False)
        if error_code:
            return error_code, error_description
        else:
            # Check for required parameters.
            required_parameters = ['response_type', 'client_id']
            missing_parameters = []
            for param in required_parameters:
                if param not in params:
                    log.error("Missing request parameter %s from params: %s",
                              param, params)
                    missing_parameters.append(param)
            
            if len(missing_parameters):
                return ('invalid_request', "Missing request parameter(s): %s" % 
                        missing_parameters)
            else:
                return None, None
                
    def _error_response(self, error, error_description, start_response):
        """Returns and error response.
        """
        response = ("%s: %s" % (error, error_description)).encode('ascii',
                                                                  'ignore')
        log.error("Returning error: %s - %s", error, error_description)
        start_response(self._get_http_status_string(httplib.BAD_REQUEST),
                       [('Content-type', 'text/plain; charset=utf-8'),
                        ('Content-length', str(len(response)))
                        ])
        return[response]

    def _check_client_authorization(self, user, req):
        """
        Gets the URL to which to redirect for the user to authorize the client.
        Returns: URL or None if already authorized
        :type user: str
        :param user: identifier of user/resource owner

        :type req: webob.Request
        :param req: HTTP request object
        """
        client_authorizations = req.environ.get(
                                            self.client_authorizations_env_key)
        client_id = req.params.get('client_id')
        scope = req.params.get('scope')
        if not client_authorizations:
            client_authorized = None
            log.debug("Client authorization register not found in environ "
                      "(key %s).", self.client_authorizations_env_key)
        else:
            client_authorized = \
                client_authorizations.is_client_authorized_by_user(user, 
                                                                   client_id, 
                                                                   scope)
        if client_authorized is None:
            log.debug("Client not authorized by user (client_id: %s  scope: %s"
                      "  user: %s).", client_id, scope, user)
            
            url_params = {'client_id': client_id,
                          'scope': scope,
                          'user': user,
                          'original_url': req.url}
            url = ("%s?%s" % (self._make_client_authorization_url(req),
                              urllib.urlencode(url_params)))
            return (None, url)
        
        return client_authorized, None

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
        :type req: webob.Request
        :param req: HTTP request object

        :type start_response: 
        :param start_response: WSGI start response function

        :rtype: iterable
        :return: WSGI response
        """
        log.debug("access_token called")
        
        # Parameters should only be taken from the body, not the URL query 
        # string.
        params = req.POST
        self.__class__.check_access_token_request(req, params, post_only=True)

        (response, 
         error_status, 
         error_description) = self._authorization_server.access_token(params,
                                                                      req.headers)
        if response is None:
            response = ''
            
        headers = [
            ('Content-Type', 'application/json; charset=UTF-8'),
            ('Cache-Control', 'no-store'),
            ('Content-length', str(len(response))),
            ('Pragma', 'no-store')
        ]
        
        if error_status == 401:
            # Add Basic Auth challenge header
            headers += [('WWW-Authenticate', 'Basic realm="%s"' % 'oauth2')]
            
        status_str = self._get_http_status_string(
                                error_status if error_status else httplib.OK)
        if error_status:
            log.debug("Error obtaining access token: %s - %s", status_str,
                      error_description)

        ##################
        # FIXME:
        status_str = '401 Unauthorized'
        start_response(status_str, headers)
        return [response]

    def check_token(self, req, start_response):
        """
        Service to validate bearer tokens. It would be called from a resource
        service that trusts this authorization service.
        :type req: webob.Request
        :param req: HTTP request object

        :type start_response: 
        :param start_response: WSGI start response function

        :rtype: iterable
        :return: WSGI response
        """
        response, error_status = self._authorization_server.check_token(
                                                                    req)[0:2]
        if response is None:
            response = ''
        headers = [
            ('Content-Type', 'application/json; charset=UTF-8'),
            ('Cache-Control', 'no-store'),
            ('Content-length', str(len(response))),
            ('Pragma', 'no-store')
        ]
        status_str = self._get_http_status_string(
                                error_status if error_status else httplib.OK)

        start_response(status_str, headers)
        return [response]

    @staticmethod
    def _get_http_status_string(status):
        return ("%d %s" % (status, httplib.responses[status]))

    def _redirect(self, url, start_response):
        """Initiates a redirect to a specified URL.
        :type param: str
        :param url: URL

        :type start_response: 
        :param start_response: WSGI start response function

        :rtype: iterable
        :return: WSGI response
        """
        log.debug("Redirecting to %s", url)
        start_response(self._get_http_status_string(httplib.FOUND),
               [('Location', url.encode('ascii', 'ignore'))])
        return []

    def _set_configuration(self, prefix, local_conf):
        """Sets the configuration values.

        :type prefix: str
        :param prefix: optional prefix for parameter names included in the
        local_conf dict - enables these parameters to be filtered from others
        which don't apply to this middleware

        :type local_conf: dict
        :param local_conf: attribute settings to apply
        """
        conf = {}
        plen = len(prefix)
        for k, v in local_conf.iteritems():
            if k.startswith(prefix):
                conf[k[plen:]] = v
        cls = self.__class__
        
        self.base_path = cls._get_config_option(conf, cls.BASE_URL_PATH_OPTION)
        self.authorization_grant_lifetime_seconds = cls._get_config_option(
                                conf, cls.AUTHORIZATION_GRANT_LIFETIME_OPTION)
        self.access_token_lifetime_seconds = cls._get_config_option(
                                conf, cls.ACCESS_TOKEN_LIFETIME_OPTION)
        self.access_token_type = cls._get_config_option(
                                conf, cls.ACCESS_TOKEN_TYPE_OPTION)
        self.certificate_request_parameter = cls._get_config_option(
                                conf, cls.CERTIFICATE_REQUEST_PARAMETER_OPTION)
        self.client_authorization_url  = cls._get_config_option(
                                conf, cls.CLIENT_AUTHORIZATION_URL_OPTION)
        self.client_authentication_method  = cls._get_config_option(
                                conf, cls.CLIENT_AUTHENTICATION_METHOD_OPTION)
        self.client_authorizations_env_key = cls._get_config_option(
                                conf, cls.CLIENT_AUTHORIZATIONS_KEY_OPTION)
        self.client_register_file = cls._get_config_option(
                                conf, cls.CLIENT_REGISTER_OPTION)
        self.resource_authentication_method = cls._get_config_option(
                                conf, cls.RESOURCE_AUTHENTICATION_METHOD_OPTION)
        self.resource_register_file = cls._get_config_option(
                                conf, cls.RESOURCE_REGISTER_OPTION)
        self.user_identifier_env_key = cls._get_config_option(
                                conf, cls.USER_IDENTIFIER_KEY_OPTION)
        
        # Return any options that start with the prefix but haven't been read
        # above.
        return conf

    @classmethod
    def _get_config_option(cls, conf, key):
        value = conf.pop(key, cls.PROPERTY_DEFAULTS.get(key, None))
        log.debug("Oauth2ServerMiddleware configuration %s=%s", key, value)
        return value

    @classmethod
    def filter_app_factory(cls, app, app_conf, **local_conf):
        return cls(app, app_conf, **local_conf)

    @classmethod
    def app_factory(cls, app_conf, **local_conf):
        return cls(None, app_conf, **local_conf)

