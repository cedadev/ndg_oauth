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

from ndg.httpsclient.ssl_context_util import SSlContextConfig
from ndg.oauth.client.lib.oauth2client import Oauth2Client
from ndg.oauth.client.lib.oauth2client import Oauth2ClientConfig
from ndg.oauth.client.lib.oauth2_myproxy_client import Oauth2MyProxyClient
from ndg.oauth.client.lib.render.configuration import RenderingConfiguration
from ndg.oauth.client.lib.render.factory import callModuleObject
from ndg.oauth.client.lib.render.renderer_interface import RendererInterface

log = logging.getLogger(__name__)


class Oauth2ClientMiddlewareSessionError(Exception):
    """Missing beaker session key"""
    
    
class Oauth2ClientMiddlewareConfigOptError(Exception):
    """Error with Config option"""
    
    
class Oauth2ClientMiddleware(object):
    """
    OAuth 2.0 client middleware that sets an access token in the WSGI environ.
    """
    PARAM_PREFIX = 'oauth2.'
    LAYOUT_PREFIX = 'layout.'
    ACCESS_TOKEN_TYPE_OPTION = 'access_token_type'
    AUTHENTICATION_TRIGGER_OPTION = 'authentication_trigger'
    AUTHENTICATION_TRIGGER_ALWAYS = 'always'
    AUTHENTICATION_TRIGGER_UNAUTHORIZED = 'unauthorized'
    AUTHENTICATION_TRIGGER_URL = 'url'
    AUTHENTICATION_TRIGGER_OPTIONS = [AUTHENTICATION_TRIGGER_ALWAYS,
                                      AUTHENTICATION_TRIGGER_UNAUTHORIZED,
                                      AUTHENTICATION_TRIGGER_URL]
    AUTHENTICATION_URL_OPTION = 'authentication_url'
    AUTHENTICATION_COMPLETE_OPTION = 'login_complete'
    BASE_URL_PATH_OPTION = 'base_url_path'
    CERTIFICATE_REQUEST_PARAMETER_OPTION = 'certificate_request_parameter'
    REDIRECT_URI = 'oauth_redirect'
    RENDERER_CLASS_OPTION = 'renderer_class'
    SCOPE_OPTION = 'scope'
    SESSION_KEY_OPTION = 'session_key'
    SESSION_CALL_CONTEXT_KEY = 'oauth2_call_context'
    TOKEN_KEY_OPTION = 'oauth2_token_key'
    CLIENT_CERT_OPTION = 'client_cert'
    CLIENT_KEY_OPTION = 'client_key'
    CA_CERT_FILE_OPTION = 'ca_cert_file'
    CA_DIR_OPTION = 'ca_dir'
    CLIENT_ID_OPTION = 'client_id'
    AUTHORIZATION_ENDPOINT_OPTION = 'authorization_endpoint'
    ACCESS_TOKEN_ENDPOINT_OPTION = 'access_token_endpoint'
    
    propertyDefaults = {
        ACCESS_TOKEN_TYPE_OPTION: 'bearer',
        AUTHENTICATION_COMPLETE_OPTION: '',
        AUTHENTICATION_TRIGGER_OPTION: AUTHENTICATION_TRIGGER_ALWAYS,
        AUTHENTICATION_URL_OPTION: 'oauth_authenticate',
        BASE_URL_PATH_OPTION: '',
        CERTIFICATE_REQUEST_PARAMETER_OPTION: 'certificate_request',
        RENDERER_CLASS_OPTION: 'ndg.oauth.client.lib.render.genshi_renderer.GenshiRenderer',
        SCOPE_OPTION: '',
        SESSION_KEY_OPTION: 'beaker.session.oauth2client',
        TOKEN_KEY_OPTION: 'oauth2client.token',
    }
    LAYOUT_PARAMETERS = ['heading',
                         'title',
                         'message',
                         'leftLogo',
                         'leftAlt',
                         'leftImage',
                         'leftLink',
                         'rightAlt',
                         'rightImage',
                         'rightLink',
                         'footerText',
                         'helpIcon',
                         'client_id',
                         'client_name',
                         'scope']

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
        if self.access_token_type == 'slcs':
            log.debug("Setting client as Oauth2MyProxyClient (SLCS)")
            self._oauth_client_class = Oauth2MyProxyClient
            self._token_retriever_class = MyProxyTokenRetriever
        else:
            log.debug("Setting client as Oauth2Client (Bearer token)")
            self._oauth_client_class = Oauth2Client
            self._token_retriever_class = TokenRetriever

        self._renderingConfiguration = RenderingConfiguration(
                                                    self.LAYOUT_PARAMETERS,
                                                    prefix + self.LAYOUT_PREFIX,
                                                    local_conf)
        self.renderer = callModuleObject(self.renderer_class,
                                         objectName=None, moduleFilePath=None, 
                                         objectType=RendererInterface,
                                         objectArgs=None, objectProperties=None)

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
        log.debug("Request url: %s", req.url)
        log.debug("Request host_url: %s", req.host_url)
        log.debug("Request application_url: %s", req.application_url)
        is_redirect_back = False
        
        original_environ = {'PATH_INFO': environ['PATH_INFO'],
                            'QUERY_STRING': environ['QUERY_STRING'],
                            'SCRIPT_NAME': environ['SCRIPT_NAME'],
                            'url': req.url}

        # Get session.
        session = environ.get(self.session_env_key)
        if session is None:
            raise Oauth2ClientMiddlewareSessionError(
                'Oauth2ClientMiddleware.__call__: No beaker session key '
                '"%s" found in environ' % self.session_env_key)

        # Determine trigger for starting authentication process.
        authenticate_before_delegating = False
        authenticate_on_unauthorized = False
        is_authentication_url = (environ['PATH_INFO'].strip('/') ==
                                                        self.authentication_url)
        if (self.authentication_trigger ==
            self.__class__.AUTHENTICATION_TRIGGER_ALWAYS):
            authenticate_before_delegating = True
            
        elif (self.authentication_trigger ==
              self.__class__.AUTHENTICATION_TRIGGER_URL):
            
            if is_authentication_url:
                authenticate_before_delegating = True
                
        elif (self.authentication_trigger ==
              self.__class__.AUTHENTICATION_TRIGGER_UNAUTHORIZED):
            authenticate_on_unauthorized = True

        # Check whether redirecting back after requesting authorization.
        redirect_url = None
        if self.client_config.is_redirect_uri(req.application_url, req.url):
            log.debug("Redirected back after requesting authorization.")
            is_redirect_back = True
            token = self._get_token_after_redirect(session, req)
            original_environ = session[self.__class__.SESSION_CALL_CONTEXT_KEY]
        else:
            # Start the OAuth2 transaction to get a token.
            log.debug("Starting OAuth2 protocol")
            (token, redirect_url) = self._get_token(session,
                                                    req.application_url)
            if authenticate_before_delegating and redirect_url:
                session[self.__class__.SESSION_CALL_CONTEXT_KEY
                                                            ] = original_environ
                session.save()
                log.debug("Redirecting to %s", redirect_url)
                start_response(self._get_http_status_string(httplib.FOUND),
                               [('Location', redirect_url)])
                return []

        local_start_response = start_response
        if token:
            log.debug("Setting token in environ[%s]=%s", self.token_env_key,
                      token)
            environ[self.token_env_key] = token
            
        elif authenticate_on_unauthorized and redirect_url:
            def local_start_response(status, response_headers, exc_info=None):
                status_code = status.split(' ')[0]
                log.debug("Response HTTP status %s", status_code)
                if status_code == str(httplib.UNAUTHORIZED):
                    session[self.__class__.SESSION_CALL_CONTEXT_KEY
                                                            ] = original_environ
                    session.save()
                    log.debug("Redirecting to %s", redirect_url)
                    start_response(self._get_http_status_string(httplib.FOUND),
                                   [('Location', redirect_url)])
                    return []
                else:
                    return start_response(status, response_headers, exc_info)

        if is_authentication_url:
            c = {'baseURL': req.application_url}
            response = self.renderer.render(self.authentication_complete,
                            self._renderingConfiguration.merged_parameters(c))
            
            start_response(self._get_http_status_string(httplib.OK),
               [('Content-type', 'text/html'),
                ('Content-length', str(len(response)))
                ])
            
            return [response]

        # Ensure that the URL is that prior to authentication redirection.
        if is_redirect_back:
            original_url = original_environ['url']
            log.debug("Redirecting to %s", original_url)
            start_response(self._get_http_status_string(httplib.FOUND),
                           [('Location', original_url)])
            return []

        app_iter = self._app(environ, local_start_response)
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
        self.access_token_type = cls._get_config_option(prefix, local_conf,
                                                cls.ACCESS_TOKEN_TYPE_OPTION)
        self.authentication_complete = cls._get_config_option(prefix,
                                local_conf, cls.AUTHENTICATION_COMPLETE_OPTION)
        
        self.authentication_trigger = cls._get_config_option(
                prefix, local_conf, cls.AUTHENTICATION_TRIGGER_OPTION).lower()
                
        if self.authentication_trigger not in cls.AUTHENTICATION_TRIGGER_OPTIONS:
            raise Oauth2ClientMiddlewareConfigOptError(
                        "Illegal value for %s option; expected one of %s" %
                        self.authentication_trigger_str,
                        cls.AUTHENTICATION_TRIGGER_OPTIONS)
            
        self.authentication_url = cls._get_config_option(
                prefix, local_conf, cls.AUTHENTICATION_URL_OPTION).strip('/')
                
        self.renderer_class = cls._get_config_option(prefix, local_conf, 
                                                     cls.RENDERER_CLASS_OPTION)
        self.scope = cls._get_config_option(prefix, local_conf, 
                                            cls.SCOPE_OPTION)
        self.session_env_key = cls._get_config_option(prefix, local_conf, 
                                                      cls.SESSION_KEY_OPTION)
        self.token_env_key = self._get_config_option(prefix, local_conf, 
                                                     cls.TOKEN_KEY_OPTION)

        # SSL configuration
        client_cert = cls._get_config_option(prefix, local_conf, 
                                             cls.CLIENT_CERT_OPTION)
        client_key = cls._get_config_option(prefix, local_conf, 
                                            cls.CLIENT_KEY_OPTION)
        ca_cert_file = cls._get_config_option(prefix, local_conf, 
                                              cls.CA_CERT_FILE_OPTION)
        ca_dir = cls._get_config_option(prefix, local_conf, cls.CA_DIR_OPTION)
        self.ssl_config = SSlContextConfig(client_key, client_cert,
                                           ca_cert_file, ca_dir, True)

        # OAuth client configuration
        certificate_request_parameter = cls._get_config_option(prefix, 
                                    local_conf, 
                                    cls.CERTIFICATE_REQUEST_PARAMETER_OPTION)
        client_id = cls._get_config_option(prefix, local_conf, 
                                           cls.CLIENT_ID_OPTION)
        authorization_endpoint = cls._get_config_option(prefix, local_conf, 
                                            cls.AUTHORIZATION_ENDPOINT_OPTION)
        access_token_endpoint = cls._get_config_option(prefix, local_conf, 
                                            cls.ACCESS_TOKEN_ENDPOINT_OPTION)
        base_url_path = cls._get_config_option(prefix, local_conf, 
                                            cls.BASE_URL_PATH_OPTION)
        
        redirect_uri = cls.REDIRECT_URI
        
        self.client_config = Oauth2ClientConfig(
            client_id, authorization_endpoint, access_token_endpoint,
            base_url_path, redirect_uri,
            certificate_request_parameter=certificate_request_parameter)

    @classmethod
    def _get_config_option(cls, prefix, local_conf, key):
        value = local_conf.get(prefix + key, 
                               cls.propertyDefaults.get(key, None))
        log.debug("Oauth2ClientMiddleware configuration %s=%s", key, value)
        return value

    @staticmethod
    def _get_http_status_string(status):
        return ("%d %s" % (status, httplib.responses[status]))

    @classmethod
    def filter_app_factory(cls, app, app_conf, **local_conf):
        return cls(app, app_conf, **local_conf)

    def _get_token(self, session, application_url):
        """Gets a token using the OAuth2 client.
        @type session: Beaker SessionObject
        @param session: session
        @type application_url: str
        @param application_url: application base part of request URL
        @rtype: tuple (
            result type of callback or None
            str or None
        )
        @return: (
            result of callback or None if a redirect is needed
            redirect URI if redirect needed or None
        """
        client = self._oauth_client_class.get_client_instance(session,
                                                self.client_config, create=True)

        callback = self._token_retriever_class(client)

        (result, redirect_url) = client.call_with_access_token(
            self.scope, application_url, callback)
        session.save()

        return (result, redirect_url)

    def _get_token_after_redirect(self, session, req):
        """Gets a token using the OAuth2 client - to be called after a redirect
        has occurred from the OAuth authorization server.
        @type session: Beaker SessionObject
        @param session: session
        @rtype: result type of callback
        @return: result of callback
        """
        client = self._oauth_client_class.get_client_instance(session,
                                                            self.client_config)
        if client:
            # Return callback result.
            callback = self._token_retriever_class(client)
            result = client.call_with_access_token_redirected_back(req,
                                                                callback,
                                                                self.ssl_config)
            # Save client state, which includes the token.
            session.save()
            # Save only marks the session for persistence at the end of the HTTP
            # transaction. Persist now so that it is available if a new request
            # is made from nested middleware.
            session.persist()

            return result
        else:
            raise Oauth2ClientMiddlewareSessionError("No OAuth client created "
                                                     "for session.")


class TokenRetriever(object):
    def __init__(self, client):
        self.client = client

    def __call__(self, access_token, error, error_description):
        """
        Returns authorization token.
        @type access_token: type of access token
        @param access_token: access token
        @type error: str
        @param error: OAuth error string
        @type error_description: str
        @param error_description: error description
        @rtype: type of access token
        @return: access token
        """
        if error:
            return None
        return self.client.access_token

class MyProxyTokenRetriever(object):
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
            return None
#            return ("", ("Token not available because of error: %s - %s" % (error, error_description)))
        return (self.client.private_key, self.client.access_token)
