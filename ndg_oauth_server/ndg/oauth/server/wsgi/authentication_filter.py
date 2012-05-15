"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "07/03/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import httplib
import logging
import urllib
import urlparse

from repoze.who.api import get_api
from webob import Request

from ndg.oauth.server.lib.register.client import ClientRegister
from ndg.oauth.server.lib.register.client_authorization import (
                            ClientAuthorization, ClientAuthorizationRegister)
from ndg.oauth.server.lib.render.configuration import RenderingConfiguration
from ndg.oauth.server.lib.render.factory import callModuleObject
from ndg.oauth.server.lib.render.renderer_interface import RendererInterface

log = logging.getLogger(__name__)

class AuthenticationFormMiddleware(object):
    """Middleware to display a login form and handle the response.
    """
    CLIENT_AUTHORIZATIONS_SESSION_KEY = 'oauth2_client_authorizations'
    PARAM_PREFIX = 'authenticationForm.'
    LAYOUT_PREFIX = 'layout.'
    # Configuration options
    AUTHENTICATION_CANCELLED_OPTION = 'login_cancelled'
    AUTHENTICATION_FORM_OPTION = 'login_form'
    BASE_URL_PATH_OPTION = 'base_url_path'
    CLIENT_REGISTER_OPTION = 'client_register'
    COMBINED_AUTHORIZATION_OPTION = 'combined_authorization'
    RENDERER_CLASS_OPTION = 'renderer_class'
    RETURN_URL_PARAM_OPTION = 'return_url_param'
    SESSION_KEY_OPTION = 'session_key_name'
    method = {
        '/login_form': 'login_form',
        '/login': 'login'
    }
    # Configuration option defaults
    propertyDefaults = {
        BASE_URL_PATH_OPTION: '/authentication',
        COMBINED_AUTHORIZATION_OPTION: 'True',
        RENDERER_CLASS_OPTION: 'ndg.oauth.server.lib.render.genshi_renderer.GenshiRenderer',
        RETURN_URL_PARAM_OPTION: 'returnurl',
        SESSION_KEY_OPTION: 'beaker.session.oauth2authorization'
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

    def __init__(self, app, app_conf, prefix=PARAM_PREFIX, **local_conf):
        """
        Sets up the server depending on the configuration.

        @type app: WSGI application
        @param app: wrapped application/middleware

        @type app_conf: dict
        @param app_conf: application configuration settings - ignored - this
        method includes this arg to fit Paste middleware / app function 
        signature

        @type prefix: str
        @param prefix: optional prefix for parameter names included in the 
        local_conf dict - enables these parameters to be filtered from others
        which don't apply to this middleware

        @type local_conf: dict
        @param local_conf: attribute settings to apply
        """
        self._app = app
        self._renderingConfiguration = RenderingConfiguration(
                                                    self.LAYOUT_PARAMETERS,
                                                    prefix + self.LAYOUT_PREFIX,
                                                    local_conf)
        self._set_configuration(prefix, local_conf)
        self.client_register = ClientRegister(self.client_register_file)
        self.renderer = callModuleObject(self.renderer_class,
                                         objectName=None, moduleFilePath=None, 
                                         objectType=RendererInterface,
                                         objectArgs=None, objectProperties=None)

    def __call__(self, environ, start_response):
        """
        @type environ: dict
        @param environ: WSGI environment

        @type start_response: 
        @param start_response: WSGI start response function

        @rtype: iterable
        @return: WSGI response
        """
        log.debug("AuthenticationFormMiddleware.__call__ ...")

        req = Request(environ)

        # Get session.
        session = environ.get(self.session_env_key)
        if session is None:
            raise Exception(
                'AuthenticationFormMiddleware.__call__: No beaker session key '
                '"%s" found in environ' % self.session_env_key)

        # Determine what operation the URL specifies.
        actionPath = None
        log.debug("Request path_info: %s", req.path_info)
        if req.path_info.startswith(self.base_path):
            actionPath = req.path_info[len(self.base_path):]
        methodName = self.__class__.method.get(actionPath, '')
        if methodName:
            log.debug("Method: %s" % methodName)
            action = getattr(self, methodName)
            return action(req, session, start_response)
        elif self._app is not None:
            log.debug("Delegating to lower filter/application.")
            return self._app(environ, start_response)
        else:
            response = "OAuth 2.0 Authentication Filter - Invalid URL"
            start_response(self._get_http_status_string(httplib.NOT_FOUND),
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))
                            ])
            return [response]

    def login_form(self, req, session, start_response):
        """Displays the login form.

        @type req: webob.Request
        @param req: HTTP request object

        @type session: Beaker SessionObject
        @param session: session data

        @type start_response: 
        @param start_response: WSGI start response function

        @rtype: iterable
        @return: WSGI response
        """
        submit_url = req.application_url + self.base_path + '/login'
        return_url = req.params.get(self.return_url_param)
        c = {'return_url': return_url,
             'return_url_param': self.return_url_param,
             'submit_url': submit_url,
             'baseURL': req.application_url}

        # Include authorization details on form if authentication and
        # authorization are to be combined.
        if self.combined_authorization:
            c.update(self._parse_return_url(return_url))

        response = self.renderer.render(self.authentication_form,
                            self._renderingConfiguration.merged_parameters(c))
        start_response(self._get_http_status_string(httplib.OK),
           [('Content-type', 'text/html'),
            ('Content-length', str(len(response)))
            ])
        return [response]

    def login(self, req, session, start_response):
        """Handles submission of the login form.

        @type req: webob.Request
        @param req: HTTP request object

        @type session: Beaker SessionObject
        @param session: session data

        @type start_response: 
        @param start_response: WSGI start response function

        @rtype: iterable
        @return: WSGI response
        """
        if ('submit' in req.params) and ('cancel' not in req.params):
            username = req.params.get('username')
            password = req.params.get('password')
            credentials = {'login': username, 'password': password}
            repoze_who_api = get_api(req.environ)
            (identity, headers) = repoze_who_api.login(credentials)
            if identity is not None:
                logged_in_username = identity['repoze.who.userid']
                log.debug("Logged in using username %s as %s", username,
                          logged_in_username)
    
                if self.combined_authorization:
                    self._set_client_authorization(req, session,
                                                   logged_in_username)
                return_url = req.params.get(self.return_url_param)
                return self._redirect(return_url, start_response, headers)
            else:
                # Login failed - redirect to login form.
                return_url = req.params.get(self.return_url_param)
                form_url = (req.application_url + self.base_path +
                    '/login_form' + '?' +
                    urllib.urlencode({self.return_url_param: return_url}))
                return self._redirect(form_url, start_response)
        else:
            # User cancelled authentication - confirm this.
            c = {'baseURL': req.application_url}
            response = self.renderer.render(self.authentication_cancelled,
                            self._renderingConfiguration.merged_parameters(c))
            start_response(self._get_http_status_string(httplib.OK),
               [('Content-type', 'text/html'),
                ('Content-length', str(len(response)))
                ])
            return [response]

    def _parse_return_url(self, return_url):
        """Gets client information from the return URL.
        @type return_url: basestring
        @param return_url: return URL
        @rtype: basestring
        @return: String describing client and scope if present
        """
        if not return_url:
            return None
        u = urlparse.urlparse(return_url)
        query_params = urlparse.parse_qs(u.query)
        client_id = query_params.get('client_id', None)
        if client_id:
            client_id = client_id[0]
        scope = query_params.get('scope', None)
        if scope:
            scope = scope[0]
        client = self.client_register.register.get(client_id)
        result = None
        if client:
            result = {'client_name': client.name,
                      'client_id': client.client_id,
                      'scope': scope}
        return result

    def _set_client_authorization(self, req, session, username):
        """Sets the client as authorized.

        @type req: webob.Request
        @param req: HTTP request object

        @type session: Beaker SessionObject
        @param session: session data
        """
        client_authorizations = session.setdefault(
                                self.CLIENT_AUTHORIZATIONS_SESSION_KEY,
                                ClientAuthorizationRegister())
        client_id = req.params.get('client_id')
        scope = req.params.get('scope')
        log.debug(
            "Adding client authorization for client_id: %s  scope: %s  user: %s",
            client_id, scope, username)
        client_authorizations.add_client_authorization(
                        ClientAuthorization(username, client_id, scope, True))
        session[self.CLIENT_AUTHORIZATIONS_SESSION_KEY] = client_authorizations
        log.debug("### client_auth: %s", client_authorizations.__repr__())
        session.save()
        # Make available immediately to chained middleware.
        session.persist()

    def _set_configuration(self, prefix, local_conf):
        """Sets the configuration values.

        @type prefix: str
        @param prefix: optional prefix for parameter names included in the
        local_conf dict - enables these parameters to be filtered from others
        which don't apply to this middleware

        @type local_conf: dict
        @param local_conf: attribute settings to apply
        """
        cls = self.__class__
        self.base_path = cls._get_config_option(prefix, local_conf,
                                                cls.BASE_URL_PATH_OPTION)
        self.client_register_file = cls._get_config_option(prefix, local_conf,
                                                    cls.CLIENT_REGISTER_OPTION)
        combined_authorization = cls._get_config_option(prefix, local_conf,
                                            cls.COMBINED_AUTHORIZATION_OPTION)
        self.combined_authorization = (combined_authorization.lower() == 'true')
        self.renderer_class = cls._get_config_option(prefix, local_conf,
                                                     cls.RENDERER_CLASS_OPTION)
        self.return_url_param = cls._get_config_option(prefix, local_conf,
                                                    cls.RETURN_URL_PARAM_OPTION)
        self.session_env_key = cls._get_config_option(prefix, local_conf,
                                                      cls.SESSION_KEY_OPTION)
        self.authentication_cancelled = cls._get_config_option(prefix,
                                                               local_conf,
                                            cls.AUTHENTICATION_CANCELLED_OPTION)
        self.authentication_form = cls._get_config_option(prefix, local_conf,
                                                cls.AUTHENTICATION_FORM_OPTION)

    @staticmethod
    def _get_http_status_string(status):
        return ("%d %s" % (status, httplib.responses[status]))

    def _redirect(self, url, start_response, headers=[]):
        log.debug("Redirecting to %s", url)
        hdrs = [('Location', url.encode('ascii', 'ignore'))]
        hdrs.extend(headers)
        start_response(self._get_http_status_string(httplib.FOUND), hdrs)
        return []

    @classmethod
    def _get_config_option(cls, prefix, local_conf, key):
        value = local_conf.get(prefix + key,
                               cls.propertyDefaults.get(key,None))
        log.debug("AuthenticationFormMiddleware configuration %s=%s",
                  key, value)
        return value

    @classmethod
    def filter_app_factory(cls, app, app_conf, **local_conf):
        return cls(app, app_conf, **local_conf)
