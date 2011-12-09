import httplib
import logging

from genshi.template import MarkupTemplate
from webob import Request

from ndgoauthserver.lib.register.client import ClientRegister
from ndgoauthserver.lib.register.client_authorization import ClientAuthorization, ClientAuthorizationRegister

log = logging.getLogger(__name__)

class Oauth2AuthorizationMiddleware(object):
    CLIENT_AUTHORIZATIONS_SESSION_KEY = 'oauth2_client_authorizations'
    SESSION_CALL_CONTEXT_KEY = 'oauth2_client_authorizations_context'
    PARAM_PREFIX = 'oauth2authorization.'
    # Configuration options
    BASE_URL_PATH_OPTION = 'base_url_path'
    CLIENT_AUTHORIZATION_FORM_OPTION = 'client_authorization_form'
    CLIENT_AUTHORIZATIONS_KEY_OPTION = 'client_authorizations_key'
    CLIENT_REGISTER_OPTION = 'client_register'
    SESSION_KEY_OPTION = 'session_key_name'
    USER_IDENTIFIER_KEY_OPTION = 'user_identifier_key'
    method = {
        '/authorize': 'authorize',
        '/client_auth': 'client_auth'
    }
    # Configuration option defaults
    propertyDefaults = {
        BASE_URL_PATH_OPTION: 'client_authorization',
        SESSION_KEY_OPTION: 'beaker.session.oauth2authorization',
        CLIENT_AUTHORIZATIONS_KEY_OPTION: 'client_authorizations',
        USER_IDENTIFIER_KEY_OPTION: 'REMOTE_USER'
    }

    def __init__(self, app, app_conf, prefix=PARAM_PREFIX, **local_conf):
        self._app = app
        self._set_configuration(prefix, local_conf)
        self.client_register = ClientRegister(self.client_register_file)

    def __call__(self, environ, start_response):
        log.debug("Oauth2AuthorizationMiddleware.__call__ ...")

        req = Request(environ)

        # Get session.
        session = environ.get(self.session_env_key)
        if session is None:
            raise Exception(
                'Oauth2AuthorizationMiddleware.__call__: No beaker session key '
                '"%s" found in environ' % self.session_env_key)

        # Determine what operation the URL specifies.
        actionPath = None
        if req.path_info.startswith(self.base_path):
            actionPath = req.path_info[len(self.base_path):]
        methodName = self.__class__.method.get(actionPath, '')
        if methodName:
            log.debug("Method: %s" % methodName)
            action = getattr(self, methodName)
            return action(req, session, start_response)
        elif self._app is not None:
            log.debug("Delegating to lower filter/application.")
            self._set_client_authorizations_in_environ(session, environ)
            return self._app(environ, start_response)
        else:
            start_response(self._get_http_status_string(httplib.NOT_FOUND),
                           [('Content-type', 'text/plain')])
            return ["OAuth 2.0 Authorization Filter - Invalid URL"]

    def _set_client_authorizations_in_environ(self, session, environ):
        """
        Sets the current authorizations currently granted by the user in
        environ,
        """
        client_authorizations = session.get(self.CLIENT_AUTHORIZATIONS_SESSION_KEY)
        if client_authorizations:
            log.debug("### _set_client_authorizations_in_environ %s", client_authorizations.__repr__())
            # TODO Should this be a deep copy so that the session copy cannot
            # be modified by other filters?
            environ[self.client_authorizations_env_key] = client_authorizations
        else:
            log.debug("### %s not found in session", self.CLIENT_AUTHORIZATIONS_SESSION_KEY)

    def authorize(self, req, session, start_response):
        """
        Checks whether the user has already authorized the client and if not
        displays the authorization form.
        """
        client_id = req.params.get('client_id')
        scope = req.params.get('scope')
        user = req.params.get('user')
#        user = req.environ.get(self.user_identifier_env_key)
        original_url = req.params.get('original_url')
        log.debug("Client authorization request for client_id: %s  scope: %s  user: %s", client_id, scope, user)

        client_authorizations = session.get(self.CLIENT_AUTHORIZATIONS_SESSION_KEY)
        client_authorized = None
        if client_authorizations:
            client_authorized = client_authorizations.is_client_authorized_by_user(user, client_id, scope)
        if client_authorized is None:
            # No existing decision - let user decide.
            session[self.SESSION_CALL_CONTEXT_KEY] = {
                'original_url': original_url,
                'client_id': client_id,
                'scope': scope,
                'user': user
                }
            session.save()
            log.debug("Client not authorized by user - returning authorization form.")
            return self._client_auth_form(client_id, scope, req, start_response)
        else:
            log.debug("Client already %s authorization by user.", ("granted" if client_authorized else "denied"))
            log.debug("Redirecting to %s", original_url)
            return self._redirect(original_url, start_response)


    def _client_auth_form(self, client_id, scope, req, start_response):
            client = self.client_register.register.get(client_id)
            tmpl_file = open(self.client_authorization_form)
            tmpl = MarkupTemplate(tmpl_file)
            tmpl_file.close()
            submit_url = req.host_url + self.base_path + '/client_auth'
            c = {'client_name': client.name,
                 'client_id': client_id,
                 'scope': scope,
                 'submit_url': submit_url}
            response = tmpl.generate(c=c).render('html')
            start_response(self._get_http_status_string(httplib.OK),
               [('Content-type', 'text/html'),
                ('Content-length', str(len(response)))
                ])
            return [response]

    def client_auth(self, req, session, start_response):
        call_context = session.get(self.SESSION_CALL_CONTEXT_KEY)
        if not call_context:
            log.error("No session context.")
            response = 'Internal server error'
            start_response(self._get_http_status_string(httplib.INTERNAL_SERVER_ERROR),
               [('Content-type', 'text/html'),
                ('Content-length', str(len(response)))
                ])
            return [response]

        if ('yes-button' in req.params) and ('no-button' not in req.params):
            log.debug("User authorized client.")
            granted = True
        else:
            log.debug("User declined authorization for client.")
            granted = False

        # Add authorization to those for the user.
        client_authorizations = session.setdefault(self.CLIENT_AUTHORIZATIONS_SESSION_KEY, ClientAuthorizationRegister())
        client_id = call_context['client_id']
        scope = call_context['scope']
        user = call_context['user']
        log.debug("Adding client authorization for client_id: %s  scope: %s  user: %s", client_id, scope, user)
        client_authorizations.add_client_authorization(ClientAuthorization(user, client_id, scope, granted))
        session[self.CLIENT_AUTHORIZATIONS_SESSION_KEY] = client_authorizations
        log.debug("### client_auth: %s", client_authorizations.__repr__())
        session.save()

        original_url = call_context['original_url']
        log.debug("Redirecting to %s", original_url)
        return self._redirect(original_url, start_response)

    def _set_configuration(self, prefix, local_conf):
        cls = self.__class__
        self.base_path = cls._get_config_option(prefix, local_conf, cls.BASE_URL_PATH_OPTION)
        self.client_register_file = cls._get_config_option(prefix, local_conf, cls.CLIENT_REGISTER_OPTION)
        self.session_env_key = cls._get_config_option(prefix, local_conf, cls.SESSION_KEY_OPTION)
        self.client_authorization_form = cls._get_config_option(prefix, local_conf, cls.CLIENT_AUTHORIZATION_FORM_OPTION)
        self.client_authorizations_env_key = cls._get_config_option(prefix, local_conf, cls.CLIENT_AUTHORIZATIONS_KEY_OPTION)
        self.user_identifier_env_key = cls._get_config_option(prefix, local_conf, cls.USER_IDENTIFIER_KEY_OPTION)

    @staticmethod
    def _get_http_status_string(status):
        return ("%d %s" % (status, httplib.responses[status]))

    def _redirect(self, url, start_response):
        start_response(self._get_http_status_string(httplib.FOUND),
               [('Location', url.encode('ascii', 'ignore'))])
        return []

    @classmethod
    def _get_config_option(cls, prefix, local_conf, key):
        return local_conf.get(prefix + key, cls.propertyDefaults.get(key, None))

    @classmethod
    def filter_app_factory(cls, app, app_conf, **local_conf):
        return cls(app, app_conf, **local_conf)
