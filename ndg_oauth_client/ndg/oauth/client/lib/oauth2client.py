"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "09/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import json
import logging
import urllib
import uuid

from ndg.httpsclient import utils as httpsclient_utils
from ndg.httpsclient import ssl_context_util

log = logging.getLogger(__name__)

class Oauth2ClientConfig(object):
    """OAuth client configuration.
    """
    def __init__(self, client_id, authorization_endpoint, access_token_endpoint,
                 base_url_path, redirect_uri, **kw):
        """
        @type client_id: str
        @param client_id: OAuth client ID

        @type authorization_endpoint: str
        @param authorization_endpoint: URL of OAuth service providing providing
        authorization grants

        @type access_token_endpoint: str
        @param access_token_endpoint: URL of OAuth service providing providing
        access tokens

        @type base_url_path: str
        @param base_url_path: base path included in OAuth client URLs

        @type redirect_uri: str
        @param redirect_uri: URL to which the OAuth authorization server should
        redirect after an authorization request

        @type kw: dict
        @param kw: additional parameters for configuring extended client classes
        """
        self.client_id = client_id
        self.authorization_endpoint = authorization_endpoint
        self.access_token_endpoint = access_token_endpoint
        self.base_url_path = base_url_path
        self.redirect_uri = redirect_uri
        self.kw = kw

    def make_redirect_uri(self, application_url):
        """Constructs the redirect URI from components.

        @type application_url: str
        @param application_url: application base URL

        @rtype: str
        @return: full redirect URI
        """
        log.debug("make_redirect_uri: application_url=%s base_url_path=%s "
                  "redirect_uri=%s",
                  application_url, self.base_url_path, self.redirect_uri)
        return self._construct_url([application_url, self.base_url_path,
                                    self.redirect_uri])

    def is_redirect_uri(self, application_url, url):
        """Determines whether a URL is the redirect URI for this client.

        @type application_url: str
        @param application_url: application base URL

        @type url: str
        @param url: URL to check

        @rtype: bool
        @return: True if URL is the redirect URI otherwise False
        """
        redirect_uri = self._construct_url([application_url, self.base_url_path, self.redirect_uri])
        (path_url, sep, query) = url.partition('?')
        return redirect_uri == path_url

    @staticmethod
    def _construct_url(parts):
        """Joins components of a URL with separators where needed.

        @type parts: dict of str
        @param parts: URL components

        @rtype: str
        @return: combined URL (part)
        """
        results = []
        last_idx = len(parts) - 1
        for n, part in enumerate(parts):
            if n > 0:
                part = part.lstrip('/')
            if n < last_idx:
                part = part.rstrip('/')
            if part:
                results.append(part)
        return '/'.join(results)
    
class Oauth2Client(object):
    """OAuth 2.0 client
    """
    ACCESS_TOKEN_ENCODING = 'utf-8'
    RESPONSE_TYPE = 'code'
    SESSION_ID_KEY = 'oauth_client_instance_id'

    def __init__(self, client_config):
        """
        @type client_config: ndgoauthclient.lib.oauth2client.Oauth2ClientConfig
        @param client_config: OAuth client configuration
        """
        self.client_config = client_config
        self.access_token = None
        for k, v in client_config.kw.iteritems():
            setattr(self, k, v)

    def call_with_access_token(self, scope, application_url, callback):
        """Calls a specified callable providing an access token.
        
        @type scope: str
        @param scope: required OAuth token scope

        @type application_url: str
        @param application_url: application base URL

        @type callback: callable called with arguments
            (access_token, error, error_description)
        @param callback: callable to call when the token is available

        @rtype: tuple (
            result (None if not obtained yet)
            redirect URL (None if access token already obtained)
        )
        @return: return value from callback if access token available or a
            URL to which to redirect to obtain an access token
        """
        if self.access_token is not None:
            log.debug("call_with_access_token: token found")
            result = callback(self.access_token, None, None)
            return (result, None)
        log.debug("call_with_access_token: token not found")

        # Client does not have an access token, so create redirect URI with
        # which to initiate the process of getting one.
        redirect_uri = self.client_config.make_redirect_uri(application_url)
        parameters = {
            'client_id': self.client_config.client_id,
            'redirect_uri': redirect_uri,
            'response_type': self.RESPONSE_TYPE,
            'scope': scope
            }
        self.state = uuid.uuid4().hex
        log.debug("call_with_access_token authorization_endpoint: %s", self.client_config.authorization_endpoint)
        log.debug("call_with_access_token parameters: %s", parameters)
        url = self._make_combined_url(self.client_config.authorization_endpoint, parameters, self.state)
        return (None, url)

    def call_with_access_token_redirected_back(self, request, callback,
                                               ssl_config):
        """ Called after redirection following authorization process.

        @type request: webob.Request
        @param request: request object

        @type callback: callable called with arguments
            (access_token, error, error_description)
        @param callback: callable to call when the token is available

        @type ssl_config: ndg.httpsclient.ssl_context_util.SSlContextConfig
        @param ssl_config: SSL configuration

        @rtype: any
        @return: result from callback
        """
        params = request.GET
        code = params.get('code', None)
        state = params.get('state', None)
        error = params.get('error', None)
        error_description = params.get('error_description', None)
        if error:
            log.info("Error from OAuth authorization server: %s - %s",
                     error, error_description)
            return callback(None, error, error_description)
        else:
            if state != self.state:
                error = 'Inconsistent state'
                error_description = 'State value incorrect implying request is not the result of legitimate OAuth redirection.'
                log.info("Erroneous request to redirect URL: %s - %s",
                         error, error_description)
                return callback(None, error, error_description)
            log.debug("Valid redirect from OAuth authorization server")
            return self.request_access_token(code, request.application_url,
                                             request, callback, ssl_config)

    def request_access_token(self, code, application_url, request, callback,
                             ssl_config):
        """
        @type code: str
        @param code: authorization code

        @type application_url: str
        @param application_url: application base URL

        @type request: webob.Request
        @param request: request object

        @type callback: callable called with arguments
            (access_token, error, error_description)
        @param callback: callable to call when the token is available

        @type ssl_config: ndg.httpsclient.ssl_context_util.SSlContextConfig
        @param ssl_config: SSL configuration

        @rtype: any
        @return: result from callback
        """
        # Make POST request to obtain an access token.
        parameters = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.client_config.make_redirect_uri(application_url)}
        self.additional_access_token_request_parameters(parameters, request)
        log.debug("Requesting access token - parameters: %s", parameters)
        data = urllib.urlencode(parameters)
        response_json = httpsclient_utils.fetch_stream_from_url(
            self.client_config.access_token_endpoint,
            httpsclient_utils.Configuration(
                    ssl_context_util.make_ssl_context_from_config(ssl_config)),
            data)
        response = json.load(response_json)
        access_token = response.get('access_token', None)
        if 'error' in response:
            error = response['error']
            error_description = response.get('error_description', None)
            return callback(None, error, error_description)
        elif access_token is None:
            error = 'invalid_request'
            error_description = 'Error retrieving access token - no access token returned.'
            return callback(None, error, error_description)
        else:
            self.access_token = access_token.encode(self.ACCESS_TOKEN_ENCODING)
            log.debug("Access token received: %s", self.access_token)
            return callback(self.access_token, None, None)

    def additional_access_token_request_parameters(self, parameters, request):
        """
        Override to add parameters into the access token request.

        @type parameters: dict of str
        @param parameters: parameters sent in access token request

        @type request: webob.Request
        @param request: request object
        """
        pass

    @staticmethod
    def _make_combined_url(base_url, parameters, state):
        """Combines a base URL and parameters to make a full URL.

        @type base_url: str
        @param base_url: base URL to which to add query parameters

        @type parameters: dict of str
        @param parameters: name/values pairs to use as query parameters

        @type state: str
        @param state: state parameter which must be included without encoding

        @rtype: str
        @return: combined URL
        """
        url = base_url.rstrip('?')
        url_parts = [url]
        sep_with_ampersand = ('?' in url)
        if parameters:
            query_string = urllib.urlencode(parameters)
            url_parts.extend([('&' if (sep_with_ampersand) else '?'), query_string])
            sep_with_ampersand = True

        if state:
            url_parts.extend([('&' if (sep_with_ampersand) else '?'), 
                              'state=',
                              state])

        return ''.join(url_parts)

    @classmethod
    def get_client_instance(cls, session, client_config, create=False):
        """Retrieves from the session, and optionally creating if necessary, a
        client instance.

        @type session: SessionObject
        @param session: session data

        @type client_config: 
        @param client_config: client configuration

        @type create: bool
        @param create: True if a client is to be created if it does not exist
            already

        @rtype: instance of Oauth2Client
        @return: OAuth 2 client object
        """
        client = None
        if cls.SESSION_ID_KEY in session:
            client = session[cls.SESSION_ID_KEY]
            log.debug("Found OAuth client in session.")
        if client is None and create:
            client = cls(client_config)
            session[cls.SESSION_ID_KEY] = client
            session.save()
            log.debug("No OAuth client in session - created new one.")
        return client

    @classmethod
    def delete_client_instance(cls, session):
        """Deletes the client instance from the session.

        @type session: SessionObject
        @param session: session data
        """
        if cls.SESSION_ID_KEY in session:
            client_instance_id = session[cls.SESSION_ID_KEY]
            if client_instance_id in cls.client_instances:
                del cls.client_instances[client_instance_id]
