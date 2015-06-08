"""OAuth 2.0 client
"""
from _pyio import __metaclass__
__author__ = "R B Wilkinson"
__date__ = "09/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from abc import ABCMeta, abstractmethod
import json
import logging
import urllib
import uuid
import httplib
from urllib2 import HTTPError

from ndg.httpsclient import utils as httpsclient_utils
from ndg.httpsclient import ssl_context_util

log = logging.getLogger(__name__)


class Oauth2ClientError(Exception):
    '''Base class for OAuth 2.0 client exceptions'''
    
class Oauth2ClientConfigError(Oauth2ClientError):
    '''OAuth 2.0 Client configuration error'''
    
class Oauth2ClientAccessTokenRetrievalError(Oauth2ClientError):
    '''OAuth 2.0 Client failed to retrieve token from OAuth 2.0 server'''
    def __init__(self, error, error_description):
        self.error = error
        self.error_description = error_description
        
        super(Oauth2ClientAccessTokenRetrievalError, self).__init__(error)
    
    
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
        redirect_uri = self._construct_url([application_url, self.base_url_path,
                                            self.redirect_uri])
        path_url = url.partition('?')[0]
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
    ACCESS_TOK_ENCODING = 'utf-8'
    RESPONSE_TYPE = 'code'
    SESSION_ID_KEY = 'oauth_client_instance_id'
    HTTP_AUTHORIZATION_HEADER_FIELD = 'Authorization'
    BEARER_TOK_ID = 'Bearer'
    MAC_TOK_ID = 'MAC'
    TOKEN_TYPES = (BEARER_TOK_ID, MAC_TOK_ID)

    def __init__(self, client_config=None, access_token=None):
        """
        @type client_config: ndgoauthclient.lib.oauth2client.Oauth2ClientConfig
        @param client_config: OAuth client configuration
        """
        self.client_config = client_config
        self.access_token = access_token
        
        if client_config is not None:
            for k, v in client_config.kw.iteritems():
                setattr(self, k, v)
        
    def call_with_access_token(self, scope, application_url, 
                               token_retriever_cb):
        """Calls a specified callable providing an access token.
        
        @type scope: str
        @param scope: required OAuth token scope

        @type application_url: str
        @param application_url: application base URL

        @type token_retriever_cb: callable called with argument access_token
        @param token_retriever_cb: callable to call when the token is available

        @rtype: tuple (
            result (None if not obtained yet)
            redirect URL (None if access token already obtained)
        )
        @return: return value from token_retriever_cb if access token available 
        or a URL to which to redirect to obtain an access token
        """
        if self.access_token is not None:
            log.debug("call_with_access_token: token found")
            result = token_retriever_cb(self.access_token)
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
        log.debug("call_with_access_token authorization_endpoint: %s", 
                  self.client_config.authorization_endpoint)
        log.debug("call_with_access_token parameters: %s", parameters)
        url = self._make_combined_url(self.client_config.authorization_endpoint, 
                                      parameters, self.state)
        return None, url

    def call_with_access_token_redirected_back(self, request, 
                                               token_retriever_cb,
                                               ssl_config):
        """Called after redirection following authorization process.

        @type request: webob.Request
        @param request: request object

        @type token_retriever_cb: callable called with arguments
            (access_token, error, error_description)
        @param token_retriever_cb: callable to call when the token is available

        @type ssl_config: ndg.httpsclient.ssl_context_util.SSlContextConfig
        @param ssl_config: SSL configuration

        @rtype: any
        @return: result from token_retriever_cb
        """
        params = request.GET
        code = params.get('code', None)
        state = params.get('state', None)
        error = params.get('error', None)
        error_description = params.get('error_description', None)
        if error:
            log.error("Error from OAuth authorization server: %s - %s",
                      error, error_description)
            raise Oauth2ClientAccessTokenRetrievalError(error, 
                                                        error_description)
        else:
            if state != self.state:
                error = 'Inconsistent state'
                error_description = (
                    'State value incorrect implying request is not the result '
                    'of legitimate OAuth redirection.')
                
                log.error("Erroneous request to redirect URL: %s - %s",
                          error, error_description)
                raise Oauth2ClientAccessTokenRetrievalError(error, 
                                                            error_description)
            else:
                log.debug("Valid redirect from OAuth authorization server")
                return self.request_access_token(code, request.application_url,
                                                 request, token_retriever_cb, 
                                                 ssl_config)

    def request_access_token(self, code, application_url, request, 
                             token_retriever_cb, ssl_config):
        """
        @type code: str
        @param code: authorization code

        @type application_url: str
        @param application_url: application base URL

        @type request: webob.Request
        @param request: request object

        @type token_retriever_cb: callable called with arguments
            (access_token, error, error_description)
        @param token_retriever_cb: callable to call when the token is available

        @type ssl_config: ndg.httpsclient.ssl_context_util.SSlContextConfig
        @param ssl_config: SSL configuration

        @rtype: any
        @return: result from token_retriever_cb
        """
        # Make POST request to obtain an access token.
        redirect_uri = self.client_config.make_redirect_uri(application_url)
        parameters = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri
        }
        
        # Put client_secret in request when defined. Most implementations
        # require this as part of the parameters, even though using an
        # authorization header with a bearer-token would seem to be preferred
        # by draft-ietf-oauth-v2-bearer-23
        if self.client_config.kw.get('client_secret') is not None:
            parameters['client_id'] = self.client_config.client_id
            parameters['client_secret'] = self.client_config.kw['client_secret']

        self.additional_access_token_request_parameters(parameters, request)
        
        log.debug("Requesting access token - parameters: %s", parameters)
        data = urllib.urlencode(parameters)
        
        ssl_ctx = ssl_context_util.make_ssl_context_from_config(ssl_config)
        
        # Header required by, for example Github, to get a json response
        config = httpsclient_utils.Configuration(
                                        ssl_ctx,
                                        headers={'Accept': 'application/json'})
        try:   
            response_json = httpsclient_utils.fetch_stream_from_url(
                                    self.client_config.access_token_endpoint,
                                    config,
                                    data)
        except HTTPError as http_error:
            # Expect 400 code if a client error occurred or 500 for server-side
            # problem.  Either way, the following if block should handle this
            if http_error.code == httplib.BAD_REQUEST:
                response_json = http_error.fp

        response = json.load(response_json)
            
        access_token = response.get('access_token', None)
        if 'error' in response:
            error = response['error']
            error_description = response.get('error_description', None)
            
            log.error('Access token request error: %s %s', error, 
                      error_description)
            
            raise Oauth2ClientAccessTokenRetrievalError(error, 
                                                        error_description)

        
        elif access_token is None:
            error = 'invalid_request'
            error_description = ('Error retrieving access token - '
                                 'no access token returned.')
            
            raise Oauth2ClientAccessTokenRetrievalError(error, 
                                                        error_description)
        else:
            self.access_token = access_token.encode(self.ACCESS_TOK_ENCODING)
            
            log.debug("Access token received: %s", self.access_token)
            
            return token_retriever_cb(self.access_token)

    def additional_access_token_request_parameters(self, parameters, request):
        """
        Override to add parameters into the access token request.

        @type parameters: dict of str
        @param parameters: parameters sent in access token request

        @type request: webob.Request
        @param request: request object
        """

    def request_resource(self, 
                         resource_url, 
                         ssl_config=None, 
                         config=None, 
                         data=None, 
                         handlers=None):
        '''Request a resource URL setting *bearer* token in Authorization
        header

        @type resource_url: str
        @param resource_url: URL of resource to be requested

        @type ssl_config: ndg.httpsclient.ssl_context_util.SSlContextConfig
        @param ssl_config: SSL configuration, Nb. if config keyword is set then
        this parameter will be *ignored*
        
        @type config: ndg.httpsclient.utils.Configuration
        @param config: HTTP configuration settings.  Setting this keyword will
        override any setting made for ssl_config      
        @param data: HTTP POST data
        @type data: str
        @param handlers: list of custom urllib2 handlers to add to the request
        @type handlers: iterable
        @return: response from resource server
        @rtype: urllib.addinfourl
        '''
        if self.access_token is None:
            raise Oauth2ClientConfigError('No access token set for request to '
                                          'resource %r' % resource_url)
        
        authorization_header = {
            self.__class__.HTTP_AUTHORIZATION_HEADER_FIELD: '%s %s' % (
                                                self.__class__.BEARER_TOK_ID, 
                                                self.access_token),
        }
        
        if config and ssl_config:
            raise TypeError('Set either "config" or "ssl_config" keywords but '
                            'not both')
            
        if config is None:
            ssl_ctx = ssl_context_util.make_ssl_context_from_config(ssl_config)
            config = httpsclient_utils.Configuration(
                                                ssl_ctx,
                                                headers=authorization_header)
        
        response = httpsclient_utils.fetch_stream_from_url(resource_url, 
                                                           config,
                                                           data=data)
        return response


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
            url_parts.extend([('&' if (sep_with_ampersand) else '?'), 
                              query_string])
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
                

class TokenRetrieverInterface(object):
    """Interface to modify access token form returned to caller of Oauth2Client
    """
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def __call__(self, access_token):
        """From input access token return translated form or pass through
        unchanged as required"""
