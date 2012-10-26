"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "Philip Kershaw"
__date__ = "19/10/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
import httplib
import re

import json
from webob import Request

from ndg.oauth.server.wsgi.oauth2_server import Oauth2ServerMiddleware
from ndg.oauth.server.lib.authorization_server import AuthorizationServer

log = logging.getLogger(__name__)
is_iterable = lambda obj: getattr(obj, '__iter__', False) 


class Oauth2ResourceServerMiddlewareError(Exception):
    '''Base exception class for OAuth 2.0 Resource Server errors'''
    

class Oauth2ResourceServerMiddlewareConfigError(
                                        Oauth2ResourceServerMiddlewareError):
    '''Exception class for OAuth 2.0 Resource Server configuration errors'''
    

class Oauth2ResourceServerMiddleware(object):
    '''OAuth 2.0 Resource Server implemented as a WSGI filter.  This filter 
    fronts a given applications resources in order to secure them.  Requests
    are intercepted and validated for an acceptable Access Token
    '''
    CERT_DN_ENVIRON_KEY = 'SSL_CLIENT_S_DN'
    DEFAULT_PARAM_PREFIX = 'oauth2.resource_server.'
    
    MATCH_SCOPE_TO_CLIENT_DN_OPTNAME = 'match_scope_to_client_dn'
    RESOURCE_URIPATHS_OPTNAME = 'resource_uripaths'
    
    CLAIMED_USER_ID_ENVIRON_KEY_OPTNAME = 'claimed_userid_environ_key'
    DEFAULT_CLAIMED_USER_ID_ENVIRON_KEYNAME = \
        'oauth.resource_server.claimed_userid'
    
    AUTHORISATION_SERVER_ENVIRON_KEYNAME = \
        Oauth2ServerMiddleware.AUTHORISATION_SERVER_ENVIRON_KEYNAME
        
    __slots__ = (
        '_app',
        '__authorization_server',
        'claimed_userid_environ_key',
        '__resource_uripaths',
        '__required_scope'
    )
    def __init__(self, app):
        self._app = app
        self.__authorization_server = None
        self.claimed_userid_environ_key = \
            self.__class__.DEFAULT_CLAIMED_USER_ID_ENVIRON_KEYNAME
        self.__resource_uripaths = []
        
        # Scope for this resource - multiple space delimited scope values may
        # be set
        self.__required_scope = None
        
    @classmethod
    def filter_app_factory(cls, app, global_conf, prefix=DEFAULT_PARAM_PREFIX,
                           **app_conf):
        obj = cls(app)
        obj.parse_keywords(**app_conf)
        return obj
        
    def parse_keywords(self, prefix=DEFAULT_PARAM_PREFIX, **conf):
        '''Set attributes from keywords passed
        
        @type prefix: basestring
        @param prefix: if a prefix is given, only update self from kw items 
        where keyword starts with this prefix
        @type conf: dict
        @param conf: items corresponding to instance variables to 
        update.  Keyword names must match their equivalent instance 
        variable names.  However, they may prefixed with <prefix>
        '''
        if prefix is None:
            prefix_ = ''
        else:
            prefix_ = prefix
            
        prefix_len = len(prefix_)
            
        for optname, val in conf.items():
            if optname.startswith(prefix_):
                setattr(self, optname[prefix_len:], val)
        
    @property
    def resource_uripaths(self):
        return self.__resource_uripaths
    
    @resource_uripaths.setter
    def resource_uripaths(self, val):
        if isinstance(val, basestring):
            self.__resource_uripaths = [re.compile(path) for path in val.split()]
            
        elif is_iterable(val):
            self.__resource_uripaths = [re.compile(path) for path in val]
        else:
            raise TypeError('Expecting single string or space-separated URI '
                            'paths or an iterable; got %r instead' % type(val))
     
    @property
    def authorization_server(self):
        return self.__authorization_server
    
    @authorization_server.setter
    def authorization_server(self, val):
        if not isinstance(val, AuthorizationServer):
            raise TypeError('Expecting %r type for "authorization_server" '
                            'attribute; got %r instead' % (AuthorizationServer, 
                                                           type(val)))
        self.__authorization_server = val
     
    @property
    def required_scope(self):
        return self.__required_scope
    
    @required_scope.setter
    def required_scope(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "required_scope" '
                            'attribute; got %r instead' % type(val))
        self.__required_scope = val 
                       
    def __call__(self, environ, start_response):
        '''Apply validation of access token for configured resource paths
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        '''
        request = Request(environ)
        
        self.authorization_server = environ.get(
                            self.__class__.AUTHORISATION_SERVER_ENVIRON_KEYNAME)
        
        if self._match_uripath(request.path_info):
            return self.request_resource(request, start_response)
        else:
            return self._app(environ, start_response)
    
    def request_resource(self, request, start_response):
        """
        Filter a resource request checking for a valid access token.  Set an
        error response if the token is invalid, otherwise pass on the request to
        the underlying app / middleware + app
        
        @type req: webob.Request
        @param req: HTTP request object

        @type start_response: 
        @param start_response: WSGI start response function

        @rtype: iterable
        @return: WSGI response
        """
        log.debug("Oauth2ResourceServerMiddleware.request_resource called for "
                  "path %r", request.path_info)

        # Check the token
        token, status, error = self.authorization_server.get_registered_token(
                                                    request, 
                                                    scope=self.required_scope)
        if not error:
            request.environ[self.claimed_userid_environ_key
                    ] = token.grant.additional_data.get('user_identifier')
                            
            return self._app(request.environ, start_response)
        else:
            status = httplib.OK
            content_dict ={}
            content_dict.setdefault('error', error)
                        
            response = json.dumps(content_dict)
            headers = [
                ('Content-Type', 'application/json; charset=UTF-8'),
                ('Cache-Control', 'no-store'),
                ('Content-length', str(len(response))),
                ('Pragma', 'no-store')
            ]
            status_str = "%d %s" % (status, httplib.responses[status])
            start_response(status_str, headers)
            return [response]
    
    def _match_uripath(self, path):
        '''Match the input request against a configured list of URI patterns
        for which this OAuth middleware should be applied
        
        @param path: URI path to match - path minus the domain name and 
        protocol specifier
        @type path: basestring
        @return: true or false for match found
        @rtype: bool
        '''
        for re_path in self.__resource_uripaths:
            if re_path.match(path):
                return True
        
        return False