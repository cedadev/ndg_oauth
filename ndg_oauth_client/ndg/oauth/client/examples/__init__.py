"""OAuth 2.0 WSGI server test application for use with client middleware
"""
__author__ = "R B Wilkinson"
__date__ = "09/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

from ndg.oauth.client.lib import certificate_request
from ndg.httpsclient import ssl_context_util


class OAuthClientTestApp(object):
    """
    Simple WSGI application that displays a token set in the WSGI environ by
    Oauth2ClientMiddleware.
    """
    method = {
        "/": 'default',
        "/token": 'tok'
    }
    TOKEN_ENV_KEYNAME = 'oauth2client.token'
    def __init__(self, app, app_conf, **local_conf):
        self.beakerSessionKeyName = app_conf['beakerSessionKeyName']
        self.app = app

    def __call__(self, environ, start_response):
        methodName = self.method.get(environ['PATH_INFO'], '').rstrip()
        if methodName:
            action = getattr(self, methodName)
            return action(environ, start_response)
        elif self.app is not None:
            return self.app(environ, start_response)
        else:
            start_response('404 Not Found', 
                           [('Content-type', 'text/plain; charset=UTF-8')])
            return "ndg_oauth WSGI Test Application: invalid URI"

    def default(self, environ, start_response):
        log.debug('OAuthClientApp.default ...')
        response = "<h2>ndg_oauth WSGI Test Application</h2>"
        start_response('200 OK', 
                       [('Content-type', 'text/html; charset=UTF-8'),
                        ('Content-length', str(len(response)))])
        return [response]

    def tok(self, environ, start_response):
        log.debug('OAuthClientApp.tok ...')

        tok = environ.get(self.TOKEN_ENV_KEYNAME)
        response = ["<h2>ndg_oauth WSGI Test Application: Get Token"
                    "</h2>"]
        if tok:
            if isinstance(tok, basestring):
                response.append("<pre>%s</pre>" % tok)
            else:
                for i in tok:
                    response.append("<pre>%s</pre>" % i)
        else:
            response.append("<p>token not found</p>")

        start_response('200 OK', 
                       [('Content-type', 'text/html; charset=UTF-8'),
                        ('Content-length', 
                         str(sum([len(r) for r in response])))])
        return response

    @classmethod
    def app_factory(cls, app_conf, **local_conf):
        return cls(None, app_conf, **local_conf)

    @classmethod
    def filter_app_factory(cls, app, app_conf, **local_conf):
        return cls(app, app_conf, **local_conf)
    
    
class BearerTokOAuthClientApp(OAuthClientTestApp):
    '''Extend basic OAuth client demonstration application to illustrate
    retrieving a resource (in this case a certificate)
    '''
    method = OAuthClientTestApp.method
    method['/resource'] = 'get_resource'
    
    DEFAULT_TOKEN_ENV_KEYNAME = 'oauth2client.token'
    DEFAULT_CERTIFICATE_REQUEST_PARAMETER = 'certificate_request'
    
    def __init__(self, app, app_conf, **local_conf):
        self.app = app

        self.resource_url = local_conf['resource_url']
        self.token_env_key = local_conf.get('oauth2_token_key',
                                            self.DEFAULT_TOKEN_ENV_KEYNAME)

        # SSL configuration
        client_cert = local_conf.get('client_cert')
        client_key = local_conf.get('client_key')
        self.ca_cert_file = local_conf.get('ca_cert_file')
        self.ca_dir = local_conf.get('ca_dir')
        self.ssl_config = ssl_context_util.SSlContextConfig(client_key,
            client_cert, self.ca_cert_file, self.ca_dir, True)

        # OAuth client configuration
        self.certificate_request_parameter = local_conf.get(
                                    'certificate_request_parameter',
                                    self.DEFAULT_CERTIFICATE_REQUEST_PARAMETER)
    
    def get_resource(self, environ, start_response):
        response = [
            "<h2>ndg_oauth WSGI Test Application: get secured resource</h2>"
        ]

        token = environ.get(self.token_env_key)
        if not token:
            response.append('<p>No OAuth token found.</p>')
        else:
            log.debug("Token found; %s" % token)
            try:
                (private_key,
                 certificate) = certificate_request.request_certificate(
                    token, self.resource_url, self.ssl_config,
                    self.certificate_request_parameter)
            except Exception, exc:
                response.append('<p>Exception obtaining certificate from OAuth '
                                'server: %s</p>' % exc)
            else:
                response.append('<p>%s</p><p>%s</p>' % (private_key,
                                                        certificate))

        start_response('200 OK',
                       [('Content-type', 'text/html; charset=UTF-8'),
                        ('Content-length', str(sum([len(r) for r in response])))
                        ])
        return response

