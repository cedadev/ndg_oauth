"""OAuth 2.0 WSGI server test application for use with client middleware
"""
__author__ = "R B Wilkinson"
__date__ = "09/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"


class WsgiTestApp(object):
    """
    Simple WSGI application that displays a token set in the WSGI environ by
    Oauth2ClientMiddleware.
    """
    method = {
        "/": 'default',
        "/token": 'tok'
    }
    TOKEN_ENV_KEYNAME = 'oauth2client.token'
    def __init__(self, app, globalConfig, **localConfig):
        self.beakerSessionKeyName = globalConfig['beakerSessionKeyName']
        self.app = app

    def __call__(self, environ, start_response):
        methodName = self.method.get(environ['PATH_INFO'], '').rstrip()
        if methodName:
            action = getattr(self, methodName)
            return action(environ, start_response)
        elif self.app is not None:
            return self.app(environ, start_response)
        else:
            start_response('404 Not Found', [('Content-type', 'text/plain')])
            return "ndg_oauth WSGI Test Application: invalid URI"

    def default(self, environ, start_response):
        response = "<h2>ndg_oauth WSGI Test Application</h2>"
        start_response('200 OK', 
                       [('Content-type', 'text/html'),
                        ('Content-length', str(len(response)))])
        return [response]

    def tok(self, environ, start_response):
        tok = environ.get(self.TOKEN_ENV_KEYNAME)
        response = ["<h2>ndg_oauth WSGI Test Application - Get Token"
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
                       [('Content-type', 'text/html'),
                        ('Content-length', 
                         str(sum([len(r) for r in response])))])
        return response

    @classmethod
    def app_factory(cls, globalConfig, **localConfig):
        return cls(None, globalConfig, **localConfig)

    @classmethod
    def filter_app_factory(cls, app, globalConfig, **localConfig):
        return cls(app, globalConfig, **localConfig)
