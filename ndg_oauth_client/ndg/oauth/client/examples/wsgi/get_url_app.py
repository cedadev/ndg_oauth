"""Test ESGI application that returns the response from a URL
"""
__author__ = "R B Wilkinson"
__date__ = "07/02/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from cookielib import Cookie, CookieJar
import logging
import urlparse

from webob import Request

import ndg.httpsclient.utils as httpsclientutils
import ndg.httpsclient.ssl_context_util as ssl_context_util

log = logging.getLogger(__name__)

class GetUrlApp(object):
    """WSGI application to exercise the NDG security proxy with OAuth.
    """
    method = {
        "/": 'default',
        "/get": 'get'
    }
    def __init__(self, app, globalConfig, **localConfig):
        self.beakerSessionKeyName = globalConfig['beakerSessionKeyName']
        self.app = app
        self.url = localConfig['url']

    def __call__(self, environ, start_response):
        methodName = self.method.get(environ['PATH_INFO'], '').rstrip()
        if methodName:
            action = getattr(self, methodName)
            return action(environ, start_response)
        elif self.app is not None:
            return self.app(environ, start_response)
        else:
            start_response('404 Not Found', [('Content-type', 'text/plain')])
            return "WSGI Test Application: invalid URI"

    def default(self, environ, start_response):
        response = "<h2>WSGI Test Application</h2>"
        start_response('200 OK', 
                       [('Content-type', 'text/html'),
                        ('Content-length', str(len(response)))])
        return [response]

    def get(self, environ, start_response):
        request = Request(environ)
        response = ["<h2>WSGI Test Application - Get URL</h2>"]

        # Access to proxy doesn't require certificate.
        ssl_context = ssl_context_util.make_ssl_context()

        # The URL of the security proxy is the root URL for the current
        # host/port.
        # Only set up a HTTP proxy as a special HTTPS client would be needed -
        # standard HTTPS proxies set up a SSL connection from client to target
        # host, which is not appropriate for the security proxy.
        proxies = {'http': 'http://' + request.host}
        cookieJar = self.make_cookie_jar(request, self.url)
        config = httpsclientutils.Configuration(ssl_context, True,
                                                proxies=proxies, no_proxy='',
                                                cookie=cookieJar)
        log.debug("Making request to URL: %s", self.url)
        resp = httpsclientutils.fetch_from_url(self.url, config)
        response.append(resp)

        start_response('200 OK', 
                       [('Content-type', 'text/html'),
                        ('Content-length', str(sum([len(r) for r in response])))])
        return response

    @staticmethod
    def make_cookie_jar(request, url):

        url = urlparse.urlparse(url)
        hostname = url.hostname
        port = str(url.port)
        path = url.path
        if not path:
            path = '/'

        cj = CookieJar()

        for k, v in request.cookies.iteritems():
            #  version, name, value,
            #  port, port_specified,
            #  domain, domain_specified, domain_initial_dot,
            #  path, path_specified,
            #  secure,
            #  expires,
            #  discard,
            #  comment,
            #  comment_url,
            #  rest,
            #  rfc2109=False
            log.debug("Setting cookie: %s=%s; domain=%s; port=%s; path=%s",
                      k, v, hostname, port, path)
            clck = Cookie(None, k, v,
                          port, (True if port is not None else False),
                          hostname, True, False,
                          path, True,
                          False,
                          None,
                          None,
                          None,
                          None,
                          None)
            cj.set_cookie(clck)
        return cj

    @classmethod
    def app_factory(cls, globalConfig, **localConfig):
        return cls(None, globalConfig, **localConfig)

    @classmethod
    def filter_app_factory(cls, app, globalConfig, **localConfig):
        return cls(app, globalConfig, **localConfig)
