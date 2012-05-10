"""Test ESGI application that returns the response from a URL
"""
__author__ = "R B Wilkinson"
__date__ = "20/03/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging

from ndg.oauth.client.lib.http_get_with_credential import HttpGetWithCredential

log = logging.getLogger(__name__)

class GetUrlApp(object):
    """WSGI application to exercise the NDG security proxy with OAuth.
    """
    method = {
        "/": 'default',
        "/get": 'get'
    }

    def __init__(self, app, globalConfig, **localConfig):
        self.app = app

        self.httpGetter = HttpGetWithCredential(
            localConfig.get('resource_server_url'),
            localConfig.get('client_cert'),
            localConfig.get('client_key'),
            localConfig.get('ca_cert_file'),
            localConfig.get('ca_dir'),
            localConfig.get('oauth2_token_key'),
            localConfig.get('certificate_request_parameter'))

        self.url = localConfig['url']

    def __call__(self, environ, start_response):
        log.debug('GetUrlApp.__call__ ...')
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
        log.debug('GetUrlApp.get ...')
        response = ["<h2>WSGI Test Application - Get URL</h2>"]

        try:
            resp = self.httpGetter.get(environ, self.url)
            response.append(resp)
        except Exception, exc:
            response.append('<p>Exception obtaining fetching data: %s</p>' %
                                                                exc.__str__())
        start_response('200 OK', 
                       [('Content-type', 'text/html'),
                        ('Content-length', str(sum([len(r) for r in response])))])
        return response

    @classmethod
    def app_factory(cls, globalConfig, **localConfig):
        return cls(None, globalConfig, **localConfig)

    @classmethod
    def filter_app_factory(cls, app, globalConfig, **localConfig):
        return cls(app, globalConfig, **localConfig)
