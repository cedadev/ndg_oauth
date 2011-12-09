"""Data fetch by URL utility
"""
__author__ = "R B Wilkinson"
__date__ = "03/11/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
import httplib
import os
import urllib2
import urlparse

from OpenSSL import SSL

from urllib2pyopenssl.urllib2_build_opener import urllib2_build_opener
from urllib2pyopenssl.https import HTTPSContextHandler
import urllib2pyopenssl.ssl_context_util as ssl_context_util

log = logging.getLogger(__name__)

#class HTTPSClientAuthHandler(urllib2.HTTPSHandler):
#    '''Extension of HTTPSHandler that provides key and certificate for certificate authentication.
#    '''
#    def __init__(self, key_file, cert_file, debuglevel=0):
#        """
#        @param key_file - location of user's private key file
#        @param cert_file - location of user's certificate key file
#        @param debuglevel - debug level for HTTPSHandler
#        """
#        urllib2.HTTPSHandler.__init__(self, debuglevel)
#        self.key_file = key_file
#        self.cert_file = cert_file
#
#    def https_open(self, req):
#        """Opens HTTPS request
#        @param req - HTTP request
#        @return HTTP Response object
#        """
#        return self.do_open(self.getConnection, req)
#
#    def getConnection(self, host, timeout=300):
#        """Gets connection
#        @param host - host name or address + port
#        @param timeout - timeout
#        @return HTTPS connection
#        """
#        return httplib.HTTPSConnection(host, timeout=timeout, key_file=self.key_file,
#                                       cert_file=self.cert_file)

def fetch_stream_from_url(url, data=None, ssl_config=None, debug=False):
    """Returns data retrieved from a URL.
    @param url: URL to attempt to open
    @type: str
    @param debug: debug flag for urllib2
    @type: bool
    @return: data retrieved from URL or None
    @rtype: file derived type
    """
    response = open_url(url, data, ssl_config, debug)
    return response

def fetch_data_from_url(url, data=None, ssl_config=None, debug=False):
    """Returns data retrieved from a URL.
    @param url: URL to attempt to open
    @type: str
    @param debug: debug flag for urllib2
    @type: bool
    @return: data retrieved from URL or None
    @rtype: str
    """
    response = open_url(url, data, ssl_config, debug)
    return_data = response.read()
    response.close()
    return return_data

def open_url(url, data=None, ssl_config=None, debug=False):
    """Attempts to open a connection to a specified URL.
    @param url: URL to attempt to open
    @type: str
    @param debug: debug flag for urllib2
    @type: bool
    @return: tuple (
    @rtype: tuple (
        int: returned HTTP status code or 0 if an error occurred
        str: returned message or error description
        file-like: response object
    )
    """
#    ssl_context = make_ssl_context(key_file, cert_file, ca_dir)
#    ssl_context_util.set_peer_verification_for_url_hostname(ssl_context, url, if_verify_enabled=True)
    ssl_context = ssl_context_util.make_ssl_context_from_config(ssl_config, url)
    handlers = []
    if debug:
        # Set up handlers for URL opener with debugging enabled.
        debuglevel = 1
        http_handler = urllib2.HTTPHandler(debuglevel=debuglevel)
        https_handler = HTTPSContextHandler(ssl_context, debuglevel=debuglevel)
        handlers.extend([http_handler, https_handler])

    # Explicitly remove proxy handling if the host is one listed in the value of
    # the no_proxy environment variable because urllib2 does use proxy settings
    # set via http_proxy and https_proxy, but does not take the no_proxy value
    # into account.
    if not _should_use_proxy(url):
        handlers.append(urllib2.ProxyHandler({}))
        log.debug("Not using proxy")

    opener = urllib2_build_opener(ssl_context, *handlers)

    # Open the URL and check the response.
    try:
        response = opener.open(url, data)
    except urllib2.HTTPError, exc:
        # Re-raise as simple exception
        raise Exception(exc.__str__())
    return response

#def make_ssl_context(key_file=None, cert_file=None, ca_dir=None):
#    # Create SSL context containing certificate and key file locations.
#    ssl_context = SSL.Context(SSL.SSLv23_METHOD)
#    if cert_file:
#        ssl_context.use_certificate_file(cert_file)
#    if key_file:
#        ssl_context.use_privatekey_file(key_file)
#    else:
#        if cert_file:
#            ssl_context.use_privatekey_file(cert_file)
#    if ca_dir:
#        ssl_context.load_verify_locations(capath=ca_dir)
#    return ssl_context

def _should_use_proxy(url):
    """Determines whether a proxy should be used to open a connection to the
    specified URL, based on the value of the no_proxy environment variable.
    @param url: URL
    @type: str
    @return: flag indicating whether proxy should be used
    @rtype: bool
    """
    no_proxy   = os.environ.get('no_proxy', '')

    urlObj = urlparse.urlparse(url)
    for np in [h.strip() for h in no_proxy.split(',')]:
        if urlObj.hostname == np:
            return False

    return True
