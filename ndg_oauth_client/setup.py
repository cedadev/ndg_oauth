__author__ = "R B Wilkinson"
__date__ = "29/02/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

_long_description = """\
This is an OAuth 2.0 client library and WSGI middleware filter.

Its intended use is to make requests to the NDG OAuth server, which returns as
access tokens certificates obtained from a MyProxy server.

ndg.oauth.client.lib.oauth2client:Oauth2Client is a client that calls a
specified callable with an access token obtained from a configured OAuth server.
ndg.oauth.client.lib.oauth2_myproxy_client:Oauth2MyProxyClient extends this to
handle key creation for obtaining MyProxy certificates.

The filter ndg.oauth.client.wsgi.oauth2_client:Oauth2ClientMiddleware uses
Oauth2MyProxyClient and sets the obtained access token in the WSGI environ. The
token contains the key/certificate pair so that it can be used by other WSGI
applications or middleware to authenticate.

Prerequisites
=============
This has been developed and tested for Python 2.6.

Installation
============
Installation can be performed using easy_install or pip.  

Configuration
=============
Examples of configuration files for WSGI stacks are:
test_app.ini:
  This configures a simple test application that simply displays the key and
  certificate.
get_url_app_proxy.ini:
  This is a more complex example that uses the NDG Security proxy. The
  application makes a request to a configured URL using the security proxy. The
  proxy uses a key/certificate pair obtained using NDG OAuth to authenticate the
  request.
"""

setup(
    name =                      'ndg_oauth_client',
    version =                   '0.2.0',
    description =               'OAuth 2.0 client',
    author =                    'R. B. Wilkinson',
    maintainer =         	'Philip Kershaw',
    maintainer_email =          'Philip.Kershaw@stfc.ac.uk',
    #url ='',
    license =                   'BSD - See LICENCE file for details',
    install_requires =[
        "PasteScript",
        "Beaker",
        "WebOb",
        "pyOpenSSL",
        "ndg_httpsclient",
        "pyasn1",
    ],
    packages =find_packages(),
    zip_safe =False,
)
