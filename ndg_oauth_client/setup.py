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

It supports simple string-based bearer token and a custom extension to enable 
the use of X.509 certificates as tokens.  The latter has been added to enable
a SLCS (Short-lived Credential Service) to issue delegated X.509-based 
credentials using OAuth.

ndg.oauth.client.lib.oauth2client:Oauth2Client is a client that calls a
specified callable with an access token obtained from a configured OAuth server.
ndg.oauth.client.lib.oauth2_myproxy_client:Oauth2MyProxyClient extends this to
handle key creation for obtaining X.509 certificates.

The filter ndg.oauth.client.wsgi.oauth2_client:Oauth2ClientMiddleware uses
Oauth2MyProxyClient and sets the obtained access token in the WSGI environ. The
token contains the key/certificate pair so that it can be used by other WSGI
applications or middleware to authenticate.

Prerequisites
=============
This has been developed and tested for Python 2.6 and 2.7.

Installation
============
Installation can be performed using easy_install or pip.  

Configuration
=============
Examples are contained in the examples/ sub-folder:

bearer_tok/:
  This configures a simple test application that uses string based tokens.
slcs/:
  This is a more complex and specialised example that issues X.509 certificate-
  based tokens as part of a Short-lived Credential Service.  The corresponding
  authorisation server available from the ndg.oauth server package requires 
  access to a specially configured MyProxyCA service (
  http://grid.ncsa.illinois.edu/myproxy/ca/) configured with a custom PAM to 
  allow issue of credentials. See: 
  http://ndg-security.ceda.ac.uk/browser/trunk/MashMyData/pam_credential_translation
  
The examples should be used in conjunction with the ndg.oauth server package.
"""

setup(
    name =                      'ndg_oauth_client',
    version =                   '0.3.0',
    description =               'OAuth 2.0 client',
    long_description =          _long_description,
    author =                    'R. B. Wilkinson',
    maintainer =         	    'Philip Kershaw',
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
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
