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

Releases
========
0.4.0
-----
 * Revised examples in ndg.oauth.client.examples.  bearer_tok uses bearer token
   to secure access to a simple html page on a resource server, slcs is an 
   example protecting a short-lived credential service aka Online Certificate 
   Authority.  This requires the ContrailOnlineCAClient package and should be 
   used in conjunction with the equivalent example in the ndg_oauth_server 
   example.
 * Revised ndg.oauth.client.lib.oauth2client.Oauth2Client to include support for
   bearer access token passed in Authorization header to resource server.
 
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
  Bearer token example protecting a Short-Lived Credential Service or OnlineCA.
  ContrailOnlineCAService package is needed for this example.
  
The examples should be used in conjunction with the ndg_oauth_server package.
"""

setup(
    name =                      'ndg_oauth_client',
    version =                   '0.4.0',
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
    package_data =      {
        'ndg.oauth.client.templates': [
            '*.html', 'public/layout/*.css', 'public/layout/*.png',
            'public/layout/icons/*.png'
        ],
        'ndg.oauth.client.examples': [
            'README'
        ],
        'ndg.oauth.client.examples.bearer_tok': [
            'README', '*.ini'
        ],
        'ndg.oauth.client.examples.slcs': [
            'README', '*.ini'
        ],
        'ndg.oauth.client.examples.shared_config': [
            'README', 'pki/*.crt', 'pki/*.key', 'pki/ca/*.0'
        ]
    },
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
