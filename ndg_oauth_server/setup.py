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
This is an OAuth 2.0 server library and WSGI middleware filter.

It supports simple string-based bearer token and a custom extension to enable 
the use of X.509 certificates as tokens.  The latter has been added for a
specialised use case to enable a SLCS (Short-lived Credential Service) to issue 
delegated X.509-based credentials with OAuth.

Releases
========
0.5.1
-----
Integrated enhancements from Willem van Engen including:

 * password-based client authentication, which is a commonly used client
   authentication method
 * resource authentication for the check_token endpoint, to avoid brute-force
   attacks on token check; also provides a starting point for audience-restricted
   tokens and resource-restricted attribute release
 * return user attribute from check_token endpoint, so that the resource knows
   what the user is; attribute name user_name according to CloudFoundry

Resource and client authentication use the same classes, and now are instantiated
with a string indicating their use (to give meaningful log messages). The
client_authenticator interface was removed, since all authenticators can derive
directly from authenticator_interface, since they're both used for clients and
resources; they were also renamed to make that clear (removing _client).

In client_register.ini and resource_register.ini (the latter is new) the field
secret is optional.

Client code is unchanged.

0.4.0
-----
 * Revised examples in ndg.oauth.client.examples.  bearer_tok uses bearer token
   to secure access to a simple html page on a resource server, slcs is an 
   example protecting a short-lived credential service aka. Online Certificate 
   Authority.  This requires the ContrailOnlineCAService package and should be 
   used in conjunction with the equivalent example in the ndg_oauth_client 
   example.
 * Added discrete WSGI resource server middleware 
   ndg.oauth.server.wsgi.resource_server.Oauth2ResourceServerMiddleware
 * Includes support for bearer access token passed in Authorization header to
   resource server.
 
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
  
The examples should be used in conjunction with the ndg_oauth_client package.
"""

setup(
    name =                      'ndg_oauth_server',
    version =                   '0.6.0',
    description =               'OAuth 2.0 server',
    long_description =          _long_description,
    author =                    'R. B. Wilkinson',
    maintainer =         	    'Philip Kershaw',
    maintainer_email =          'Philip.Kershaw@stfc.ac.uk',
    url =                       'https://github.com/cedadev/ndg_oauth/',
    license =                   'BSD - See LICENCE file for details',
    install_requires =[
        "PasteScript",
        "Beaker",
        "WebOb",
        "repoze.who",
        "Genshi",
    ],
    packages = find_packages(),
    package_data =      {
        'ndg.oauth.server.templates': [
            '*.html', 'public/js/*.js', 'public/layout/*.css',
            'public/layout/*.png', 'public/layout/icons/*.png'
        ],
        'ndg.oauth.server.examples': [
            'README'
        ],
        'ndg.oauth.server.examples.bearer_tok': [
            'README', 'passwd', '*.ini', 'templates/*.html', 
            'static/layout/*.css', 'static/layout/*.png'
        ],
        'ndg.oauth.server.examples.slcs': [
            'README', 'passwd', '*.ini', 'templates/*.html', 
            'static/layout/*.css', 'static/layout/*.png'
        ],
        'ndg.oauth.server.examples.shared_config': [
            'README', 'pki/*.pem', 'pki/ca/*.0'
        ]
    },
    extras_require = {
        'test-services': ['Genshi==0.6']
    },
    zip_safe = False,
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
