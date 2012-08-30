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
  based tokens as part of a Short-lived Credential Service.  The authorisation
  server requires access to a specially configured MyProxyCA service (
  http://grid.ncsa.illinois.edu/myproxy/ca/) configured with a custom PAM to 
  allow issue of credentials. See: 
  http://ndg-security.ceda.ac.uk/browser/trunk/MashMyData/pam_credential_translation
  
The examples should be used in conjunction with the ndg.oauth client package.
"""

setup(
    name =                      'ndg_oauth_server',
    version =                   '0.3.1',
    description =               'OAuth 2.0 server',
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
        "repoze.who",
        "Genshi",
    ],
    extras_require = {'slcs_support': 'MyProxyClient'},
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
