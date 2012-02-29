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

Prerequisites
=============
This has been developed and tested for Python 2.6.

Installation
============
Installation can be performed using easy_install or pip.  

Configuration
=============
An example of configuration is provided in the file development.ini. This
configures the components needed to authenticate users, obtain user
authorisation for an OAuth client and obtain a certificate to use as an access
token using MyProxyClient.
"""

setup(
    name =                      'ndg_oauth_server',
    version =                   '0.2.0',
    description =               'OAuth 2.0 server providing MyProxy certificates as access tokens',
    long_description =          _long_description,
    author =                    'R. B. Wilkinson',
    maintainer =         	'Philip Kershaw',
    maintainer_email =          'Philip.Kershaw@stfc.ac.uk',
    #url ='',
    license =                   'BSD - See LICENCE file for details',
    install_requires =[
        "PasteScript",
        "Beaker",
        "WebOb",
        "repoze.who",
        "MyProxyWebService",
        "Genshi",
    ],
    packages =find_packages(),
    zip_safe =False,
)
