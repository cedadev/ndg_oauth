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

import os

THIS_DIR = os.path.dirname(__file__)
try:
    LONG_DESCR = open(os.path.join(THIS_DIR, 'README.md')).read()
except IOError:
    LONG_DESCR = """This is an OAuth 2.0 client library and WSGI middleware 
filter.
"""

setup(
    name =                      'ndg_oauth_client',
    version =                   '0.6.0',
    description =               'OAuth 2.0 client',
    long_description =          LONG_DESCR,
    author =                    'R. B. Wilkinson',
    maintainer =         	    'Philip Kershaw',
    maintainer_email =          'Philip.Kershaw@stfc.ac.uk',
    url =                       'https://github.com/cedadev/ndg_oauth/',
    license =                   'BSD - See LICENCE file for details',
    install_requires =[
        "PasteScript",
        "Beaker",
        "WebOb",
        "pyOpenSSL",
        "ndg_httpsclient",
        "pyasn1",
    ],
    extras_require = {
        'test-services': ['Genshi==0.6']
    },
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
