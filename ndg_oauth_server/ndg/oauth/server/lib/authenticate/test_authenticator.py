"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from ndg.oauth.server.lib.authenticate.authenticator_interface import AuthenticatorInterface

class TestAuthenticator(AuthenticatorInterface):
    def authenticate(self, params):
        """Test implementation of user authenticator.
        @type params: dict
        @param params: request parameters

        @rtype: bool
        @return: True if user authenticated
        """
        if params.get('identifier', None) and params.get('password', '') == 'test':
            return True
        return False
