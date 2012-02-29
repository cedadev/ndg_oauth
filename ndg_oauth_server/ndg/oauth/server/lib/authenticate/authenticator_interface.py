"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from abc import ABCMeta, abstractmethod
class AuthenticatorInterface(object):
    """
    Interface for user authentication.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def authenticate(self, params):
        """Authenticates a user.
        @type params: dict
        @param params: request parameters

        @rtype: bool
        @return: True if user authenticated
        """
        return None
