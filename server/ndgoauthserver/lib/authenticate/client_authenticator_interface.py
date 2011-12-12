"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

from abc import ABCMeta, abstractmethod
class ClientAuthenticatorInterface(object):
    """
    Interface for client authenticators.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def authenticate(self, request):
        """
        Returning None implies client id is not to be checked against grant.
        Implementations should raise OauthException if authentication fails.

        @type request: webob.Request
        @param request: HTTP request object

        @rtype: str
        @return: ID of authenticated client, or None if authentication is not to
        be performed.
        """
        return None
