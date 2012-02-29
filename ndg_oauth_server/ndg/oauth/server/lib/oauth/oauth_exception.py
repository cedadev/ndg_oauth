"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

class OauthException(Exception):
    """
    Exception representing OAuth errors
    """
    def __init__(self, error, error_description):
        self.error = error
        self.error_description = error_description

    def __str__(self):
        return("%s: %s" % (self.error, self.error_description))
