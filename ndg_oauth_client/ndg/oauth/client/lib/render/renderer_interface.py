"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "28/02/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

class RendererInterface(object):
    """Interface for rendering templated pages.
    """
    def render(self, filename, parameters):
        """Render a page from a template.
        @type filename: basestring
        @param filename: filename of template
        @type parameters: dict
        @param parameters: parameters to substitute into template
        @rtype: basestring
        @return: rendered template
        """
        return None
