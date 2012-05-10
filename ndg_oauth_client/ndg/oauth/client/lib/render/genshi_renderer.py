"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "28/02/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import os

from genshi.template import TemplateLoader

from ndg.oauth.client.lib.render.renderer_interface import RendererInterface

class GenshiRenderer(RendererInterface):
    """Implementation of the renderer interface using Genshi
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
        fname = os.path.basename(filename)
        dirname = os.path.dirname(filename)
        loader = TemplateLoader(dirname, auto_reload=True)
        tmpl = loader.load(fname)
        response = tmpl.generate(c=parameters).render('html')
        return response
