"""NDG OAuth 2.0 

Example paster script to run bearer token example client app
"""
__author__ = "Philip Kershaw"
__date__ = "24/08/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from paste.script.serve import ServeCommand

ServeCommand("serve").run(["./bearer_tok_client_app.ini"])
