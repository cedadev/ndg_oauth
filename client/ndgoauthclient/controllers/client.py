"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "09/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging

from pylons import request, session
from pylons.controllers.util import redirect

from ndg.httpsclient.ssl_context_util import SSlContextConfig

from ndgoauthclient.lib.base import BaseController, render
from ndgoauthclient.lib.oauth2client import Oauth2Client, Oauth2ClientConfig

log = logging.getLogger(__name__)

class ClientController(BaseController):
    """Skeleton test application acting as OAuth client.
    """
    SESSION_ID_KEY = 'oauth_client'
    client_cert = '/home/rwilkinson_local/dev/oauthclient/certificate/usercert.pem'
    client_key = '/home/rwilkinson_local/dev/oauthclient/certificate/userkey.pem'
    ca_dir = '/home/rwilkinson_local/dev/oauthclient/ca'
    ssl_config = SSlContextConfig(client_key, client_cert, None, ca_dir, True)

    def __init__(self):
        # TODO This should be configurable:
        self.client_config = Oauth2ClientConfig(
            client_id='11',
            authorization_endpoint='https://ice.badc.rl.ac.uk:5000/oauth/authorize',
            access_token_endpoint='https://ice.badc.rl.ac.uk:5000/oauth/access_token',
            base_url_path='client',
            redirect_uri='redirect_target',
            ssl_config=self.ssl_config)

    def index(self):
        """ Default action
        """
        return 'This is an OAuth 2.0 test client.'

    def hello(self):
        client = Oauth2Client.get_client_instance(session, self.client_config,
                                                  create=True)
        (result, redirect_url) = client.call_with_access_token(
            scope='scope1 scope2', application_url=request.application_url,
            callback=self.all_done)
        if redirect_url:
            redirect(redirect_url)
        else:
            return result

    def redirect_target(self):
        client = Oauth2Client.get_client_instance(session, self.client_config)
        if client:
            return client.call_with_access_token_redirected_back(request,
                                                        callback=self.all_done)
        else:
            return "No OAuth client created for session."

    def all_done(self, access_token, error, error_description):
        # Oauth2Client.delete_client_instance(session)
        return render('hello.html')
