"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "R B Wilkinson"
__date__ = "12/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging
from ConfigParser import SafeConfigParser
log = logging.getLogger(__name__)

class ClientRegistration(object):
    """
    An entry in the client register.
    """
    def __init__(self, name, client_id, client_type, redirect_uris, authentication_data):
        self.name = name
        self.client_id = client_id
        self.client_type = client_type
        if redirect_uris:
            self.redirect_uris = [r.strip() for r in redirect_uris.split(',')]
        else:
            self.redirect_uris = []
        self.authentication_data = authentication_data

class ClientRegister(object):
    """
    Client reqister read from a configuration file
    """
    register = {}
    def __init__(self, config_file):
        config = SafeConfigParser()
        config.read(config_file)
        client_keys = config.get('client_register', 'clients').strip()
        if client_keys:
            for client_key in [k.strip() for k in client_keys.split(',')]:
                self._create_client(config, client_key, 'client')

    def _create_client(self, config, client_key, prefix):
        client_section_name = prefix + ':' + client_key
        client_id = config.get(client_section_name, 'id')
        client_registration = ClientRegistration(
            config.get(client_section_name, 'name'),
            config.get(client_section_name, 'id'),
            config.get(client_section_name, 'type'),
            config.get(client_section_name, 'redirect_uris'),
            config.get(client_section_name, 'authentication_data'))
        self.register[client_id] = client_registration

    def is_registered_client(self, client_id):
        """Determines if a client ID is in the client register.
        """
        if client_id not in self.register:
            return ('Client of id "%s" is not registered.' % client_id)
        return None

    def is_valid_client(self, client_id, redirect_uri):
        """Determines if a client ID is in the client register and the
        redirect_uri is registered for that client.
        """
        # Check if client ID is registered.
        if client_id not in self.register:
            return ('Client of id "%s" is not registered.' % client_id)
        client = self.register[client_id]

        if redirect_uri is None:
            if len(client.redirect_uris) != 1:
                return 'No redirect URI is registered for the client or specified in the request.'
        if redirect_uri is not None and redirect_uri not in client.redirect_uris:
            return 'Redirect URI is not registered.'
        return None
