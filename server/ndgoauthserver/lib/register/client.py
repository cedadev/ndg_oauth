'''
Created on 16 Nov 2011

@author: rwilkinson
'''
import logging
from ConfigParser import SafeConfigParser
log = logging.getLogger(__name__)

class ClientRegistration(object):
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

    def is_valid_client(self, client_id, redirect_uri):
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
