"""OAuth 2.0 WSGI server middleware providing MyProxy certificates as access tokens
"""
__author__ = "W V Engen"
__date__ = "13/11/12"
__copyright__ = "(C) 2012 FOM / Nikhef"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "wvengen@nikhef.nl"
__revision__ = "$Id$"
import logging
from ConfigParser import SafeConfigParser
log = logging.getLogger(__name__)


class ResourceRegistration(object):
    """
    An entry in the resource register.
    """
    def __init__(self, name, resource_id,
                 resource_secret, authentication_data):
        self.name = name
        self.id = resource_id
        self.secret = resource_secret
        self.authentication_data = authentication_data


class ResourceRegister(object):
    """
    Resource reqister read from a configuration file
    """
    register = {}
    def __init__(self, config_file=None):
        if config_file:
            config = SafeConfigParser()
            config.read(config_file)
            resource_keys = config.get('resource_register', 'resources').strip()

            if resource_keys:
                for resource_key in [k.strip() for k in resource_keys.split(',')]:
                    self._create_resource(config, resource_key, 'resource')

    def _create_resource(self, config, resource_key, prefix):
        resource_section_name = prefix + ':' + resource_key
        resource_id = config.get(resource_section_name, 'id')
        resource_secret = None

        if config.has_option(resource_section_name, 'secret'):
            resource_secret = config.get(resource_section_name, 'secret')

        resource_authentication_data = None
        if config.has_option(resource_section_name, 'authentication_data'):
            resource_authentication_data = config.get(resource_section_name, 'authentication_data')

        resource_registration = ResourceRegistration(
            config.get(resource_section_name, 'name'),
            resource_id,
            resource_secret,
            resource_authentication_data)
        self.register[resource_id] = resource_registration

    def is_registered_resource(self, resource_id):
        """Determines if a resource ID is in the resource register.
        """
        if resource_id not in self.register:
            return ('Resource of id "%s" is not registered.' % resource_id)

        return None

