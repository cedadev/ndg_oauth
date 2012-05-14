"""Plugin package for repoze.who including comparison of passwords against
stored MD5 hash and a variant of the SQLAuthenticatorPlugin supplied with
repoze.who that can be configured via the repoze.wno configuration file.
Substantially based on repoze.who.plugins.sql from version 2.0.
"""
__author__ = "R B Wilkinson"
__date__ = "11/05/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import logging
log = logging.getLogger(__name__)

try:
    from hashlib import md5
except ImportError: # Python < 2.5
    from md5 import new as md5

from zope.interface import implements
from repoze.who.interfaces import IAuthenticator
from repoze.who.plugins.sql import (default_password_compare,
                        SQLAuthenticatorPlugin as DefaultSQLAuthenticatorPlugin)

def md5_password_compare(cleartext_password, stored_password_hash):
    """Password comparison function suitable for use with repoze.who, for
    passwords stored as MD5 hashes.
    @type cleartext_password: basestring
    @param cleartext_password: cleartext password
    @type stored_password_hash: basestring
    @rtype: bool
    @return: True if the MD5 hash formed from the cleartext password matches
    the supplied stored hash, otherwise False
    """
    log.debug("Checking for match of password against hash '%s'",
              stored_password_hash)
    digest = md5(cleartext_password).hexdigest()

    if stored_password_hash == digest:
        return True

    return False

def make_psycopg_conn_factory(**kw):
    """Constructor of PostgreSQL connection factory using psycopg2.
    @type kw: dict
    @param kw: configuration options: should include the PostgreSQL connection
    string with key 'connection_string'
    """
    def conn_factory():
        import psycopg2
        return psycopg2.connect(kw['connection_string'])
    return conn_factory

class SQLAuthenticatorPlugin(DefaultSQLAuthenticatorPlugin):
    """Extension of repoze.who.plugins.sql.SQLAuthenticatorPlugin that allows
    configuration from a repoze.who configuration file:
    o allows additional keywords to be passed in so that a connection string
      can be set for the connection factory
    o allows a format for the query string that does not cause problems with
      ConfigParser parsing of the configuration file.
    """
    implements(IAuthenticator)

    def __init__(self, query, conn_factory, compare_fn, **kw):
        """
        Differs from repoze.who.plugins.sql:SQLAuthenticatorPlugin.__init__ only
        in the presence of the kw parameter. This is available to the connection
        factory.
        @type query: basestring
        @param query: SQL query to return the username and p
        @type conn_factory: function
        @param conn_factory: database connection factory
        @type compare_fn: function
        @param compare_fn: function to compare supplied and stored passwords
        @type kw: dict
        @param kw: additional configuration options that may be used by the
        connection factory constructor
        """
        # statement should be pyformat dbapi binding-style, e.g.
        # "select user_id, password from users where login=%(login)s"
        # Unfortunately, repose.who 2.0 uses ConfigParser, not SafeConfigParser,
        # making it impossible to include a pyformat query in the configuration
        # file (since there is no escaping mechanism). Allow '#(' to be used
        # instead of '%('.
        self.query = query.replace('#(', '%(')
        self.conn_factory = conn_factory
        self.compare_fn = compare_fn or default_password_compare
        self.conn = None

def make_authenticator_plugin(query=None, conn_factory=None,
                              compare_fn=None, **kw):
    """
    Differs from repoze.who.plugins.sql.make_authenticator_plugin only in that
    kw is passed to SQLAuthenticatorPlugin.
    @type query: basestring
    @param query: SQL query to return the username and p
    @type conn_factory: function
    @param conn_factory: database connection factory
    @type compare_fn: function
    @param compare_fn: function to compare supplied and stored passwords
    @type kw: dict
    @param kw: additional configuration options that are passed to the
    SQLAuthenticatorPlugin constructor
    """
    from repoze.who.utils import resolveDotted
    if query is None:
        raise ValueError('query must be specified')
    if conn_factory is None:
        raise ValueError('conn_factory must be specified')
    try:
        conn_factory = resolveDotted(conn_factory)(**kw)
    except Exception, why:
        raise ValueError('conn_factory could not be resolved: %s' % why)
    if compare_fn is not None:
        compare_fn = resolveDotted(compare_fn)
    return SQLAuthenticatorPlugin(query, conn_factory, compare_fn, **kw)
