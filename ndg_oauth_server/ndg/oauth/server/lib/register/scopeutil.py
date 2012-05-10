"""OAuth 2.0 WSGI server middleware - utilities for handling scope strings and
lists
"""
__author__ = "R B Wilkinson"
__date__ = "28/03/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging
import urllib

log = logging.getLogger(__name__)

def scopeStringToList(scope_str):
    """Converts a scope string to a list. The strings are space separated and
    must not contain '"' or '\' so allow them to be URL encoded.
    @type scope_str: basestring
    @param scope_str: space separated list of scopes
    @rtype: list of basestring
    @return: list of scopes
    """
    result = []
    if scope_str:
        for s in scope_str.split():
            result.append(urllib.unquote_plus(s))
    log.debug("Converted scope string %s to %r", scope_str, result)
    return result

def isScopeGranted(granted_scope, requested_scope):
    """Determines whether all scopes requested have been granted.
    @type granted_scope: list of basestring
    @param granted_scope: list of granted scopes
    @type requested_scope: list of basestring
    @param requested_scope: list of requested scopes
    @rtype: bool
    @return: True if all requested scopes are in the list of granted scopes,
    or if no scopes are requested, otherwise False
    """
    result = True
    for s in requested_scope:
        if s not in granted_scope:
            result = False
    log.debug(
        "Checking for requested scopes %r in granted scopes %r - result: %r",
        requested_scope, granted_scope, result)
    return result
