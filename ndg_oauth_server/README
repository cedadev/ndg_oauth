This is an OAuth 2.0 server library and WSGI middleware filter.

Releases
========
0.6.0
-----
 * Clean up of password-based authentication of client by authorization server
 * Removal of redundant MyProxy hooks
 
0.5.1
-----
Integrated enhancements from Willem van Engen including:

 * password-based client authentication, which is a commonly used client
   authentication method
 * resource authentication for the check_token endpoint, to avoid brute-force
   attacks on token check; also provides a starting point for audience-restricted
   tokens and resource-restricted attribute release
 * return user attribute from check_token endpoint, so that the resource knows
   what the user is; attribute name user_name according to CloudFoundry

Resource and client authentication use the same classes, and now are instantiated
with a string indicating their use (to give meaningful log messages). The
client_authenticator interface was removed, since all authenticators can derive
directly from authenticator_interface, since they're both used for clients and
resources; they were also renamed to make that clear (removing _client).

In client_register.ini and resource_register.ini (the latter is new) the field
secret is optional.

Client code is unchanged.

0.4.0
-----
 * Revised examples in ndg.oauth.client.examples.  bearer_tok uses bearer token
   to secure access to a simple html page on a resource server, slcs is an 
   example protecting a short-lived credential service aka. Online Certificate 
   Authority.  This requires the ContrailOnlineCAService package and should be 
   used in conjunction with the equivalent example in the ndg_oauth_client 
   example.
 * Added discrete WSGI resource server middleware 
   ndg.oauth.server.wsgi.resource_server.Oauth2ResourceServerMiddleware
 * Includes support for bearer access token passed in Authorization header to
   resource server.
 
Prerequisites
=============
This has been developed and tested for Python 2.6 and 2.7.

Installation
============
Installation can be performed using easy_install or pip.  

Configuration
=============
Examples are contained in the examples/ sub-folder:

bearer_tok/:
  This configures a simple test application that uses string based tokens.
slcs/:
  Bearer token example protecting a Short-Lived Credential Service or OnlineCA.
  ContrailOnlineCAService package is needed for this example.
  
The examples should be used in conjunction with the ndg_oauth_client package.
