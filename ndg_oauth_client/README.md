This is an OAuth 2.0 client library and WSGI middleware filter.

Releases
========
0.6.0
-----
 * Clean up of password-based authentication of client by authorization server
 * Removal of redundant MyProxy hooks

0.5.1
-----
New pseudo release to keep in sync with ndg_oauth_server package versioning. No
changes from 0.4.0.  New ndg_oauth_server 0.5.1 contains enhancements from W
van Engen including support for password based authentication for clients. See
ndg_oauth_server package for details.

0.4.0
-----
 * Revised examples in ndg.oauth.client.examples.  bearer_tok uses bearer token
   to secure access to a simple html page on a resource server, slcs is an 
   example protecting a short-lived credential service aka Online Certificate 
   Authority.  This requires the ContrailOnlineCAClient package and should be 
   used in conjunction with the equivalent example in the ndg_oauth_server 
   example.
 * Revised ndg.oauth.client.lib.oauth2client.Oauth2Client to include support for
   bearer access token passed in Authorization header to resource server.
 
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
  
The examples should be used in conjunction with the ndg_oauth_server package.
