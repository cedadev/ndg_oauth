Example OAuth 2.0 bearer token authorisation and resource server app
====================================================================
This example uses simple string based bearer tokens.  It protects a short-lived
credential service (SLCS) which issues X.509 certificates to delegated clients.
The service requires the Grid software package MyProxyCA from the Globus 
toolkit.  This service fronts MyProxyCA and uses it for certificate issuing.
The example can be run without it to show the step to obtain an access token.
However, it is needed for showing access to a resource (aka requesting a 
certificate).

Two components are provided then:
 * a generic OAuth Authorisation Server which authenticates users by 
   username/password on a web form
 * a resource server.  This is a specialised one which enables delegated 
   clients to obtain short-lived X.509 certificate credentials.  It does this
   by using MyProxyCA as a backend certificate issuing service.  A MyProxyCA
   instance is required to demonstrate this but not to demonstrate the 
   authorisation service.
   
To Run
======

$ python bearer_tok_server_app_serve.py

Run equivalent client app under ndg.oauth.client.examples.bearer_tok in order to
test.  Open a browser:
 * http://localhost:5002/token to show the step for getting an access token.  
 * http://localhost:5002/resource to show requesting a resource (a certificate).
 
The log in 
credentials for the authorisation server are username: rwilkinson_local, 
password: changeme.  Clear out cookies to reset between test runs.

