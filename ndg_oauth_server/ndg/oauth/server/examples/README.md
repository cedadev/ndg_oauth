This directory contains example server configurations for ndg_oauth.  Each
configuration contains a simple script to run the server using paster and an
ini file which sets the combination of middleware and config settings needed.

bearer_tok/ -       uses string-based bearer tokens

slcs/ -             short-lived credential service returns an X.509 cert as 
                    token.  It uses MyProxy as a backend service to issue certs.  
                    A test MyProxyCA service (see 
                    http://grid.ncsa.illinois.edu/myproxy/ca/) is needed for 
                    this configured with a custom PAM to allow of a global
                    password. See: 
                    http://ndg-security.ceda.ac.uk/browser/trunk/MashMyData/pam_credential_translation

shared_config/ -    contains config files used by all example configurations

These examples should be used with their equivalent client apps in 
ndg.oauth.client.examples