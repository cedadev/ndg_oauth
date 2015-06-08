This directory contains example server configurations for ndg_oauth.  Each
configuration contains a simple script to run the server using paster and an
ini file which sets the combination of middleware and config settings needed.

bearer_tok/ -       uses string-based bearer tokens

slcs/ -             Resource server is a short-lived credential service (SLCS) -
					returns a user X.509 cert.  The SLCS implementation is based
					on the ContrailCA OnlineCAService.

shared_config/ -    contains config files used by all example configurations

These examples should be used with their equivalent client apps in 
ndg.oauth.client.examples