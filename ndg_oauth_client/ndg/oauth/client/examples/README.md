This directory contains example client configurations for ndg_oauth.  Each
configuration contains a simple script to run the server using paster and an
ini file which sets the combination of middleware and config settings needed.

bearer_tok/ -       use string-based bearer tokens

slcs/ -             retrieve an X.509 cert.-based credentials
shared_config/ -    contains config files used by all example configurations

These examples should be used with their equivalent authorisation/resource
server apps in ndg.oauth.server.examples from the ndg_oauth_server package.