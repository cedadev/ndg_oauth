#!/usr/bin/env python
"""NDG OAuth test harness for bearer token example

"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id:$"  
from os import path
                                     
from ndg.oauth.server.examples.utils import serve_app
                                      
INI_FILENAME = 'bearer_tok_server_app.ini'

# To start run 
# $ paster serve services.ini or run this file as a script, see
# $ ./securityservicesapp.py -h
if __name__ == '__main__':    
    config_filepath = path.join(path.dirname(path.abspath(__file__)), 
                                INI_FILENAME) 
    serve_app(INI_FILENAME)