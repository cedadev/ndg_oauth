#!/usr/bin/env python
"""NDG OAuth test harness for Short-Lived Credential Service bearer token 
example

"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id:$"  
from os import path
import optparse

from OpenSSL import SSL
import paste.httpserver
from paste.deploy import loadapp
from paste.script.util.logging_config import fileConfig

THIS_DIR = path.dirname(path.abspath(__file__))                                  
INI_FILENAME = "slcs_server_app.ini"
INI_FILEPATH = path.join(THIS_DIR, INI_FILENAME) 
SHARED_CONFIG_DIR = path.join(path.dirname(THIS_DIR), 'shared_config')
DEFAULT_PORT = 5000

# if __name__ == '__main__':    
#     serve_app(INI_FILENAME)
if __name__ == '__main__':       
    def_cert_filepath = path.join(SHARED_CONFIG_DIR, 'pki', 'localhost.crt')
    def_prikey_filepath = path.join(SHARED_CONFIG_DIR, 'pki', 'localhost.key')
    
    parser = optparse.OptionParser()
    parser.add_option("-p",
                      "--port",
                      dest="port",
                      default=DEFAULT_PORT,
                      type='int',
                      help="port number to run under")

    parser.add_option("-s",
                      "--with-ssl",
                      dest="withSSL",
                      default='True',
                      help="Run with SSL")

    parser.add_option("-c",
                      "--cert-file",
                      dest='cert_filepath',
                      default=def_cert_filepath,
                      help="SSL Certificate file")

    parser.add_option("-k",
                      "--private-key-file",
                      dest='prikey_filepath',
                      default=def_prikey_filepath,
                      help="SSL private key file")

    parser.add_option("-f",
                      "--conf",
                      dest="cfg_filepath",
                      default=INI_FILEPATH,
                      help="Configuration file path")
    
    opt = parser.parse_args()[0]
    
    if opt.withSSL.lower() == 'true':        
        ssl_context = SSL.Context(SSL.TLSv1_METHOD)
    
        ssl_context.use_privatekey_file(opt.prikey_filepath)
        ssl_context.use_certificate_file(opt.cert_filepath)
    else:
        ssl_context = None
        
    fileConfig(opt.cfg_filepath, 
               defaults={'here':path.dirname(opt.cfg_filepath)})
    
    app = loadapp('config:%s' % opt.cfg_filepath)
    
    server = paste.httpserver.serve(app, host='localhost', port=opt.port, 
                                    start_loop=False, ssl_context=ssl_context)
 
    server.serve_forever()