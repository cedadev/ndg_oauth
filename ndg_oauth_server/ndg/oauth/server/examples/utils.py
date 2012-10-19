"""NDG OAuth Paste utilities for example code

"""
__author__ = "P J Kershaw"
__date__ = "19/10/12"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id:$"
from os import path
from threading import Thread
import optparse

from OpenSSL import crypto, SSL
from paste.deploy import loadapp
from paste.script.util.logging_config import fileConfig
import paste.httpserver


THIS_DIR = path.dirname(__file__)
SHARED_CONFIG_DIR  = path.join(THIS_DIR, 'shared_config')
PKI_DIR = path.join(SHARED_CONFIG_DIR, 'pki') 
CACERT_DIR = path.join(PKI_DIR, 'ca')


def serve_app(config_filepath):     
    defCertFilePath = path.join(PKI_DIR, 'host.pem')
    defPriKeyFilePath = path.join(PKI_DIR, 'host.pem')
        
    parser = optparse.OptionParser()
    parser.add_option("-p",
                      "--port",
                      dest="port",
                      default=5000,
                      type='int',
                      help="port number to run under")

    parser.add_option("-s",
                      "--with-ssl",
                      dest="with_ssl",
                      default='True',
                      help="Run with SSL")

    parser.add_option("-c",
                      "--cert-file",
                      dest='certFilePath',
                      default=defCertFilePath,
                      help="SSL Certificate file")

    parser.add_option("-k",
                      "--private-key-file",
                      default=defPriKeyFilePath,
                      dest='priKeyFilePath',
                      help="SSL private key file")

    parser.add_option("-f",
                      "--conf",
                      dest="configFilePath",
                      default=config_filepath,
                      help="Configuration file path")
    
    parser.add_option("-a",
                      "--with-ssl-client-auth",
                      dest="ssl_client_authn",
                      action='store_true',
                      default=True,
                      help="Set client authentication with SSL (requires -s "
                           "option")
    
    opt = parser.parse_args()[0]
    config_filepath = path.abspath(opt.configFilePath)
    
    if opt.with_ssl.lower() == 'true':
        ssl_context = SSL.Context(SSL.SSLv23_METHOD)
    
        ssl_context.set_session_id('oauthserver')
        ssl_context.use_privatekey_file(opt.priKeyFilePath)
        ssl_context.use_certificate_file(opt.certFilePath)
        
        ssl_context.load_verify_locations(None, CACERT_DIR)
        ssl_context.set_verify_depth(9)
        
        # Load the application from the Paste ini file configuration        
        fileConfig(config_filepath, 
                   defaults={'here': path.dirname(config_filepath)})
        app = loadapp('config:%s' % config_filepath)
        
        if opt.ssl_client_authn:
            # Wrap the application in middleware to set the SSL client certificate 
            # obtained from the SSL handshake in environ                
            app = OpenSSLVerifyCallbackMiddleware(app)
            _callback = app.create_ssl_callback()
            
            # Wrap in middleware to simulate Apache environment
            app = ApacheSSLVariablesMiddleware(app)
        
            ssl_context.set_verify(SSL.VERIFY_PEER, _callback)
            
        server = PasteDeployAppServer(app=app, 
                                      port=opt.port,
                                      ssl_context=ssl_context) 
    else:
        server = PasteDeployAppServer(config_filepath=config_filepath, 
                                      port=opt.port) 
    server.start()


class PasteDeployAppServer(object):
    """Wrapper to paste.httpserver to enable background threading"""
    
    def __init__(self, app=None, config_filepath=None, port=7443, host='0.0.0.0',
                 ssl_context=None):
        """Load an application configuration from config_filepath ini file and 
        instantiate Paste server object
        """       
        self.__thread = None
        
        if config_filepath:
            if app:
                raise KeyError('Set either the "config_filepath" or "app" '
                               'keyword but not both')
            
            fileConfig(config_filepath, 
                       defaults={'here':path.dirname(config_filepath)})
            app = loadapp('config:%s' % config_filepath)
            
        elif app is None:
            raise KeyError('Either the "config_filepath" or "app" keyword must '
                           'be set')
                       
        self.__paste_server = paste.httpserver.serve(app, host=host, port=port, 
                                                    start_loop=False, 
                                                    ssl_context=ssl_context)
    
    @property
    def pasteServer(self):
        return self.__paste_server
    
    @property
    def thread(self):
        return self.__thread
    
    def start(self):
        """Start server"""
        self.pasteServer.serve_forever()
        
    def startThread(self):
        """Start server in a separate thread"""
        self.__thread = Thread(target=PasteDeployAppServer.start, args=(self,))
        self.thread.start()
        
    def terminateThread(self):
        self.pasteServer.server_close()

 
class OpenSSLVerifyCallbackMiddleware(object):
    """Set peer certificate retrieved from PyOpenSSL SSL context callback in
    environ dict SSL_CLIENT_CERT item
    
    FOR TESTING PURPOSES ONLY - IT IS NOT THREAD SAFE
    """
    def __init__(self, app):
        self._app = app
        self.ssl_client_cert = None
        self.ssl_client_cert_dn = None
        self.ignore_pat = None
        
    def create_ssl_callback(self):
        """Make a SSL Context callback function and return it to the caller"""
        def _callback(conn, x509, errnum, errdepth, ok):
            if errdepth == 0:
                subject = x509.get_subject()
                components = subject.get_components()
                if self.ignore_pat not in [i[-1] for i in components]:
                    self.ssl_client_cert = crypto.dump_certificate(
                                                    crypto.FILETYPE_PEM, x509)
                    self.ssl_client_cert_dn = '/'+ '/'.join(
                                        ['%s=%s' % i for i in components])
            return ok
        
        return _callback
        
    def __call__(self, environ, start_response):
        """Set the latest peer SSL client certificate from the SSL callback
        into environ SSL_CLIENT_CERT key"""
        if self.ssl_client_cert:
            environ['SSL_CLIENT_CERT'] = self.ssl_client_cert
            environ['SSL_CLIENT_S_DN'] = self.ssl_client_cert_dn
            self.ssl_client_cert = None

        return self._app(environ, start_response)
    

class ApacheSSLVariablesMiddleware(object):
    """Simulate Apache SSL environment setting relevant environ variables"""
    def __init__(self, app):
        self._app = app
                                 
    def __call__(self, environ, start_response):
        environ['HTTPS'] = '1'
        return self._app(environ, start_response)
