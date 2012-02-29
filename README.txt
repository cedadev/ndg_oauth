Installation of NDG OAuth 2.0 Server Providing MyProxy Certificates as Access Tokens
====================================================================================
There are three primary components required:
o MyProxy server, installed as part of the Globus Toolkit. This acts as a certificate authority for the certificates issued as access tokens.
o OAuth server - This acts as a MyProxy client to create certificates for authenticated users. It also allows the user to determine whether a given OAuth client should be authorised.
o OAuth client - This requests MyProxy certificate access tokens from the OAuth server and makes them available to other applications in a Python WSGI stack.

The client contains a test WSGI application that simply displays the retrieved certificate.

These instructions are for OpenSUSE 11.2. Development was with Python 2.6.2.

The NDG OAuth source code is available from the Subversion repository at http://proj.badc.rl.ac.uk/svn/ndg-security/trunk/ndg_oauth.


Prerequisites
=============
The following should be installed:
  Apache2 server
  Apache2 mod_wsgi
  Python
  pam-devel


Globus Toolkit
==============
Install the Globus Toolkit following the instructions at this location (or the equivalent for the current release):
http://www.globus.org/toolkit/docs/5.0/5.0.4/admin/install/#gtadmin

Configure SimpleCA following:
http://www.globus.org/toolkit/docs/5.0/5.0.4/admin/install/#gtadmin-simpleca

Following these instructions:
Create a host certificate.
Create grid-mapfile with at least one user:
grid-mapfile-add-entry -dn <DN> -ln <login username>
in which the DN is the distinguished name to be put in certificates created for the specified username.

Configure MyProxy following:
http://www.globus.org/toolkit/docs/5.0/5.0.4/security/myproxy/admin/

Configure the $GLOBUS_LOCATION/etc/myproxy-server.config file. The relevant settings are of the following form (modify file locations as necessary):

certificate_issuer_cert /home/globus/.globus/simpleCA/cacert.pem
certificate_issuer_key /home/globus/.globus/simpleCA/private/cakey.pem
certificate_issuer_key_passphrase "changeit"
certificate_serialfile /home/globus/.globus/simpleCA/serial
certificate_out_dir /home/globus/.globus/simpleCA/newcerts
certificate_mapfile /etc/grid-security/grid-mapfile
cert_dir /etc/grid-security/certificates
pam  "sufficient"
pam_id "myproxy"

This assumes that initial MyProxy testing will be performed using operating system user accounts and the standard PAM login modules. This can be omitted and pam_credential_translation used instead (see the next section). 

Create /etc/pam.d/myproxy
#%PAM-1.0
auth     requisite      pam_nologin.so
auth     include        common-auth
account  include        common-account
session  required       pam_loginuid.so


In /etc/services add (from $GLOBUS_LOCATION/share/myproxy/etc.services.modifications):
myproxy-server  7512/tcp    # Myproxy server

Create a xinetd.d myproxy configuration file:
Copy $GLOBUS_LOCATION/share/myproxy/etc.xinetd.myproxy to /etc/xinetd.d/myproxy
Check this file - options to set locations include:
  server       = /usr/local/globus-5.0.4-oauth/sbin/myproxy-server
  server_args  = -c /usr/local/globus-5.0.4-oauth/etc/myproxy-server.config
  env          = GLOBUS_LOCATION=/usr/local/globus-5.0.4-oauth LD_LIBRARY_PATH=/usr/local/globus-5.0.4-oauth/lib

Ensure that the files referenced by myproxy-server.config can be read by the user configured to run the MyProxy server.

Update the xinetd configuration using "kill -HUP <xinetd PID>" or "service xinetd restart".


At this point it should be possible to use the online CA to via
myproxyclient logon -b -T -s <host> -p <port> -l <username> -C <trusted certificate dir.> -o <output credential file>

If the -C option is omitted, an appropriate default will be used (e.g., $HOME/.globus/certificates).


A host certificate/key pair is needed for the Apache server - this could be created using SimpleCA as follows, if a certificate from another source is not available:
Create a host credential file with a CN equal to the fully qualified host name following the procedure using grid-cert-request described in the SimpleCA configuration instructions referred to above except use the following options for grid-cert-request (to avoid the certificate CN including the prefix "host/"):
grid-cert-request -nopw -dir . -cn <fully qualified host name>

Create a single file with the certificate and private key:
cat usercert.pem userkey.pem > host.pem


pam_credential_translation configuration
========================================
Ensure that the pam-devel package is installed.
With Subversion, get http://proj.badc.rl.ac.uk/svn/ndg-security/trunk/MashMyData/pam_credential_translation

On OpenSUSE is was found necessary to add to pam_credential_translation.c the following function:

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pam_h,
                                int flags,
                                int argc,
                                const char **argv)
{
    return PAM_SUCCESS;
}

Execute make.
Put the created pam_credential_translation.so in /lib64/security
Check that file ownership and permissions are the same as for the other SOs in the directory.

Create the file
/etc/pam.d/myproxy-pam-credential-translation
The content should be of the form:

#%PAM-1.0
auth     required       pam_credential_translation.so  sha256passwd=<sha256 hash>
account  required       pam_credential_translation.so

<sha256 hash> is the SHA256 hash of the global password to be used by the MyProxy client to obtain certificates for the OAuth server. It can be found for a chosen password using:
echo -n <password> | sha256sum

To configure MyProxy to use this, set in $GLOBUS_LOCATION/etc/myproxy-server.config:

pam_id "myproxy-pam-credential-translation"


NDG OAuth Client installation
=============================
The NDG OAuth client egg is built by moving to the ndg_oauth/client directory in the source tree and running:
python setup.py bdist_egg


Logged in as a suitable user, install ndgoauthclient as follows:

Create a suitable installation directory and move to it, e.g.:
mkdir ~/ndgoauthclient
cd ~/ndgoauthclient

Get the ndgoauthclient egg and the following configuration files:
  buildout.cfg
  development.ini

Update in buildout.cfg:
find-links = <location of ndgoauthclient egg>

Build using the commands:
easy_install zc.buildout
buildout init
wget http://svn.zope.org/*checkout*/zc.buildout/trunk/bootstrap/bootstrap.py
python bootstrap.py
bin/buildout

This should result in the creation of a file parts/ndgoauthclient_wsgi/wsgi and the referenced eggs being placed in the eggs subdirectory.

Obtain a PEM encoded x509 certificate and key to be used by the client to authenticate itself to the OAuth server. The trusted CA certificate(s) needed to verify this must be present in the location configured for Apache set using the SSLCACertificatePath directive. This is in a virtual host .conf file in /etc/apache2/vhosts.d/ for the default Apache configuration.

Create a ndgoauthclient configuration file based on test_app.ini. The [server:main] section can be ignored when running under Apache. Set values for:

oauth2.client_cert = location of certificate file
oauth2.client_key = location of key file
oauth2.ca_dir = path of directory containing trusted CA certificates
                This should include the certificate(s) needed to verify the host certificate used by the Apache server.
oauth2.client_id = unique ID of the client (an arbitrary string)
oauth2.authorization_endpoint=<base URL of OAuth server>/oauth/authorize
oauth2.access_token_endpoint=<base URL of OAuth server>/oauth/access_token

In a production environment include:
set debug = false

Note that the directories specified by the following parameters must be writable by the user as which the OAuth client runs:
  beaker.cache.data_dir
  beaker.session.data_dir


Update the buildout.cfg file to set the .ini file location with the config-file parameter.


NDG OAuth Server installation
=============================
The NDG OAuth server egg is built by moving to the ndg_oauth/server directory in the source tree and running:
python setup.py bdist_egg


Logged in as a suitable user, install ndgoauthserver as follows:

Create a suitable installation directory and move to it, e.g.:
mkdir ~/ndgoauthserver
cd ~/ndgoauthserver

Get the ndgoauthserver egg and the following configuration files:
  buildout.cfg
  development.ini
  client_register.ini
  repoze_who.ini

Update in buildout.cfg:
find-links = <location of ndgoauthserver egg>

Build using the commands:
easy_install zc.buildout
buildout init
wget http://svn.zope.org/*checkout*/zc.buildout/trunk/bootstrap/bootstrap.py
python bootstrap.py
bin/buildout

This should result in the creation of a file parts/ndgoauthserver_wsgi/wsgi and the referenced eggs being placed in the eggs subdirectory.


Create a ndgoauthserver configuration file based on development.ini. The [server:main] section can be ignored when running under Apache. Set values for:
myproxy.client.hostname = host on which MyProxy server is running
myproxy.client.port = port on which MyProxy server is running if not the default value of 7512
myproxy.client.caCertDir = full path of directory containing certificates of trusted certificate authorities
oauth2server.myproxy_global_password = global password set for myproxy-pam-credential-translation PAM module

In a production environment include:
set debug = false

Note that the directories specified by the following parameters must be writable by the user as which the OAuth client runs:
  beaker.cache.data_dir
  beaker.session.data_dir
  oauth2server.cache.accesstokenregister.data_dir
  oauth2server.cache.authorizationgrantregister.data_dir

Update the buildout.cfg file to set the .ini file location with the config-file parameter.


Copy ndgoauthserver/templates/auth_client_form.html to a suitable location and set
oauth2authorization.client_authorization_form=<path>/auth_client_form.html


Create a password file:
htpasswd2 -c passwd <username>
Ensure that its location is as set in repoze_who.ini.
Add further users using:
htpasswd2 passwd <username>


Each OAuth client needs a x509 certificate with a different distinguished name (DN), since when using certificate authentication of the OAuth client to the server the DN is used to identify the client. (As described above, the client certificates must be issued by CAs trusted by Apache.) The client details are set in the server's client_register.ini file, which is of the following form:

[DEFAULT]

[client_register]
# Registered clients
clients=test1,test2

[client:test1]
name=test1
id=11
type=confidential
redirect_uris=http://host.inst.ac.uk:5001/oauth2/oauth_redirect
authentication_data=/O=inst/OU=simpleCA-host.inst.ac.uk/OU=inst.ac.uk/CN=test1.client

[client:test2]
...

The parameters have the following meanings:
  name = name of client displayed to user when asking for user authorisation for the client
  id = client ID set as the client configuration file value of oauth2.client_id
  redirect_uris = <OAuth client application base URL>/oauth2/oauth_redirect
                - a comma separated list of URLs to which the OAuth server should permit redirection back to the client.
  authentication_data = Distinguished name contained in the client certificate set as the client configuration file value of oauth2.client_cert

For the test application, create one client entry.


Apache
======
The OAuth server should be configured within a SSL container.

    <Directory "/home/oauthserver/ndgoauthserver/parts/ndgoauthserver_wsgi">
        SSLVerifyClient optional_no_ca
        SSLVerifyDepth  10
        SSLOptions +StdEnvVars +ExportCertData

        # Pass the Authorization header to the WSGI middleware/application.
        WSGIPassAuthorization On

        Order allow,deny
        Allow from all
    </Directory>

    WSGIDaemonProcess oauth2-server processes=2 threads=15 display-name=%{GROUP} user=oauthserver group=oasgroup
    WSGIProcessGroup oauth2-server

    # OAuth 2.0 authorization server
    WSGIScriptAlias /oas /home/oauthserver/ndgoauthserver/parts/ndgoauthserver_wsgi/wsgi


The OAuth client may be configured without SSL.

    <Directory "/home/rwilkinson_local/dev/ndgoauthclient_bo/parts/ndgoauthclient_wsgi">
       Order allow,deny
       Allow from all
    </Directory>

    WSGIDaemonProcess oauth2-client processes=2 threads=15 display-name=%{GROUP} user=oauthclient group=oacgroup
    WSGIProcessGroup oauth2-client

    WSGIScriptAlias /oac /home/oauthclient/ndgoauthclient/parts/ndgoauthclient_wsgi/wsgi


Summary of Certificates and Trusted CAs
=======================================
There are four sets of certificate and trusted CA relationships, all of which must be configured correctly for the system to work:

1) Apache host certificate / OAuth2 client trusted CAs
Certificate location:
Apache parameter: SSLCertificateFile
Key location:
Apache parameter: SSLCertificateKeyFile

CA configuration:
OAuth2 client parameter: oauth2.ca_dir

2) OAuth2 client certificate / Apache trusted CAs
Certificate location:
OAuth2 client parameter: oauth2.client_cert
Key location:
OAuth2 client parameter: oauth2.client_key

CA configuration:
Apache parameter: SSLCACertificatePath

3) MyProxy server certificate / MyProxyClient trusted CAs
Certificate location:
By default: /etc/grid-security/hostcert.pem
Overide by setting the environment variable X509_USER_CERT in the /etc/xinetd.d/myproxy
Key location:
By default: /etc/grid-security/hostkey.pem
Overide by setting the environment variable X509_USER_KEY in the /etc/xinetd.d/myproxy

CA configuration:
myproxy.client.caCertDir

4) MyProxy Server CA certificate / service accepting certificates from MyProxy Online CA 
Certificate and key location:
The OAuth access token contains the certificate and key

CA configuration:
Dependent on service. The CA certificate and key are configured with:
Certificate location:
myproxy-server.config parameter: certificate_issuer_cert
Key location:
myproxy-server.config parameter: certificate_issuer_key
The certificates downloaded using "myproxyclient logon -T" should include the required trusted certificates.
