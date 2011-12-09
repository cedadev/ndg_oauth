from OpenSSL import crypto

PRIKEY_NBITS = 4096
MESSAGE_DIGEST_TYPE = "md5"

def createKeyPair(nBitsForKey=PRIKEY_NBITS):
    """Generate key pair and return as PEM encoded string
    @type nBitsForKey: int
    @param nBitsForKey: number of bits for private key generation - 
    default is 2048
    @rtype: OpenSSL.crypto.PKey
    @return: public/private key pair
    """
    keyPair = crypto.PKey()
    keyPair.generate_key(crypto.TYPE_RSA, nBitsForKey)
    
    return keyPair
        
def createCertReq(CN, keyPair, messageDigest=MESSAGE_DIGEST_TYPE):
    """Create a certificate request.
    
    @type CN: basestring
    @param CN: Common Name for certificate - effectively the same as the
    username for the MyProxy credential
    @type keyPair: string/None
    @param keyPair: public/private key pair
    @type messageDigest: basestring
    @param messageDigest: message digest type - default is MD5
    @rtype: base string
    @return certificate request PEM text and private key PEM text
    """
    
    # Check all required certificate request DN parameters are set                
    # Create certificate request
    certReq = crypto.X509Req()
    
    # Create public key object
    certReq.set_pubkey(keyPair)
    
    # Add the public key to the request
    certReq.sign(keyPair, messageDigest)
    
    derCertReq = crypto.dump_certificate_request(crypto.FILETYPE_ASN1, 
                                                 certReq)

    return derCertReq

def getKeyPairPrivateKey(keyPair):
    return crypto.dump_privatekey(crypto.FILETYPE_PEM, keyPair)
