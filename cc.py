from PyKCS11 import *
from PyKCS11.LowLevel import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_public_key 
from cryptography.hazmat.primitives.asymmetric import (padding , rsa , utils)
from cryptography.hazmat.primitives import hashes, serialization

lib = '/usr/local/lib/libpteidpkcs11.dylib' # mac
#lib = '/usr/local/lib/libpteidpkcs11.so' # linux
pkcs11 = PyKCS11.PyKCS11Lib() 
pkcs11.load( lib )
slots = pkcs11.getSlotList()

def signaturePseudo(data):
    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo( slot ).label:
            tmp = bytes(data, 'utf-8')
            session = pkcs11.openSession( slot )
            privKey = session.findObjects( [(CKA_CLASS , CKO_PRIVATE_KEY),( CKA_LABEL, 'CITIZEN AUTHENTICATION KEY' )] )[0]
            signature = bytes(session.sign( privKey, tmp, Mechanism( CKM_SHA1_RSA_PKCS ) ))
            session.closeSession
            return signature

def getPublicKey():
    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo( slot ).label:
            session = pkcs11.openSession( slot )
            pubKeyHandle = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY),(CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
            pubKeyDer = session.getAttributeValue( pubKeyHandle, [CKA_VALUE], True )[0]
            session.closeSession
            pubKey = load_der_public_key( bytes( pubKeyDer ), default_backend() )
            return pubKey.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

def validationPseudo(data, PEM, signature):
    try :
        pubKey = load_pem_public_key(PEM, default_backend())
        pubKey.verify( signature, bytes(data, 'utf-8' ), padding.PKCS1v15(), hashes.SHA1() ) 
        return True
    except:
        return False