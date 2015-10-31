import binascii
from petlib.bindings import _C, _FFI, Const
from petlib.ec import *

if __name__ == "__main__":
  ecgroup = EcGroup(409)
  priv_key = ecgroup.order().random()
  pub_key = priv_key * ecgroup.generator()
  
  with open('test-pub.pem', 'r') as f1:
    pem_key = f1.read()
    print pem_key 

  with open('test-pub.der', 'rb') as f2:
    der_key = f2.read()
    print binascii.b2a_base64(der_key)

  EcPt.from_binary(der_key, ecgroup)
