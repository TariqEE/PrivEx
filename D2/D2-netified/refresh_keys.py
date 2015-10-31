import binascii
from petlib.bindings import _C, _FFI, Const
from petlib.ec import *

def refreshKeys():
  ecgroup = EcGroup(409)
  priv_key = ecgroup.order().random()
  pub_key = priv_key * ecgroup.generator()
 
  with open("priv-key-2.pem", 'w') as f1:
    f1.write(repr(priv_key))

  with open("pub-key-2.pem", 'wb') as f2:
    f2.write(binascii.b2a_base64(pub_key.export()))

#  with open("pub-key-2.pem", 'rb') as f3:
#    base64_key = f3.read()
#    pub_key_2 = binascii.a2b_base64(base64_key)
#    pub_point = EcPt.from_binary(pub_key_2, ecgroup)

if __name__ == '__main__':
  refreshKeys()
