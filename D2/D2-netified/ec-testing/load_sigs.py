import binascii
from petlib.bindings import _C, _FFI, Const
from petlib.ec import *

if __name__ == "__main__":
    with open("pub-key.pem", 'rb') as f1:
        k1 = ''
        for line in f1:
            if line.startswith('-'):
                pass
            else:
                k1 = k1 + line
                
        print k1
        
        k2 = binascii.a2b_base64(k1)
        print binascii.hexlify(k2)
    
    ecgroup = _C.EC_GROUP_new_by_curve_name(409)
    if not _C.EC_GROUP_have_precompute_mult(ecgroup):
        _C.EC_GROUP_precompute_mult(ecgroup, _FFI.NULL);
    gen = _C.EC_GROUP_get0_generator(ecgroup)