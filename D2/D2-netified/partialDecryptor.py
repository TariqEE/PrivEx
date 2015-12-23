from petlib.bindings import _C, _FFI, Const
from petlib.ec import *
from binascii import hexlify, unhexlify
from commonFuncs import *

class partialDecryptor:
  def __init__(self, curveID = 409):
#    global _C
#    self._C = _C
    self.curveID = curveID

    self.currPrivKey = None
    self.prevPrivKey = None

    # Store the group we work in
    # precompute tables and the generator and order
    self.ecgroup = EcGroup(self.curveID)
    self.gen = self.ecgroup.generator()
    self.order = self.ecgroup.order()
    
    # Generate the private and public key pair
    self.currPrivKey = self.order.random()
    self.currPubKey = self.currPrivKey * self.gen
    
    # Generate the NIZK proof (that we really know the key pair?)
    self.proof = NIZKPK_prove_DL(self.ecgroup, self.currPubKey, self.currPrivKey)
#    print self.currPubKey.export().encode("hex")
#    self.ecgroup = _C.EC_GROUP_new_by_curve_name(curveID)
#    if not _C.EC_GROUP_have_precompute_mult(self.ecgroup):
#        _C.EC_GROUP_precompute_mult(self.ecgroup, _FFI.NULL);
#    self.gen = _C.EC_GROUP_get0_generator(self.ecgroup)

#    ctx = _C.BN_CTX_new()
#    self.bnorder = _C.BN_new()
#    _C.EC_GROUP_get_order(self.ecgroup, self.bnorder, ctx)
#    self.order = int(_FFI.string(_C.BN_bn2dec(self.bnorder)))
#    _C.BN_CTX_free(ctx)

#    self.key = _C.EC_KEY_new_by_curve_name(self.curveID)
#    _C.EC_KEY_set_group(self.key, self.ecgroup)
#    _C.EC_KEY_generate_key(self.key)

#    s_priv = _C.EC_KEY_get0_private_key(self.key)
#    s_pub = _C.EC_KEY_get0_public_key(self.key)
    
#    self.proof = NIZKPK_prove_DL(self.ecgroup, s_pub, s_priv)


  def __del__(self):
#    _C = self._C
    del(self.currPubKey)
    del(self.ecgroup)
#    _C.EC_GROUP_free(self.ecgroup)
    del(self.order)
#    _C.BN_clear_free(self.bnorder)

  def combinekey(self, pubkey = None):
    s_pub = self.currPubKey
#    _C = self._C
#    s_pub = _C.EC_KEY_get0_public_key(self.key)

    NIZKPK_verify_DL(self.ecgroup, s_pub, self.proof)
    NIZKPK_free_DL_proof(self.proof)
    self.proof = None
    
    if type(pubkey) != EcPt: # changed from the '== None' test since that was giving an error in debug mode
      pubkey = s_pub
#      print pubkey.export().encode("hex")
      return pubkey
  
    else:
      pubkey.pt_add_inplace(s_pub)
      return pubkey
#
#      pk = _C.EC_POINT_new(self.ecgroup)
#      _C.EC_POINT_copy(pk, s_pub)
#      return pk
#
#    else:
#      _C.EC_POINT_add(self.ecgroup, pubkey, pubkey, s_pub, _FFI.NULL);
#      return pubkey

  def partialdecrypt(self, buf):
#    _C = self._C
    pairs = []
    for (a,b) in buf:
      k_priv = self.currPrivKey
      k_pub = self.currPubKey
      alpha = copy(a)
      savealpha = copy(a)
#      k_priv = _C.EC_KEY_get0_private_key(self.key)
#      k_pub = _C.EC_KEY_get0_public_key(self.key)
#      alpha = _C.EC_POINT_dup(a, self.ecgroup)
#      savealpha = _C.EC_POINT_dup(a, self.ecgroup)

      alpha.pt_mul_inplace(k_priv)
      savealphapriv = copy(alpha)
#      _C.EC_POINT_mul(self.ecgroup, alpha, _FFI.NULL, alpha, k_priv, _FFI.NULL);
#      savealphapriv = _C.EC_POINT_dup(alpha, self.ecgroup)

      pairs.append((savealpha, savealphapriv))

#      print alpha
      alpha.pt_neg_inplace()
#      print alpha
      b.pt_add_inplace(alpha)
#      _C.EC_POINT_invert(self.ecgroup, alpha, _FFI.NULL);
#      _C.EC_POINT_add(self.ecgroup, b, b, alpha, _FFI.NULL);

      del(alpha)
#      _C.EC_POINT_clear_free(alpha)

    proof = NIZKPK_prove_eqDL(self.ecgroup, k_pub, pairs, k_priv)
    return proof

  def finaldecrypt(self, buf, table=None, table_size=100000):
    print buf
#    _C = self._C
#    gamma = EcPt(self.ecgroup)
#    gamma = _C.EC_POINT_new(self.ecgroup)

    table_min = Bn(-table_size)
    
#    table_min = _C.BN_new()
#    _C.BN_set_word(table_min, table_size)
#    _C.BN_set_negative(table_min, 1)

    gamma = self.gen.pt_mul(table_min)
#    _C.EC_POINT_mul(self.ecgroup, gamma, _FFI.NULL, self.gen, table_min, _FFI.NULL)

    point_size = 200 ## Only use the first bytes as ID
#    point_oct = _FFI.new("unsigned char[]", point_size)

    lookup = {}
    for i in range(-table_size,table_size):
        point_oct, xsize = gamma.sized_export(point_size)
#        xsize = _C.EC_POINT_point2oct(self.ecgroup, gamma,  _C.POINT_CONVERSION_COMPRESSED, 
#                                      point_oct, point_size, _FFI.NULL);
        assert 0 < xsize < point_size

        lkey = point_oct[:min(16,xsize)]
#        lkey = _FFI.buffer(point_oct)[:min(16,xsize)]

        try:
            assert lkey not in lookup

        except:
            print "Key \"%s\"" % hexlify(lkey)
            print "Collision between %s and %s" % (i, lookup[lkey])
            raise
        lookup[lkey] = i

        gamma.pt_add_inplace(self.gen)
#        _C.EC_POINT_add(self.ecgroup, gamma, gamma, self.gen, _FFI.NULL);

    del(gamma)
#    _C.EC_POINT_clear_free(gamma)

    cleartext = []
    for (_, b) in buf:
        point_oct, xsize = b.sized_export(point_size)
#        xsize = _C.EC_POINT_point2oct(self.ecgroup, b,  _C.POINT_CONVERSION_COMPRESSED,
#            point_oct, point_size, _FFI.NULL);
        
        lkey = point_oct[:min(16,xsize)]
#        lkey = _FFI.buffer(point_oct)[:min(16,xsize)]
        if lkey in lookup:
          cleartext += [int(lookup[lkey]/resolution)]
        else:
          #if _C.EC_POINT_is_at_infinity(self.ecgroup, b) == 1:
          #  cleartext += [0]
          #else:
          cleartext += [None]

    return cleartext

  def test_decrypt(self):
        vals = []
#        v = _C.BN_new()

        for i in range(-100, 100):
#            gamma = EcPt(self.ecgroup)
#            gamma = _C.EC_POINT_new(self.ecgroup)

            v = Bn(i*resolution)
#            if i < 0:               
#                _C.BN_set_word(v, -i*resolution)
#                _C.BN_set_negative(v, 1)
#            else:
#                v = i*resolution
#                _C.BN_set_word(v, i*resolution)

            gamma = self.gen.pt_mul(v)
#            _C.EC_POINT_mul(self.ecgroup, gamma, _FFI.NULL, self.gen, v, _FFI.NULL)

            vals += [(None, gamma)]
        return vals
