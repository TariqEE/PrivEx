#from cffiECC import _C, _FFI
from petlib.bindings import _C, _FFI, Const
from petlib.ec import *
from binascii import hexlify
from commonFuncs import *

class partialDecryptor:
  def __init__(self, curveID = 409):
    global _C
    self._C = _C
    self.curveID = curveID

    # Store the group we work in
    # precompute tables and the generator
    self.ecgroup = _C.EC_GROUP_new_by_curve_name(curveID)
    if not _C.EC_GROUP_have_precompute_mult(self.ecgroup):
        _C.EC_GROUP_precompute_mult(self.ecgroup, _FFI.NULL);
    self.gen = _C.EC_GROUP_get0_generator(self.ecgroup)

    ctx = _C.BN_CTX_new()
    self.bnorder = _C.BN_new()
    _C.EC_GROUP_get_order(self.ecgroup, self.bnorder, ctx)
    self.order = int(_FFI.string(_C.BN_bn2dec(self.bnorder)))
    _C.BN_CTX_free(ctx)

    self.key = _C.EC_KEY_new_by_curve_name(self.curveID)
    _C.EC_KEY_set_group(self.key, self.ecgroup)
    _C.EC_KEY_generate_key(self.key)

    s_priv = _C.EC_KEY_get0_private_key(self.key)
    s_pub = _C.EC_KEY_get0_public_key(self.key)
    self.proof = NIZKPK_prove_DL(self.ecgroup, s_pub, s_priv)


  def __del__(self):
    _C = self._C
    _C.EC_KEY_free(self.key)
    _C.EC_GROUP_free(self.ecgroup)
    _C.BN_clear_free(self.bnorder)

  def combinekey(self, pubkey = None):
    _C = self._C
    s_pub = _C.EC_KEY_get0_public_key(self.key)
    NIZKPK_verify_DL(self.ecgroup, s_pub, self.proof)
    NIZKPK_free_DL_proof(self.proof)
    self.proof = None

    if pubkey == None:

      pk = _C.EC_POINT_new(self.ecgroup)
      _C.EC_POINT_copy(pk, s_pub)
      return pk

    else:
      _C.EC_POINT_add(self.ecgroup, pubkey, pubkey, s_pub, _FFI.NULL);
      return pubkey

  def partialdecrypt(self, buf):
    _C = self._C
    pairs = []
    for (a,b) in buf:

      k_priv = _C.EC_KEY_get0_private_key(self.key)
      k_pub = _C.EC_KEY_get0_public_key(self.key)
      alpha = _C.EC_POINT_dup(a, self.ecgroup)
      savealpha = _C.EC_POINT_dup(a, self.ecgroup)

      _C.EC_POINT_mul(self.ecgroup, alpha, _FFI.NULL, alpha, k_priv, _FFI.NULL);
      savealphapriv = _C.EC_POINT_dup(alpha, self.ecgroup)
      pairs.append((savealpha, savealphapriv))
      _C.EC_POINT_invert(self.ecgroup, alpha, _FFI.NULL);
      _C.EC_POINT_add(self.ecgroup, b, b, alpha, _FFI.NULL);


      _C.EC_POINT_clear_free(alpha)

    proof = NIZKPK_prove_eqDL(self.ecgroup, k_pub, pairs, k_priv)
    return proof


  def finaldecrypt(self, buf, table=None, table_size=100000):
    _C = self._C
    gamma = _C.EC_POINT_new(self.ecgroup)

    table_min = _C.BN_new()
    _C.BN_set_word(table_min, table_size)
    _C.BN_set_negative(table_min, 1)

    _C.EC_POINT_mul(self.ecgroup, gamma, _FFI.NULL, self.gen, table_min, _FFI.NULL)

    point_size = 200 ## Only use the first bytes as ID
    point_oct = _FFI.new("unsigned char[]", point_size)

    lookup = {}
    for i in range(-table_size,table_size):
        xsize = _C.EC_POINT_point2oct(self.ecgroup, gamma,  _C.POINT_CONVERSION_COMPRESSED,
          point_oct, point_size, _FFI.NULL);

        assert 0 < xsize < point_size

        lkey = _FFI.buffer(point_oct)[:min(16,xsize)]
        try:
            assert lkey not in lookup

        except:
            print "Key \"%s\"" % hexlify(lkey)
            print "Collision between %s and %s" % (i, lookup[lkey])
            raise
        lookup[lkey] = i

        _C.EC_POINT_add(self.ecgroup, gamma, gamma, self.gen, _FFI.NULL);

    _C.EC_POINT_clear_free(gamma)

    cleartext = []
    for (_, b) in buf:
        xsize = _C.EC_POINT_point2oct(self.ecgroup, b,  _C.POINT_CONVERSION_COMPRESSED,
            point_oct, point_size, _FFI.NULL);

        lkey = _FFI.buffer(point_oct)[:min(16,xsize)]
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
        v = _C.BN_new()

        for i in range(-100, 100):
            gamma = _C.EC_POINT_new(self.ecgroup)

            if i < 0:
                _C.BN_set_word(v, -i*resolution)
                _C.BN_set_negative(v, 1)
            else:
                _C.BN_set_word(v, i*resolution)
            _C.EC_POINT_mul(self.ecgroup, gamma, _FFI.NULL, self.gen, v, _FFI.NULL)

            vals += [(None, gamma)]
        return vals
