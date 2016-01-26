from noise import Noise
from exit_weight import *
from commonFuncs import sigma, resolution
from commonFuncs import *
from petlib.bindings import _C, _FFI, Const
from petlib.ec import *
from collections import OrderedDict
#from numpy.oldnumeric.random_array import beta

class crypto_counts:
  def __init__(self, labels, pubkey, curveID = 409, fingerprint = "fingerprint"):
#    global _C
#    self._C = _C
    self.num = len(labels)
    self.curveID = curveID
    self.pubkey = pubkey
#    print self.pubkey.export().encode("hex")
    self.lab = {}

    # Store the group we work in
    # precompute tables and the generator
    self.ecgroup = EcGroup(curveID)
    self.gen = self.ecgroup.generator()
    self.order = self.ecgroup.order()
    
#    self.ecgroup = _C.EC_GROUP_new_by_curve_name(curveID)
#    if not _C.EC_GROUP_have_precompute_mult(self.ecgroup):
#        _C.EC_GROUP_precompute_mult(self.ecgroup, _FFI.NULL);
#    self.gen = _C.EC_GROUP_get0_generator(self.ecgroup)

    # This is where we store the ECEG ciphertexts
    self.buf = []

    # This DC's weight for noise calculation
    twbw, p_exit, num_of_dc, sum_of_sq = prob_exit(consensus, fingerprint)

    for label in labels:
      #Make session key
      s_priv = self.order.random()
      s_pub = s_priv * self.gen
      
      alpha = s_pub
      
      beta = self.pubkey
      beta.pt_mul_inplace(s_priv)
      
      # Adding noise and setting the resolution
      res_noise = int(Noise(sigma, sum_of_sq, p_exit) * resolution)
      n = Bn(res_noise)
      
      kappa = self.gen
      kappa = kappa.pt_mul(n)
      beta.pt_add_inplace(kappa)
      
      del(kappa)
      del(n)
      
      # Save the ECEG ciphertext
      c = (alpha, beta)
      self.lab[label] = c
      self.buf += [c]
      
      # Save the resolution
      resolute = Bn(resolution)
      self.resolution = self.gen
      self.resolution = self.resolution.pt_mul(resolute)
      del(resolute)

#    for label in labels:
#      # Make session key
#      session = _C.EC_KEY_new_by_curve_name(curveID)
#      _C.EC_KEY_set_group(session, self.ecgroup)
#      _C.EC_KEY_generate_key(session)

#      s_pub = _C.EC_KEY_get0_public_key(session)
#      s_priv = _C.EC_KEY_get0_private_key(session)

#      alpha = _C.EC_POINT_new(self.ecgroup)
#      _C.EC_POINT_copy(alpha, s_pub);

#      beta = _C.EC_POINT_new(self.ecgroup)
#      _C.EC_POINT_copy(beta, self.pubkey);
#      _C.EC_POINT_mul(self.ecgroup, beta, _FFI.NULL, beta, s_priv, _FFI.NULL)

#      # Adding noise and setting the resolution
#      n = _C.BN_new()
#      res_noise = int(Noise(sigma, sum_of_sq, p_exit) * resolution)

#      if res_noise < 0:
#        _C.BN_set_word(n, -res_noise)
#        _C.BN_set_negative(n, 1)
#      else:
#        _C.BN_set_word(n, res_noise)

#      kappa = _C.EC_POINT_new(self.ecgroup)
#      _C.EC_POINT_mul(self.ecgroup, kappa, _FFI.NULL, self.gen, n, _FFI.NULL)
#      _C.EC_POINT_add(self.ecgroup, beta, beta, kappa, _FFI.NULL)
#      _C.EC_POINT_free(kappa)

#      _C.EC_KEY_free(session)
#      _C.BN_clear_free(n)

#      # Save the ECEG ciphertext
#      c = (alpha, beta)
#      self.lab[label] = c
#      self.buf += [c]

#      # Save the resolution
#      resolute = _C.BN_new()
#      _C.BN_set_word(resolute, resolution)
#      self.resolution = _C.EC_POINT_new(self.ecgroup)
#      _C.EC_POINT_mul(self.ecgroup, self.resolution, _FFI.NULL, self.gen, resolute, _FFI.NULL)
#      _C.BN_clear_free(resolute)

  def addone(self, label):
#    _C = self._C
    (_, beta) = self.lab[label]
#    (alpha, beta) = self.lab[label]
#    indice = self.lab.keys().index(label)
#    print "ID of beta BEFORE!: ", id(beta)
#    print "before add self.lab", self.lab
#    print "before add self.buf", self.buf
#    beta = beta.pt_add(self.resolution)
    beta.pt_add_inplace(self.resolution)
    ## since beta is pass by value and not reference we need to update 
    ## self.lab[label] and self.buf(label) appropriately. Had to make self.lab
    ## an ordered dictionary to maintain the indices across the two data structures.
#    c = (alpha, beta)
#    self.lab[label] = c
#    self.buf[indice] = c
#    print "ID of beta AFTER!: ", id(beta)
#    print "after add self.lab", self.lab
#    print "after add self.buf", self.buf
#    _C.EC_POINT_add(self.ecgroup, beta, beta, self.resolution, _FFI.NULL);

  def randomize(self):
#    _C = self._C

    for (a,b) in self.buf:
      # Make session keys
      s_priv = self.order.random()
      s_pub = s_priv * self.gen
      
#      session = _C.EC_KEY_new_by_curve_name(self.curveID)
#      _C.EC_KEY_set_group(session, self.ecgroup)
#      _C.EC_KEY_generate_key(session)

#      s_pub = _C.EC_KEY_get0_public_key(session)
#      s_priv = _C.EC_KEY_get0_private_key(session)

      alpha = s_pub

      beta = self.pubkey
      beta.pt_mul_inplace(s_priv)
      
#      alpha = _C.EC_POINT_new(self.ecgroup)
#      _C.EC_POINT_copy(alpha, s_pub);

#      beta = _C.EC_POINT_new(self.ecgroup)
#      _C.EC_POINT_copy(beta, self.pubkey);
#      _C.EC_POINT_mul(self.ecgroup, beta, _FFI.NULL, beta, s_priv, _FFI.NULL)

      a.pt_add_inplace(alpha)
      b.pt_add_inplace(beta)
#      _C.EC_POINT_add(self.ecgroup, a, a, alpha, _FFI.NULL);
#      _C.EC_POINT_add(self.ecgroup, b, b, beta, _FFI.NULL);

      del(alpha)
      del(beta)
#      _C.EC_POINT_clear_free(alpha)
#      _C.EC_POINT_clear_free(beta)
#      _C.EC_KEY_free(session)

  def extract(self):
    buf = []
    for (a,b) in self.buf:
        acopy = copy(a)
        bcopy = copy(b)
#        acopy = _C.EC_POINT_dup(a, self.ecgroup)
#        bcopy = _C.EC_POINT_dup(b, self.ecgroup)
        buf.append((acopy,bcopy))
    return buf

  def extract_into(self, data):
    clidata = self.buf
    hashval = hash_clidata(self.ecgroup, clidata)

    if data is None:
      return self.extract(), clidata, hashval

    assert len(self.buf) == len(data)

    for ((a,b), (alpha, beta)) in zip(data, self.buf):
      a.pt_add_inplace(alpha)
      b.pt_add_inplace(beta)
#      _C.EC_POINT_add(self.ecgroup, a, a, alpha, _FFI.NULL);
#      _C.EC_POINT_add(self.ecgroup, b, b, beta, _FFI.NULL);
    return data, clidata, hashval

  def __del__(self):
    del(self.ecgroup)
#    self._C.EC_GROUP_free(self.ecgroup)
    if self.buf is not None:
      for (a,b) in self.buf:
        del(a)
        del(b)
#        self._C.EC_POINT_clear_free(a)
#        self._C.EC_POINT_clear_free(b)
