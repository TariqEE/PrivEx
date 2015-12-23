from StatKeeper import StatKeeper
from petlib.bindings import _C, _FFI, Const
from petlib.ec import *
from commonFuncs import *
from partialDecryptor import *
from cryptoCounter import *

import random

num_TKS = 2
num_websites =1

if __name__ == "__main__":
  random.seed("PrivEx")
  TKS = partialDecryptor()

  pk = None
  pk = TKS.combinekey(pk)

  labels = range(num_websites)
  DC = crypto_counts(labels, pk)

  items = 1
  for i in range(items):
    DC.addone(i % len(labels))

  DC.randomize()

  data = None
  hashes = []
  eqDLproofs = []
  print "hash that!"
  data, clidata, hashval = DC.extract_into(data)
  hashes.append((clidata, hashval))

  # Check the hashes
  print "Checking hashes"
  for (clidata, hashval) in hashes:
    if hash_clidata(TKS.ecgroup, clidata) != hashval:
        raise Exception("Hash mismatch!")
  eqDLproofs.append(TKS.partialdecrypt(data))

  # Check the eqDL proofs
  print "Checking proofs"
  for p in eqDLproofs:
    NIZKPK_verify_eqDL(DC.ecgroup, p[0], p[1])
    NIZKPK_free_eqDL_proof(p[1])
  res = TKS.finaldecrypt(data)
    
  print res
