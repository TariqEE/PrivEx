from StatKeeper import StatKeeper
from petlib.bindings import _C, _FFI, Const
from petlib.ec import *
from commonFuncs import *
from partialDecryptor import *
from cryptoCounter import *

import random

num_DC=1
num_TKG=1
num_websites=2

if __name__ == "__main__":
  stats = StatKeeper()
  random.seed('PrivEx')
  
  #ctx = sha256()
  #ctx.update("he")
  #ctx.update("llo")
  #md = ctx.digest()
  #print md.encode("hex")

  D = []
  for _ in range(num_TKG): #changed from 5 to 10 TKGs.
    with(stats["decrypt_init"]):
      D += [partialDecryptor()]

  pk = None
  for Di in D:
    with(stats["decrypt_combinekey"]):
      pk = Di.combinekey(pk)

  labels = range(num_websites)
  clients = []
  for _ in range(num_DC): #changed from 10 to 1 clients
    with(stats["client_init"]):
      c = crypto_counts(labels, pk)
      clients += [c]

  items = 1
  mock = [0] * len(labels)
  for i in range(items):
    x = clients[i]
    with(stats["client_addone"]):
      x.addone(i)
      mock[i] += 1

  print clients
  for c in clients:
    with(stats["client_rerandomize"]):
      c.randomize()

  data = None
  hashes = []
  eqDLproofs = []
  for c in clients:
    with(stats["client_aggregate"]):
      data, clidata, hashval = c.extract_into(data)
      hashes.append((clidata, hashval))

  for Di in D:
    with(stats["decrypt_partial"]):
      # Check the hashes
      for (clidata, hashval) in hashes:
        if hash_clidata(Di.ecgroup, clidata) != hashval:
            raise Exception("Hash mismatch!")
      eqDLproofs.append(Di.partialdecrypt(data))
  
  with(stats["decrypt_final"]):
    for p in eqDLproofs:
        NIZKPK_verify_eqDL(x.ecgroup, p[0], p[1])
        NIZKPK_free_eqDL_proof(p[1])
    res = D[-1].finaldecrypt(data)

    print res
    assert sum(res) == 99935

  stats.print_stats()

  for (a,b) in data:
    del(a)
    del(b)
#    _C.EC_POINT_clear_free(a)
#    _C.EC_POINT_clear_free(b)
