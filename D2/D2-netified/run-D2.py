from StatKeeper import StatKeeper
from petlib.bindings import _C, _FFI, Const
from petlib.ec import *
from commonFuncs import *
from partialDecryptor import *
from cryptoCounter import *
#from cffiECC import _C, _FFI

import random

if __name__ == "__main__":
  stats = StatKeeper()
  random.seed('PrivEx')
  #ctx = _FFI.new("SHA256_CTX *")
  #md = _FFI.new("unsigned char[]", 32)
  #_C.SHA256_Init(ctx)
  #_C.SHA256_Update(ctx, "he", 2)
  #_C.SHA256_Update(ctx, "llo", 3)
  #_C.SHA256_Final(md, ctx)
  #print _FFI.buffer(md, 32)[:].encode("hex")

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
  for _ in range(num_DC): #changed from 10 to 1000 clients
    with(stats["client_init"]):
      c = crypto_counts(labels, pk)
      clients += [c]

  items = 100000
  mock = [0] * len(labels)
  for i in range(items):
    l = len(labels)
    x = clients[i % 10]
    ## Keep the last 10 as zero to test decryption
    with(stats["client_addone"]):
      x.addone(i % (l-10))
      mock[i % (l-10)] += 1

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

  for (a,b) in data[-10:]:
    # assert _C.EC_POINT_is_at_infinity(x.ecgroup, b) == 1
    pass

  with(stats["decrypt_final"]):
    for p in eqDLproofs:
        NIZKPK_verify_eqDL(x.ecgroup, p[0], p[1])
        NIZKPK_free_eqDL_proof(p[1])
    res = D[-1].finaldecrypt(data)

    # test decryption
    buf = D[-1].test_decrypt()
    result = D[-1].finaldecrypt(buf)
    assert result == range(-100,100)
    print repr(result)


    print res
    #assert sum(res) == items

  stats.print_stats()

  for (a,b) in data:
    _C.EC_POINT_clear_free(a)
    _C.EC_POINT_clear_free(b)
