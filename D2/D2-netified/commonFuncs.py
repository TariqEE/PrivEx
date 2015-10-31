from petlib.bindings import _C, _FFI, Const
from petlib.ec import *

num_DC=10
num_TKG=3
num_websites=100

sigma = 240
resolution = 10

# Commit to a list of encrypted counters by hashing
def hash_clidata(ecgroup, data):
    ctx = _FFI.new("SHA256_CTX *")
    md = _FFI.new("unsigned char[]", 32)
    _C.SHA256_Init(ctx)
    for (a,b) in data:
        buf, size = point2str(ecgroup, a)
        _C.SHA256_Update(ctx, buf, size)
        # print _FFI.buffer(buf, size)[:].encode("hex"),
        buf, size = point2str(ecgroup, b)
        _C.SHA256_Update(ctx, buf, size)
        # print _FFI.buffer(buf, size)[:].encode("hex")
    _C.SHA256_Final(md, ctx)
    hashval = _FFI.buffer(md, 32)[:]
    return hashval

## Convert a point to a string representation
def point2str(ecgroup, point):
    bnctx = _C.BN_CTX_new()
    size = _C.EC_POINT_point2oct(ecgroup, point, _C.POINT_CONVERSION_COMPRESSED,
    _FFI.NULL, 0, bnctx)
    buf = _FFI.new("unsigned char[]", size)
    _C.EC_POINT_point2oct(ecgroup, point, _C.POINT_CONVERSION_COMPRESSED,
    buf, size, bnctx)
    _C.BN_CTX_free(bnctx)
    return buf, size

## Functions to create and check NIZKPKs
def NIZKPK_prove_DL(ecgroup, pub, priv):
    # b rand
    # B = b * G
    # c = H(G, pub, B)
    # s = priv * c + b
    # return (c,s)
    
    bB = EcGroup(ecgroup.nid())
    G = bB.generator()
    b = bB.order().random()
    B = b * G
    
#    bB = _C.EC_KEY_new_by_curve_name(_C.EC_GROUP_get_curve_name(ecgroup))
#    _C.EC_KEY_set_group(bB, ecgroup)
#    _C.EC_KEY_generate_key(bB)
#    b = _C.EC_KEY_get0_private_key(bB)
#    B = _C.EC_KEY_get0_public_key(bB)
#    G = _C.EC_GROUP_get0_generator(ecgroup)

    ctx = _FFI.new("SHA256_CTX *")
    md = _FFI.new("unsigned char[]", 32)
    _C.SHA256_Init(ctx)
    buf, size = point2str(ecgroup, G)
    _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, pub)
    _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, B)
    _C.SHA256_Update(ctx, buf, size)
    _C.SHA256_Final(md, ctx)
    c = _C.BN_bin2bn(md, 32, _FFI.NULL)

    bnctx = _C.BN_CTX_new()
    order = _C.BN_new()
    _C.EC_GROUP_get_order(ecgroup, order, bnctx)

    privc = _C.BN_new()
    s = _C.BN_new()
    _C.BN_mul(privc, priv, c, bnctx)
    _C.BN_mod_add(s, privc, b, order, bnctx)

    _C.EC_KEY_free(bB)
    _C.BN_CTX_free(bnctx)
    _C.BN_clear_free(privc)
    _C.BN_clear_free(order)
    return c,s

def NIZKPK_verify_DL(ecgroup, pub, proof):
    # c =?= H(G, pub, s * G - c * pub)
    c,s = proof

    negc = _C.BN_new()
    _C.BN_copy(negc, c)
    _C.BN_set_negative(negc, 1)

    G = _C.EC_GROUP_get0_generator(ecgroup)
    B = _C.EC_POINT_new(ecgroup)
    _C.EC_POINT_mul(ecgroup, B, s, pub, negc, _FFI.NULL)
    _C.BN_clear_free(negc)

    ctx = _FFI.new("SHA256_CTX *")
    md = _FFI.new("unsigned char[]", 32)
    _C.SHA256_Init(ctx)
    buf, size = point2str(ecgroup, G)
    _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, pub)
    _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, B)
    _C.SHA256_Update(ctx, buf, size)
    _C.SHA256_Final(md, ctx)
    cprime = _C.BN_bin2bn(md, 32, _FFI.NULL)

    diff = _C.BN_cmp(cprime, c)

    _C.BN_clear_free(cprime)
    _C.EC_POINT_free(B)

    if diff != 0:
        raise Exception("DL proof failed")

def NIZKPK_free_DL_proof(proof):
    c,s = proof
    _C.BN_clear_free(c)
    _C.BN_clear_free(s)

# Prove that DL_G(pub) = DL_X(Y) for each (X,Y) \in pairs.
# priv is this common private value.
def NIZKPK_prove_eqDL(ecgroup, pub, pairs, priv):
    # b rand
    # B = b * G
    # c = H(G, pub, <X,Y>_{(X,Y}\in pairs}, B, <b*X>_{(X,Y)\in pairs})
    # s = priv * c + b
    # return (c,s)
    bB = _C.EC_KEY_new_by_curve_name(_C.EC_GROUP_get_curve_name(ecgroup))
    _C.EC_KEY_set_group(bB, ecgroup)
    _C.EC_KEY_generate_key(bB)
    b = _C.EC_KEY_get0_private_key(bB)
    B = _C.EC_KEY_get0_public_key(bB)
    G = _C.EC_GROUP_get0_generator(ecgroup)
    T = _C.EC_POINT_new(ecgroup)
    bnctx = _C.BN_CTX_new()

    ctx = _FFI.new("SHA256_CTX *")
    md = _FFI.new("unsigned char[]", 32)
    _C.SHA256_Init(ctx)
    buf, size = point2str(ecgroup, G)
    _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, pub)
    _C.SHA256_Update(ctx, buf, size)
    for (X,Y) in pairs:
        buf, size = point2str(ecgroup, X)
        _C.SHA256_Update(ctx, buf, size)
        buf, size = point2str(ecgroup, Y)
        _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, B)
    _C.SHA256_Update(ctx, buf, size)
    for (X,Y) in pairs:
        _C.EC_POINT_mul(ecgroup, T, _FFI.NULL, X, b, bnctx)
        buf, size = point2str(ecgroup, T)
        _C.SHA256_Update(ctx, buf, size)
    _C.SHA256_Final(md, ctx)
    c = _C.BN_bin2bn(md, 32, _FFI.NULL)

    bnctx = _C.BN_CTX_new()
    order = _C.BN_new()
    _C.EC_GROUP_get_order(ecgroup, order, bnctx)

    privc = _C.BN_new()
    s = _C.BN_new()
    _C.BN_mul(privc, priv, c, bnctx)
    _C.BN_mod_add(s, privc, b, order, bnctx)

    _C.EC_KEY_free(bB)
    _C.EC_POINT_free(T)
    _C.BN_CTX_free(bnctx)
    _C.BN_clear_free(privc)
    _C.BN_clear_free(order)

    return pub, (pairs,c,s)

def NIZKPK_verify_eqDL(ecgroup, pub, proof):
    # c =?= H(G, pub, <X,Y>_{(X,Y)\in pairs}, s * G - c * pub,
    #            <s * X - c * Y>_{(X,Y)\in pairs})
    pairs,c,s = proof

    negc = _C.BN_new()
    _C.BN_copy(negc, c)
    _C.BN_set_negative(negc, 1)

    bnctx = _C.BN_CTX_new()
    G = _C.EC_GROUP_get0_generator(ecgroup)
    B = _C.EC_POINT_new(ecgroup)
    _C.EC_POINT_mul(ecgroup, B, s, pub, negc, bnctx)
    T1 = _C.EC_POINT_new(ecgroup)
    T = _C.EC_POINT_new(ecgroup)

    ctx = _FFI.new("SHA256_CTX *")
    md = _FFI.new("unsigned char[]", 32)
    _C.SHA256_Init(ctx)
    buf, size = point2str(ecgroup, G)
    _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, pub)
    _C.SHA256_Update(ctx, buf, size)
    for (X,Y) in pairs:
        buf, size = point2str(ecgroup, X)
        _C.SHA256_Update(ctx, buf, size)
        buf, size = point2str(ecgroup, Y)
        _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, B)
    _C.SHA256_Update(ctx, buf, size)
    for (X,Y) in pairs:
        _C.EC_POINT_mul(ecgroup, T1, _FFI.NULL, X, s, bnctx)
        _C.EC_POINT_mul(ecgroup, T, _FFI.NULL, Y, negc, bnctx)
        _C.EC_POINT_add(ecgroup, T, T, T1, bnctx)
        buf, size = point2str(ecgroup, T)
        _C.SHA256_Update(ctx, buf, size)
    _C.SHA256_Final(md, ctx)
    cprime = _C.BN_bin2bn(md, 32, _FFI.NULL)

    diff = _C.BN_cmp(cprime, c)

    _C.BN_clear_free(negc)
    _C.BN_clear_free(cprime)
    _C.EC_POINT_free(B)
    _C.EC_POINT_free(T)
    _C.EC_POINT_free(T1)
    _C.BN_CTX_free(bnctx)

    if diff != 0:
        raise Exception("eqDL proof failed")

def NIZKPK_free_eqDL_proof(proof):
    pairs,c,s = proof
    for (X,Y) in pairs:
        _C.EC_POINT_free(X)
        _C.EC_POINT_free(Y)
    _C.BN_clear_free(c)
    _C.BN_clear_free(s)

