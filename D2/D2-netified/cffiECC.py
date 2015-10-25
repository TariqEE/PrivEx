import cffi

_FFI = cffi.FFI()

_FFI.cdef("""


typedef enum {
  /* values as defined in X9.62 (ECDSA) and elsewhere */
  POINT_CONVERSION_COMPRESSED = 2,
  POINT_CONVERSION_UNCOMPRESSED = 4,
  POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

typedef ... EC_GROUP;
typedef ... EC_POINT;
typedef ... BN_CTX;
typedef ... BIGNUM;

EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
void EC_GROUP_free(EC_GROUP* x);
void EC_GROUP_clear_free(EC_GROUP *);

const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *);
int EC_GROUP_get_order(const EC_GROUP *, BIGNUM *order, BN_CTX *);
int EC_GROUP_get_cofactor(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);
int EC_GROUP_get_curve_name(const EC_GROUP *group);

EC_POINT *EC_POINT_new(const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
void EC_POINT_clear_free(EC_POINT *);
int EC_POINT_copy(EC_POINT *, const EC_POINT *);
EC_POINT *EC_POINT_dup(const EC_POINT *, const EC_GROUP *);

int EC_POINT_set_to_infinity(const EC_GROUP *, EC_POINT *);
int EC_POINT_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int EC_POINT_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int EC_POINT_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);

int EC_POINT_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);

int EC_POINT_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

int EC_POINT_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int EC_POINTs_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);


int EC_POINTs_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, size_t num, const EC_POINT *[], const BIGNUM *[], BN_CTX *);
int EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *);

/* EC_GROUP_precompute_mult() stores multiples of generator for faster point multiplication */
int EC_GROUP_precompute_mult(EC_GROUP *, BN_CTX *);
/* EC_GROUP_have_precompute_mult() reports whether such precomputation has been done */
int EC_GROUP_have_precompute_mult(const EC_GROUP *);

size_t EC_POINT_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
        unsigned char *buf, size_t len, BN_CTX *);
int EC_POINT_oct2point(const EC_GROUP *, EC_POINT *,
        const unsigned char *buf, size_t len, BN_CTX *);


typedef ... EC_KEY;

EC_KEY *EC_KEY_new(void);
EC_KEY *EC_KEY_new_by_curve_name(int nid);
void EC_KEY_free(EC_KEY *);
EC_KEY *EC_KEY_copy(EC_KEY *, const EC_KEY *);
EC_KEY *EC_KEY_dup(const EC_KEY *);

int EC_KEY_up_ref(EC_KEY *);

const EC_GROUP *EC_KEY_get0_group(const EC_KEY *);
int EC_KEY_set_group(EC_KEY *, const EC_GROUP *);
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *);
int EC_KEY_set_private_key(EC_KEY *, const BIGNUM *);
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *);
int EC_KEY_set_public_key(EC_KEY *, const EC_POINT *);

unsigned EC_KEY_get_enc_flags(const EC_KEY *);
void EC_KEY_set_enc_flags(EC_KEY *, unsigned int);

/* EC_KEY_generate_key() creates a ec private (public) key */
int EC_KEY_generate_key(EC_KEY *);
/* EC_KEY_check_key() */
int EC_KEY_check_key(const EC_KEY *);


typedef struct {
  int nid;
  const char *comment;
  } EC_builtin_curve;

/* EC_builtin_curves(EC_builtin_curve *r, size_t size) returns number
 * of all available curves or zero if a error occurred.
 * In case r ist not zero nitems EC_builtin_curve structures
 * are filled with the data of the first nitems internal groups */
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);

typedef unsigned int BN_ULONG;

BN_CTX *BN_CTX_new(void);
void    BN_CTX_free(BN_CTX *c);

BIGNUM *BN_new(void);
void  BN_init(BIGNUM *);
void  BN_clear_free(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void  BN_swap(BIGNUM *a, BIGNUM *b);
int     BN_cmp(const BIGNUM *a, const BIGNUM *b);
int   BN_set_word(BIGNUM *a, BN_ULONG w);
void    BN_set_negative(BIGNUM *b, int n);
int     BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int     BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int     BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
char *  BN_bn2dec(const BIGNUM *a);
BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);

typedef unsigned int SHA_LONG;
#define SHA_LBLOCK 16

typedef struct SHA256state_st
        {
        SHA_LONG h[8];
        SHA_LONG Nl,Nh;
        SHA_LONG data[SHA_LBLOCK];
        unsigned int num,md_len;
        } SHA256_CTX;

int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n,unsigned char *md);

""")

_C = _FFI.verify("""
#include <openssl/ec.h>
#include <openssl/sha.h>

""", libraries=["crypto"], extra_compile_args=['-Wno-deprecated-declarations'])
