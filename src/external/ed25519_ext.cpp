#include "sha512.h"
#include "ge.h"
#include "ed25519_ext.hpp"

void ed25519_restore_from_private_key(unsigned char *public_key, const unsigned char *private_key) 
{
    ge_p3 A;

    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
}